"""SecuredDatabase: one object per server owning its settings, engine and limiter."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import pytest
from sqlalchemy import text
from sqlalchemy.exc import TimeoutError as PoolTimeout

from pgbulkhead import (
    GucBypass,
    Overloaded,
    PoolConfigError,
    PoolExhausted,
    PoolSettings,
    RefusalText,
    SecuredDatabase,
    SecurityContext,
    TenancyModel,
    WorkspaceBusy,
    WorkspaceLimiter,
)
from pgbulkhead.testing import use_limiter

MODEL = TenancyModel(namespace="app", bypass=GucBypass())
A = SecurityContext(tenant_id="tenant-a", workspace_id="ws-a")
B = SecurityContext(tenant_id="tenant-a", workspace_id="ws-b")


def test_importing_and_declaring_needs_no_database(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SVC_DATABASE_URL", raising=False)
    db = SecuredDatabase(model=MODEL, url_env="SVC_DATABASE_URL", prefix="SVC")
    db.check()
    with pytest.raises(RuntimeError, match="SVC_DATABASE_URL"):
        db.get_engine()


def test_check_fails_on_settings_that_cannot_hold(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SVC_WORKSPACE_CONCURRENCY", "5")
    with pytest.raises(PoolConfigError):
        SecuredDatabase(model=MODEL, url_env="SVC_DATABASE_URL", prefix="SVC").check()


def test_settings_are_read_once_with_the_servers_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    own = PoolSettings(pool_size=10, max_overflow=10, workspace_concurrency=4)
    db = SecuredDatabase(model=MODEL, url_env="SVC_DATABASE_URL", prefix="SVC", defaults=own)
    db.check()
    monkeypatch.setenv("SVC_WORKSPACE_CONCURRENCY", "1")
    assert db.settings == own
    assert db.limiter.limit == 4


async def test_session_is_admitted_per_workspace(pg_url: str) -> None:
    db = SecuredDatabase(model=MODEL, url_env="UNUSED", prefix="SVC", url=lambda: pg_url)
    try:
        with use_limiter(db, WorkspaceLimiter(limit=1, wait_seconds=0.05)) as limiter:
            async with db.session(A) as held:
                await held.execute(text("SELECT 1"))
                with pytest.raises(WorkspaceBusy):
                    async with db.session(A):
                        pytest.fail("admitted past the cap")
                async with db.session(B) as other:
                    assert (await other.execute(text("SELECT 1"))).scalar() == 1
            assert limiter.tracked() == 0
    finally:
        await db.dispose()


async def test_admitted_slot_holds_one_slot_across_sessions(pg_url: str) -> None:
    db = SecuredDatabase(model=MODEL, url_env="UNUSED", prefix="SVC", url=lambda: pg_url)
    try:
        with use_limiter(db, WorkspaceLimiter(limit=1, wait_seconds=0.05)) as limiter:
            async with db.admitted(A) as slot:
                for _ in range(3):
                    async with slot.session() as conn:
                        await conn.execute(text("SELECT 1"))
                assert limiter.tracked() == 1
                with pytest.raises(WorkspaceBusy):
                    async with db.session(A):
                        pass
            assert limiter.tracked() == 0
    finally:
        await db.dispose()


async def test_admitted_slot_never_calls_a_later_checkout_timeout_safe_to_retry() -> None:
    committed: list[int] = []

    @asynccontextmanager
    async def second_checkout_times_out(ctx: SecurityContext) -> AsyncGenerator[None, None]:
        if committed:
            raise PoolTimeout("QueuePool limit reached")
        yield
        committed.append(1)

    db = SecuredDatabase(model=MODEL, url_env="UNUSED", prefix="SVC")
    db.unadmitted_session = second_checkout_times_out  # ty: ignore[invalid-assignment]
    async with db.admitted(A) as slot:
        async with slot.session():
            pass
        assert committed
        with pytest.raises(PoolTimeout) as caught:
            async with slot.session():
                pytest.fail("the body ran without a session")
        assert not isinstance(caught.value, PoolExhausted)


async def test_admitted_slot_first_checkout_timeout_is_a_safe_refusal() -> None:
    """Nothing has run under the slot before its first session opens, so a timeout there is
    the same refusal ``db.session`` gives, with this server's text."""
    pool = RefusalText(message="Busy everywhere.", next_step="Retry later.")
    db = SecuredDatabase(model=MODEL, url_env="UNUSED", prefix="SVC", refusals={Overloaded: pool})
    db.unadmitted_session = _exhausted  # ty: ignore[invalid-assignment]
    with pytest.raises(PoolExhausted) as caught:
        async with db.admitted(A) as slot, slot.session():
            pytest.fail("the body ran without a session")
    assert caught.value.message == pool.message


def test_a_database_needs_a_url_source() -> None:
    with pytest.raises(ValueError, match="url_env or url"):
        SecuredDatabase(model=MODEL, prefix="SVC")


async def test_refusals_replace_the_overload_text(pg_url: str) -> None:
    busy = RefusalText(message="Too many requests for this notebook.", next_step="Retry soon.")
    pool = RefusalText(message="Busy everywhere.", next_step="Retry later.")
    db = SecuredDatabase(
        model=MODEL,
        prefix="SVC",
        url=lambda: pg_url,
        refusals={WorkspaceBusy: busy, Overloaded: pool},
    )
    try:
        with use_limiter(db, WorkspaceLimiter(limit=1, wait_seconds=0.05)):
            async with db.session(A):
                with pytest.raises(WorkspaceBusy) as caught:
                    async with db.session(A):
                        pass
                assert (caught.value.message, caught.value.next_step) == (
                    busy.message,
                    busy.next_step,
                )
                assert str(caught.value) == busy.message
                with pytest.raises(WorkspaceBusy) as held:
                    async with db.admitted(A):
                        pass
                assert held.value.message == busy.message
        # A class with no entry of its own takes its nearest listed base's text.
        db.unadmitted_session = _exhausted  # ty: ignore[invalid-assignment]
        with pytest.raises(PoolExhausted) as exhausted:
            async with db.session(B):
                pass
        assert exhausted.value.message == pool.message
    finally:
        await db.dispose()
    # The defaults are untouched for everyone else.
    assert WorkspaceBusy().message != busy.message


@asynccontextmanager
async def _exhausted(ctx: SecurityContext) -> AsyncGenerator[None, None]:
    raise PoolTimeout("QueuePool limit reached")
    yield


async def test_system_session_binds_the_tenant_it_is_given(pg_url: str) -> None:
    db = SecuredDatabase(model=MODEL, prefix="SVC", url=lambda: pg_url)
    try:
        async with db.system_session("tenant-a") as conn:
            row = await conn.execute(
                text(
                    "SELECT current_setting('app.role', true),"
                    " current_setting('app.tenant_id', true)"
                )
            )
            assert tuple(row.one()) == ("system", "tenant-a")
    finally:
        await db.dispose()
