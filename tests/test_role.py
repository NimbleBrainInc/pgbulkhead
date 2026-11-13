"""A pooled engine refuses a role that row-level security does not apply to.

Postgres applies no policy to a superuser or a ``BYPASSRLS`` role, so a server connected as one
would read every tenant's rows. These tests connect as each kind of role and show the engine
refuses the bypassing ones before any session runs, and serves the safe one.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from pgbulkhead import (
    PoolSettings,
    SecuredDatabase,
    SecurityContext,
    TenancyModel,
    UnsafeRoleError,
    check_role,
    create_pooled_engine,
    install_role_guard,
    scoped_session,
)

from .conftest import URL, url_for

BYPASS_ROLE = "pgbulkhead_bypassrls"
SETTINGS = PoolSettings(pool_size=1, max_overflow=2, workspace_concurrency=1)
MODEL = TenancyModel(namespace="role")
CTX = SecurityContext(tenant_id="tenant-a", workspace_id="ws-1")


@pytest_asyncio.fixture
async def bypass_url(admin_engine: AsyncEngine) -> str:
    """A login role that is not a superuser but has ``BYPASSRLS``."""
    async with admin_engine.begin() as conn:
        exists = await conn.execute(
            text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": BYPASS_ROLE}
        )
        if exists.scalar() is None:
            await conn.execute(text(f"CREATE ROLE {BYPASS_ROLE} LOGIN NOSUPERUSER BYPASSRLS"))
    return url_for(BYPASS_ROLE)


@pytest_asyncio.fixture
async def engines() -> AsyncIterator[list[AsyncEngine]]:
    """Engines a test builds, disposed after it."""
    built: list[AsyncEngine] = []
    try:
        yield built
    finally:
        for engine in built:
            await engine.dispose()


async def test_pooled_engine_refuses_a_superuser(
    admin_engine: AsyncEngine, engines: list[AsyncEngine]
) -> None:
    engine = create_pooled_engine(URL, SETTINGS)
    engines.append(engine)
    with pytest.raises(UnsafeRoleError, match="superuser"):
        async with scoped_session(engine, MODEL, CTX) as conn:
            await conn.execute(text("SELECT 1"))


async def test_pooled_engine_refuses_a_bypassrls_role(
    bypass_url: str, engines: list[AsyncEngine]
) -> None:
    engine = create_pooled_engine(bypass_url, SETTINGS)
    engines.append(engine)
    with pytest.raises(UnsafeRoleError, match="BYPASSRLS"):
        async with scoped_session(engine, MODEL, CTX) as conn:
            await conn.execute(text("SELECT 1"))


async def test_refusal_holds_on_every_attempt(bypass_url: str, engines: list[AsyncEngine]) -> None:
    """The refused connection is discarded, not pooled: a retry is refused again."""
    engine = create_pooled_engine(bypass_url, SETTINGS)
    engines.append(engine)
    for _ in range(3):
        with pytest.raises(UnsafeRoleError):
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))


async def test_refused_connections_are_closed_on_the_server(
    admin_engine: AsyncEngine, bypass_url: str, engines: list[AsyncEngine]
) -> None:
    """Each refusal closes its connection before the error propagates, so repeated attempts
    cannot pile up open backends for the refused role. The errors are kept, so nothing is left
    for garbage collection to close: what is open right after the refusals stays open."""
    engine = create_pooled_engine(bypass_url, SETTINGS)
    engines.append(engine)
    refusals: list[pytest.ExceptionInfo[UnsafeRoleError]] = []
    for _ in range(4):
        with pytest.raises(UnsafeRoleError) as caught:
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
        refusals.append(caught)
    async with admin_engine.connect() as conn:
        count = await conn.execute(
            text("SELECT count(*) FROM pg_stat_activity WHERE usename = :r"), {"r": BYPASS_ROLE}
        )
        assert count.scalar_one() == 0
    assert len(refusals) == 4


async def test_pooled_engine_serves_a_role_that_cannot_bypass(
    pg_url: str, engines: list[AsyncEngine]
) -> None:
    engine = create_pooled_engine(pg_url, SETTINGS)
    engines.append(engine)
    async with scoped_session(engine, MODEL, CTX) as conn:
        assert (await conn.execute(text("SELECT 1"))).scalar() == 1


async def test_guard_can_be_turned_off_for_a_bypassing_engine(
    admin_engine: AsyncEngine, engines: list[AsyncEngine]
) -> None:
    """A migration engine is meant to bypass; it opts out explicitly."""
    engine = create_pooled_engine(URL, SETTINGS, refuse_bypass_roles=False)
    engines.append(engine)
    async with engine.connect() as conn:
        assert (await conn.execute(text("SELECT 1"))).scalar() == 1


async def test_check_role_on_a_connection_you_hold(
    bypass_url: str, pg_url: str, engines: list[AsyncEngine]
) -> None:
    unsafe = create_async_engine(bypass_url)
    safe = create_async_engine(pg_url)
    engines.extend([unsafe, safe])
    async with unsafe.connect() as conn:
        with pytest.raises(UnsafeRoleError, match="BYPASSRLS"):
            await check_role(conn)
    async with safe.connect() as conn:
        await check_role(conn)


async def test_install_role_guard_on_an_engine_you_built(
    bypass_url: str, engines: list[AsyncEngine]
) -> None:
    engine = install_role_guard(create_async_engine(bypass_url))
    engines.append(engine)
    with pytest.raises(UnsafeRoleError):
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))


async def test_secured_database_check_role_fails_the_rollout(bypass_url: str, pg_url: str) -> None:
    unsafe = SecuredDatabase(model=MODEL, prefix="SVC", url=lambda: bypass_url)
    safe = SecuredDatabase(model=MODEL, prefix="SVC", url=lambda: pg_url)
    try:
        with pytest.raises(UnsafeRoleError, match="NOSUPERUSER NOBYPASSRLS"):
            await unsafe.check_role()
        await safe.check_role()
    finally:
        await unsafe.dispose()
        await safe.dispose()
