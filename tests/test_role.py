"""A pooled engine refuses a session that row-level security does not apply to.

Postgres applies no policy to a superuser or a ``BYPASSRLS`` role, and a managed Postgres can
exempt more (on Amazon RDS, a member of ``rds_superuser`` with neither attribute), so a server
connected as one would read every tenant's rows. These tests connect as each kind of role and
show the engine refuses the bypassing ones before any session runs, and serves the safe one.

Stock Postgres exempts a role from row-level security only through those two attributes, so no
role here bypasses without one. The behavioural probe is shown on its own by masking the
attribute and membership checks (``attributes_unseen``): a real superuser and a real
``BYPASSRLS`` session, which bypass for real, are then refused by the probe alone.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy import make_url, text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from pgbulkhead import (
    MANAGED_ADMIN_ROLES,
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
from pgbulkhead import role as role_module

from .conftest import URL, url_for

BYPASS_ROLE = "pgbulkhead_bypassrls"
ADMIN_ROLE = "pgbulkhead_managed_admin"
ADMIN_GROUP = "pgbulkhead_managed_admin_group"
ADMIN_MEMBER = "pgbulkhead_admin_member"
READ_ONLY_ROLE = "pgbulkhead_read_only"
NO_TEMP_DB = "pgbulkhead_no_temp"
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


async def _ensure_role(conn: AsyncConnection, role: str, attributes: str) -> None:
    exists = await conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": role})
    if exists.scalar() is None:
        await conn.execute(text(f"CREATE ROLE {role} {attributes}"))


@pytest_asyncio.fixture
async def admin_member_url(admin_engine: AsyncEngine) -> str:
    """A login role with neither attribute that belongs, through a group, to a stand-in for a
    managed Postgres admin role."""
    async with admin_engine.begin() as conn:
        await _ensure_role(conn, ADMIN_ROLE, "NOLOGIN")
        await _ensure_role(conn, ADMIN_GROUP, "NOLOGIN")
        await _ensure_role(conn, ADMIN_MEMBER, "LOGIN NOSUPERUSER NOBYPASSRLS")
        await conn.execute(text(f"GRANT {ADMIN_ROLE} TO {ADMIN_GROUP}"))
        await conn.execute(text(f"GRANT {ADMIN_GROUP} TO {ADMIN_MEMBER}"))
    return url_for(ADMIN_MEMBER)


@pytest.fixture
def attributes_unseen(monkeypatch: pytest.MonkeyPatch) -> None:
    """Blind the attribute and membership checks, so only the behavioural probe can refuse."""
    monkeypatch.setattr(role_module, "_reasons", lambda *_: [])


async def test_the_probe_alone_refuses_a_superuser_session(
    admin_engine: AsyncEngine, attributes_unseen: None, engines: list[AsyncEngine]
) -> None:
    engine = create_pooled_engine(URL, SETTINGS)
    engines.append(engine)
    with pytest.raises(UnsafeRoleError, match="saw a row that a forced policy hides"):
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))


async def test_the_probe_alone_refuses_a_bypassrls_session(
    bypass_url: str, attributes_unseen: None, engines: list[AsyncEngine]
) -> None:
    guarded = create_pooled_engine(bypass_url, SETTINGS)
    plain = create_async_engine(bypass_url)
    engines.extend([guarded, plain])
    with pytest.raises(UnsafeRoleError, match="saw a row that a forced policy hides"):
        async with guarded.connect() as conn:
            await conn.execute(text("SELECT 1"))
    async with plain.connect() as conn:
        with pytest.raises(UnsafeRoleError, match="saw a row that a forced policy hides"):
            await check_role(conn)


async def test_the_probe_passes_a_role_policies_apply_to(
    pg_url: str, attributes_unseen: None, engines: list[AsyncEngine]
) -> None:
    engine = create_pooled_engine(pg_url, SETTINGS)
    engines.append(engine)
    async with engine.connect() as conn:
        await check_role(conn)


async def test_a_member_of_a_managed_admin_role_is_refused(
    admin_member_url: str, engines: list[AsyncEngine]
) -> None:
    """Membership counts however indirect, and the list is the caller's to set."""
    engine = install_role_guard(create_async_engine(admin_member_url), admin_roles=[ADMIN_ROLE])
    engines.append(engine)
    with pytest.raises(UnsafeRoleError, match=f"is a member of '{ADMIN_ROLE}'"):
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    plain = create_async_engine(admin_member_url)
    engines.append(plain)
    async with plain.connect() as conn:
        with pytest.raises(UnsafeRoleError, match="a managed Postgres admin role"):
            await check_role(conn, admin_roles=(ADMIN_ROLE,))
        # Not in the default list, and the role does not bypass, so the default passes it.
        await check_role(conn)


def test_the_default_admin_roles_name_the_managed_services() -> None:
    assert "rds_superuser" in MANAGED_ADMIN_ROLES
    assert "azure_pg_admin" in MANAGED_ADMIN_ROLES
    assert "cloudsqlsuperuser" in MANAGED_ADMIN_ROLES


@pytest.mark.parametrize("bad", ["", "a\x00b"])
def test_admin_roles_must_be_role_names(bad: str) -> None:
    with pytest.raises(ValueError, match="not a role name"):
        install_role_guard(create_async_engine(URL), admin_roles=[bad])


async def test_an_admin_role_name_is_quoted_not_spliced(
    pg_url: str, engines: list[AsyncEngine]
) -> None:
    engine = install_role_guard(
        create_async_engine(pg_url), admin_roles=["x') OR true OR ('", "back\\slash"]
    )
    engines.append(engine)
    async with engine.connect() as conn:
        assert (await conn.execute(text("SELECT 1"))).scalar() == 1


async def test_the_guard_leaves_no_probe_table_and_no_open_transaction(
    pg_url: str, engines: list[AsyncEngine]
) -> None:
    engine = create_pooled_engine(pg_url, SETTINGS)
    engines.append(engine)
    async with engine.connect() as conn:
        raw = await conn.get_raw_connection()
        assert raw.driver_connection is not None
        assert not raw.driver_connection.is_in_transaction()
        probe = await conn.execute(text("SELECT to_regclass('pg_temp.pgbulkhead_rls_probe')"))
        assert probe.scalar() is None


async def test_check_role_keeps_the_callers_transaction(
    pg_url: str, engines: list[AsyncEngine]
) -> None:
    """The probe runs in a savepoint: what the caller did before it is still there after."""
    engine = create_async_engine(pg_url)
    engines.append(engine)
    async with engine.connect() as conn:
        await conn.execute(text("CREATE TEMPORARY TABLE kept (x int)"))
        await conn.execute(text("INSERT INTO kept VALUES (7)"))
        await check_role(conn)
        assert (await conn.execute(text("SELECT x FROM kept"))).scalar() == 7
        probe = await conn.execute(text("SELECT to_regclass('pg_temp.pgbulkhead_rls_probe')"))
        assert probe.scalar() is None


async def test_under_autocommit_the_guard_leaves_no_probe_table(
    pg_url: str, engines: list[AsyncEngine]
) -> None:
    """Each statement commits on its own, so the probe opens and rolls back its own transaction."""
    engine = install_role_guard(create_async_engine(pg_url, isolation_level="AUTOCOMMIT"))
    engines.append(engine)
    async with engine.connect() as conn:
        probe = await conn.execute(text("SELECT to_regclass('pg_temp.pgbulkhead_rls_probe')"))
        assert probe.scalar() is None


async def test_under_autocommit_check_role_probes_and_leaves_no_probe_table(
    pg_url: str, bypass_url: str, engines: list[AsyncEngine], monkeypatch: pytest.MonkeyPatch
) -> None:
    safe = create_async_engine(pg_url, isolation_level="AUTOCOMMIT")
    unsafe = create_async_engine(bypass_url, isolation_level="AUTOCOMMIT")
    engines.extend([safe, unsafe])
    async with safe.connect() as conn:
        await check_role(conn)
        probe = await conn.execute(text("SELECT to_regclass('pg_temp.pgbulkhead_rls_probe')"))
        assert probe.scalar() is None
    monkeypatch.setattr(role_module, "_reasons", lambda *_: [])
    async with unsafe.connect() as conn:
        with pytest.raises(UnsafeRoleError, match="saw a row that a forced policy hides"):
            await check_role(conn)


async def test_under_autocommit_check_role_keeps_a_transaction_the_caller_began(
    pg_url: str, engines: list[AsyncEngine]
) -> None:
    """A transaction opened with SQL BEGIN on an AUTOCOMMIT connection survives the probe."""
    engine = create_async_engine(pg_url, isolation_level="AUTOCOMMIT")
    engines.append(engine)
    async with engine.connect() as conn:
        await conn.execute(text("BEGIN"))
        await conn.execute(text("CREATE TEMPORARY TABLE kept (x int)"))
        await conn.execute(text("INSERT INTO kept VALUES (7)"))
        await check_role(conn)
        raw = await conn.get_raw_connection()
        assert raw.driver_connection is not None
        assert raw.driver_connection.is_in_transaction()
        assert (await conn.execute(text("SELECT x FROM kept"))).scalar() == 7
        probe = await conn.execute(text("SELECT to_regclass('pg_temp.pgbulkhead_rls_probe')"))
        assert probe.scalar() is None
        await conn.execute(text("ROLLBACK"))


@pytest_asyncio.fixture
async def no_temp_url(admin_engine: AsyncEngine, pg_url: str) -> str:
    """The server role, on a database where nobody may create temporary tables."""
    autocommit = admin_engine.execution_options(isolation_level="AUTOCOMMIT")
    async with autocommit.connect() as conn:
        exists = await conn.execute(
            text("SELECT 1 FROM pg_database WHERE datname = :d"), {"d": NO_TEMP_DB}
        )
        if exists.scalar() is None:
            await conn.execute(text(f"CREATE DATABASE {NO_TEMP_DB}"))
        await conn.execute(text(f"REVOKE TEMPORARY ON DATABASE {NO_TEMP_DB} FROM PUBLIC"))
    return make_url(pg_url).set(database=NO_TEMP_DB).render_as_string(hide_password=False)


@pytest_asyncio.fixture
async def read_only_url(admin_engine: AsyncEngine) -> str:
    """A login role whose sessions default to read-only transactions."""
    async with admin_engine.begin() as conn:
        await _ensure_role(conn, READ_ONLY_ROLE, "LOGIN NOSUPERUSER NOBYPASSRLS")
        await conn.execute(
            text(f"ALTER ROLE {READ_ONLY_ROLE} SET default_transaction_read_only = on")
        )
    return url_for(READ_ONLY_ROLE)


async def _serves_and_warns(
    url: str, engines: list[AsyncEngine], caplog: pytest.LogCaptureFixture
) -> None:
    engine = create_pooled_engine(url, SETTINGS)
    engines.append(engine)
    with caplog.at_level(logging.WARNING, logger="pgbulkhead.role"):
        async with engine.connect() as conn:
            assert (await conn.execute(text("SELECT 1"))).scalar() == 1
    assert "could not run its row-level security probe" in caplog.text


async def test_without_temp_the_probe_is_skipped_and_it_says_so(
    no_temp_url: str, engines: list[AsyncEngine], caplog: pytest.LogCaptureFixture
) -> None:
    await _serves_and_warns(no_temp_url, engines, caplog)


async def test_in_a_read_only_session_the_probe_is_skipped_and_it_says_so(
    read_only_url: str, engines: list[AsyncEngine], caplog: pytest.LogCaptureFixture
) -> None:
    await _serves_and_warns(read_only_url, engines, caplog)


async def test_a_bypassrls_role_is_refused_where_the_probe_cannot_run(
    bypass_url: str, no_temp_url: str, engines: list[AsyncEngine]
) -> None:
    there = make_url(bypass_url).set(database=NO_TEMP_DB).render_as_string(hide_password=False)
    engine = create_pooled_engine(there, SETTINGS)
    engines.append(engine)
    with pytest.raises(UnsafeRoleError, match="BYPASSRLS"):
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
