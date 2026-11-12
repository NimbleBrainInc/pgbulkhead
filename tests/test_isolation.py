"""The walls, enforced by a real Postgres, against a role that is neither superuser nor BYPASSRLS.

Every test here connects as ``pgbulkhead_app``, the role a server would use, to tables owned by
``pgbulkhead_owner``. Rows are seeded as a superuser, which row-level security does not apply
to. Each test states one property of the guarantee, or one edge of it.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from dataclasses import dataclass

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from pgbulkhead import (
    GucBypass,
    RoleBypass,
    SecurityContext,
    TenancyModel,
    policy_statements,
    scoped_session,
    system_session,
    transaction,
)

from .conftest import url_for

APP, OWNER, RECONCILER, JOB = (
    "pgbulkhead_app",
    "pgbulkhead_owner",
    "pgbulkhead_reconciler",
    "pgbulkhead_job",
)

#: Per-command shape: tenant hard wall, workspace soft wall.
NOTES = TenancyModel(namespace="t")
#: Single-key on the tenant: a tenant-wide fact, readable from every workspace of the tenant.
LEDGER = TenancyModel(workspace_column=None, namespace="t")
#: Single-key on another column and setting, standing for a second, unrelated key.
ORGS = TenancyModel(tenant_column="org_id", workspace_column=None, namespace="t")
GUC_BYPASS = TenancyModel(namespace="t", bypass=GucBypass())
ROLE_BYPASS = TenancyModel(namespace="t", bypass=RoleBypass(RECONCILER))

TABLES: dict[str, tuple[TenancyModel, str]] = {
    "notes": (NOTES, "tenant_id text NOT NULL, workspace_id text NOT NULL, body text"),
    "ledger": (LEDGER, "tenant_id text NOT NULL, workspace_id text NOT NULL, body text"),
    "org_rows": (ORGS, "org_id text NOT NULL, body text"),
    "notes_guc": (GUC_BYPASS, "tenant_id text NOT NULL, workspace_id text NOT NULL, body text"),
    "notes_role": (ROLE_BYPASS, "tenant_id text NOT NULL, workspace_id text NOT NULL, body text"),
}

A1 = SecurityContext(tenant_id="tenant-a", workspace_id="ws-1")
A1_READS_2 = SecurityContext(
    tenant_id="tenant-a", workspace_id="ws-1", allowed_workspaces=frozenset({"ws-2"})
)
B1 = SecurityContext(tenant_id="tenant-b", workspace_id="ws-1")

SEED = [
    ("tenant-a", "ws-1", "a1"),
    ("tenant-a", "ws-2", "a2"),
    ("tenant-b", "ws-1", "b1"),
]


@dataclass
class Db:
    admin: AsyncEngine
    app: AsyncEngine
    owner: AsyncEngine
    job: AsyncEngine


async def _exec(engine: AsyncEngine, *statements: str) -> None:
    async with engine.begin() as conn:
        for statement in statements:
            await conn.execute(text(statement))


@pytest_asyncio.fixture
async def db(admin_engine: AsyncEngine) -> AsyncGenerator[Db, None]:
    roles = (APP, OWNER, RECONCILER, JOB)
    await _exec(
        admin_engine,
        *(f"DROP TABLE IF EXISTS {t}" for t in TABLES),
        *(f"DROP ROLE IF EXISTS {r}" for r in reversed(roles)),
        f"CREATE ROLE {APP} LOGIN NOSUPERUSER NOBYPASSRLS",
        f"CREATE ROLE {OWNER} LOGIN NOSUPERUSER NOBYPASSRLS",
        f"CREATE ROLE {RECONCILER} NOLOGIN NOSUPERUSER NOBYPASSRLS",
        f"CREATE ROLE {JOB} LOGIN NOSUPERUSER NOBYPASSRLS IN ROLE {RECONCILER}",
        f"GRANT CREATE ON SCHEMA public TO {OWNER}",
    )
    owner = create_async_engine(url_for(OWNER))
    for table, (model, columns) in TABLES.items():
        await _exec(
            owner,
            f"CREATE TABLE {table} ({columns})",
            *policy_statements(model, table),
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {APP}, {RECONCILER}",
        )
    for table in TABLES:
        if table == "org_rows":
            await _exec(admin_engine, f"INSERT INTO {table} VALUES ('org-a', 'a'), ('org-b', 'b')")
        else:
            values = ", ".join(f"('{t}', '{w}', '{b}')" for t, w, b in SEED)
            await _exec(admin_engine, f"INSERT INTO {table} VALUES {values}")
    app = create_async_engine(url_for(APP), pool_size=1, max_overflow=0)
    job = create_async_engine(url_for(JOB))
    try:
        yield Db(admin_engine, app, owner, job)
    finally:
        for engine in (app, owner, job):
            await engine.dispose()
        await _exec(
            admin_engine,
            *(f"DROP TABLE IF EXISTS {t}" for t in TABLES),
            f"REVOKE CREATE ON SCHEMA public FROM {OWNER}",
            *(f"DROP ROLE IF EXISTS {r}" for r in reversed(roles)),
        )


async def _bodies(conn: AsyncConnection, table: str = "notes") -> list[str]:
    rows = await conn.execute(text(f"SELECT body FROM {table} ORDER BY body"))
    return list(rows.scalars())


async def _count(conn: AsyncConnection, sql: str) -> int:
    return (await conn.execute(text(sql))).rowcount


# --- reads -------------------------------------------------------------------------------


async def test_reads_see_only_the_active_workspace_of_the_tenant(db: Db) -> None:
    async with scoped_session(db.app, NOTES, A1) as conn:
        assert await _bodies(conn) == ["a1"]


async def test_cross_tenant_read_sees_nothing(db: Db) -> None:
    async with scoped_session(db.app, NOTES, B1) as conn:
        assert await _bodies(conn) == ["b1"]
        rows = await conn.execute(text("SELECT body FROM notes WHERE tenant_id = 'tenant-a'"))
        assert rows.all() == []


async def test_a_read_grant_spans_the_granted_workspace(db: Db) -> None:
    async with scoped_session(db.app, NOTES, A1_READS_2) as conn:
        assert await _bodies(conn) == ["a1", "a2"]


async def test_a_revoked_grant_reads_nothing_more(db: Db) -> None:
    async with scoped_session(db.app, NOTES, A1_READS_2) as conn:
        assert await _bodies(conn) == ["a1", "a2"]
    async with scoped_session(db.app, NOTES, A1) as conn:
        assert await _bodies(conn) == ["a1"]


async def test_a_grant_in_another_tenant_reads_nothing(db: Db) -> None:
    reaching = SecurityContext(
        tenant_id="tenant-b", workspace_id="ws-1", allowed_workspaces=frozenset({"ws-2"})
    )
    async with scoped_session(db.app, NOTES, reaching) as conn:
        assert await _bodies(conn) == ["b1"]


# --- writes ------------------------------------------------------------------------------


async def test_writes_land_in_the_active_workspace(db: Db) -> None:
    async with scoped_session(db.app, NOTES, A1) as conn:
        await conn.execute(text("INSERT INTO notes VALUES ('tenant-a', 'ws-1', 'a1-new')"))
    async with scoped_session(db.app, NOTES, A1) as conn:
        assert await _bodies(conn) == ["a1", "a1-new"]


@pytest.mark.parametrize(
    "row", [("tenant-a", "ws-2"), ("tenant-b", "ws-1")], ids=["granted-workspace", "other-tenant"]
)
async def test_insert_outside_the_active_workspace_is_refused(db: Db, row: tuple[str, str]) -> None:
    with pytest.raises(DBAPIError, match="row-level security"):
        async with scoped_session(db.app, NOTES, A1_READS_2) as conn:
            await conn.execute(text(f"INSERT INTO notes VALUES ('{row[0]}', '{row[1]}', 'x')"))


async def test_a_read_grant_cannot_update_or_delete_the_granted_workspace(db: Db) -> None:
    async with scoped_session(db.app, NOTES, A1_READS_2) as conn:
        assert await _count(conn, "UPDATE notes SET body = 'x' WHERE workspace_id = 'ws-2'") == 0
        assert await _count(conn, "DELETE FROM notes WHERE workspace_id = 'ws-2'") == 0
    async with scoped_session(db.app, NOTES, A1_READS_2) as conn:
        assert await _bodies(conn) == ["a1", "a2"]


async def test_a_row_cannot_be_relabelled_out_of_the_active_workspace(db: Db) -> None:
    for target in ("workspace_id = 'ws-2'", "tenant_id = 'tenant-b'"):
        with pytest.raises(DBAPIError, match="row-level security"):
            async with scoped_session(db.app, NOTES, A1_READS_2) as conn:
                await conn.execute(text(f"UPDATE notes SET {target} WHERE body = 'a1'"))


# --- default deny, pooling, ownership ----------------------------------------------------


async def test_an_unscoped_session_reads_and_writes_nothing(db: Db) -> None:
    async with transaction(db.app) as conn:
        assert await _bodies(conn) == []
        assert await _bodies(conn, "ledger") == []
        assert await _count(conn, "DELETE FROM notes") == 0
    with pytest.raises(DBAPIError, match="row-level security"):
        async with transaction(db.app) as conn:
            await conn.execute(text("INSERT INTO notes VALUES ('tenant-a', 'ws-1', 'x')"))


async def test_a_pooled_connection_carries_no_context_to_the_next_checkout(db: Db) -> None:
    async with scoped_session(db.app, NOTES, A1_READS_2) as conn:
        pid = (await conn.execute(text("SELECT pg_backend_pid()"))).scalar_one()
    async with transaction(db.app) as conn:
        assert (await conn.execute(text("SELECT pg_backend_pid()"))).scalar_one() == pid
        setting = await conn.execute(text("SELECT current_setting('t.tenant_id', true)"))
        assert setting.scalar() in (None, "")
        assert await _bodies(conn) == []


async def test_forced_policies_bind_the_table_owner_too(db: Db) -> None:
    async with transaction(db.owner) as conn:
        assert await _bodies(conn) == []
    async with scoped_session(db.owner, NOTES, A1) as conn:
        assert await _bodies(conn) == ["a1"]


async def test_empty_identity_is_refused_before_binding() -> None:
    engine = create_async_engine("postgresql+asyncpg://unused@127.0.0.1:1/unused")
    for ctx in (SecurityContext(tenant_id="", workspace_id="ws-1"), SecurityContext("tenant-a")):
        with pytest.raises(ValueError):
            async with scoped_session(engine, NOTES, ctx):
                pytest.fail("bound an empty identity")
    await engine.dispose()


# --- single-key shape and mixed shapes ---------------------------------------------------


async def test_a_single_key_table_is_shared_across_the_tenants_workspaces(db: Db) -> None:
    async with scoped_session(db.app, LEDGER, SecurityContext("tenant-a")) as conn:
        assert await _bodies(conn, "ledger") == ["a1", "a2"]
        await conn.execute(text("INSERT INTO ledger VALUES ('tenant-a', 'ws-9', 'a9')"))
    with pytest.raises(DBAPIError, match="row-level security"):
        async with scoped_session(db.app, LEDGER, SecurityContext("tenant-a")) as conn:
            await conn.execute(text("INSERT INTO ledger VALUES ('tenant-b', 'ws-1', 'x')"))


async def test_models_on_different_settings_cannot_be_confused(db: Db) -> None:
    """Each policy reads only its own setting, NULL when unbound, so a session bound for one
    model matches no row of a table under another: mixing fails closed."""
    async with scoped_session(db.app, NOTES, A1) as conn:
        assert await _bodies(conn, "org_rows") == []
    async with scoped_session(db.app, ORGS, SecurityContext("org-a")) as conn:
        assert await _bodies(conn, "org_rows") == ["a"]
        assert await _bodies(conn) == []
        assert await _bodies(conn, "ledger") == []


# --- bypasses ----------------------------------------------------------------------------


async def test_guc_bypass_crosses_workspaces_never_tenants(db: Db) -> None:
    async with system_session(db.app, GUC_BYPASS, "tenant-a") as conn:
        assert await _bodies(conn, "notes_guc") == ["a1", "a2"]
    async with system_session(db.app, GUC_BYPASS) as conn:
        assert await _bodies(conn, "notes_guc") == []
    # Tables whose model carries no bypass ignore the setting.
    async with system_session(db.app, GUC_BYPASS, "tenant-a") as conn:
        assert await _bodies(conn) == []


async def test_role_bypass_is_out_of_the_app_roles_reach(db: Db) -> None:
    async with scoped_session(db.app, ROLE_BYPASS, A1) as conn:
        await conn.execute(text("SELECT set_config('t.role', 'system', true)"))
        assert await _bodies(conn, "notes_role") == ["a1"]
    with pytest.raises(DBAPIError, match="permission denied"):
        async with scoped_session(db.app, ROLE_BYPASS, A1) as conn:
            await conn.execute(text(f"SET LOCAL ROLE {RECONCILER}"))
    async with scoped_session(db.job, ROLE_BYPASS, A1) as conn:
        assert await _bodies(conn, "notes_role") == ["a1", "a2"]
    async with transaction(db.job) as conn:
        assert await _bodies(conn, "notes_role") == []


async def test_system_session_needs_a_guc_bypass_and_a_real_tenant() -> None:
    engine = create_async_engine("postgresql+asyncpg://unused@127.0.0.1:1/unused")
    for model, tenant, match in (
        (NOTES, None, "GucBypass"),
        (ROLE_BYPASS, None, "GucBypass"),
        (GUC_BYPASS, "", "non-empty"),
    ):
        with pytest.raises(ValueError, match=match):
            async with system_session(engine, model, tenant):
                pytest.fail("opened a session it should refuse")
    await engine.dispose()


# --- the edge of the guarantee -----------------------------------------------------------


async def test_arbitrary_sql_in_the_app_role_is_outside_the_guarantee(db: Db) -> None:
    """The documented limit: the app role can set any context setting, so SQL it runs
    unchecked can move its own session to another tenant. Isolation holds against query bugs
    and identity from untrusted input, not against arbitrary SQL in the app role. If this test
    starts failing, the threat model in the README has changed and must be rewritten."""
    async with scoped_session(db.app, NOTES, A1) as conn:
        await conn.execute(text("SELECT set_config('t.tenant_id', 'tenant-b', true)"))
        assert await _bodies(conn) == ["b1"]
