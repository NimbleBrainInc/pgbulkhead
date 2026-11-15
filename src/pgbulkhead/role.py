"""Refuse a database session that row-level security does not apply to.

Postgres skips every row-level security policy for a superuser and for a role with
``BYPASSRLS``, ``FORCE ROW LEVEL SECURITY`` included, and a managed Postgres can exempt more
roles than those: on Amazon RDS a member of ``rds_superuser`` has neither attribute and still
bypasses every policy. A server that connects as such a role sees and writes every tenant's
rows, and nothing in a query result says so. That one misconfiguration voids every wall, so it
is checked rather than trusted to the docs:

  * :func:`create_pooled_engine` installs :func:`install_role_guard` by default, so a pooled
    engine refuses each new connection whose session bypasses row-level security, before any
    session runs on it.
  * :func:`check_role` runs the same checks on a connection you already hold, for an engine you
    built yourself.

Each new physical connection is checked three ways, and refused if any says it bypasses:

  1. **Attributes.** The role is a superuser or has ``BYPASSRLS``.
  2. **Managed admin roles.** The role is a member, directly or not, of a role a managed
     Postgres uses for its administrator (:data:`MANAGED_ADMIN_ROLES`, or your own list).
  3. **Behaviour.** In a transaction that is always rolled back, the session creates a
     temporary table holding one row, forces row-level security on it with a policy that hides
     every row, and counts its rows. A session that policies apply to counts 0; one that
     bypasses them, for any reason, counts 1. The table lives only in that transaction, so no
     catalog change outlasts the check.

The probe needs the ``TEMP`` privilege on the database (granted to ``PUBLIC`` by default) and a
writable session. Without either (``TEMP`` revoked, a hot standby, or
``default_transaction_read_only``) the connection is checked by the first two only, and the
``pgbulkhead.role`` logger warns that the probe could not run.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Iterable
from typing import Any

from sqlalchemy import event, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

__all__ = ["MANAGED_ADMIN_ROLES", "UnsafeRoleError", "check_role", "install_role_guard"]

log = logging.getLogger(__name__)

#: The administrator roles of managed Postgres services: Amazon RDS and Aurora, Azure Database
#: for PostgreSQL, Google Cloud SQL, AlloyDB, and Neon. A server's app role is never meant to be
#: a member of one.
MANAGED_ADMIN_ROLES: tuple[str, ...] = (
    "rds_superuser",
    "azure_pg_admin",
    "cloudsqlsuperuser",
    "alloydbsuperuser",
    "neon_superuser",
)

_PROBE_TABLE = "pg_temp.pgbulkhead_rls_probe"
_PROBE_STATEMENTS = (
    f"CREATE TEMPORARY TABLE {_PROBE_TABLE} AS SELECT 1 AS x",
    f"ALTER TABLE {_PROBE_TABLE} ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY",
    f"CREATE POLICY pgbulkhead_hide_every_row ON {_PROBE_TABLE} USING (false)",
)
_PROBE_COUNT = f"SELECT count(*) FROM {_PROBE_TABLE}"


class UnsafeRoleError(RuntimeError):
    """The connection's session bypasses row-level security (its role is a superuser, has
    ``BYPASSRLS``, belongs to a managed Postgres admin role, or was seen to bypass a forced
    policy), so pgbulkhead refuses to use it."""


def _literal(value: str) -> str:
    """``value`` as a Postgres string literal, whatever ``standard_conforming_strings`` is."""
    return "E'" + value.replace("\\", "\\\\").replace("'", "''") + "'"


def _admin_roles(admin_roles: Iterable[str]) -> tuple[str, ...]:
    roles = tuple(admin_roles)
    for role in roles:
        if not isinstance(role, str) or not role or "\x00" in role:
            raise ValueError(f"admin_roles holds {role!r}, which is not a role name")
    return roles


def _role_query(admin_roles: tuple[str, ...]) -> str:
    """The role's attributes, the listed admin roles it belongs to, and whether the behavioural
    probe can run in this session. Schema-qualified, so no ``search_path`` can shadow a name."""
    names = ", ".join(_literal(r) for r in admin_roles)
    return (
        "SELECT r.rolname::text, r.rolsuper, r.rolbypassrls, "
        "ARRAY(SELECT a.rolname::text FROM pg_catalog.pg_roles a "
        f"WHERE a.rolname::text = ANY (ARRAY[{names}]::text[]) "
        "AND pg_catalog.pg_has_role(r.oid, a.oid, 'MEMBER') ORDER BY 1), "
        "pg_catalog.has_database_privilege(pg_catalog.current_database(), 'TEMP') "
        "AND NOT pg_catalog.pg_is_in_recovery() "
        "AND pg_catalog.current_setting('transaction_read_only') = 'off' "
        "FROM pg_catalog.pg_roles r WHERE r.rolname = CURRENT_USER"
    )


def _reasons(superuser: bool, bypassrls: bool, member_of: list[str]) -> list[str]:
    reasons = []
    if superuser:
        reasons.append("is a superuser")
    if bypassrls:
        reasons.append("has BYPASSRLS")
    if member_of:
        names = ", ".join(repr(r) for r in member_of)
        reasons.append(f"is a member of {names}, a managed Postgres admin role")
    return reasons


_PROBE_REASON = "saw a row that a forced policy hides from everyone (a probe on a temporary table)"


def _refuse(role: str, reasons: list[str]) -> None:
    if not reasons:
        return
    raise UnsafeRoleError(
        f"database role {role!r} {' and '.join(reasons)}, so Postgres applies no row-level "
        "security policy to this session and every tenant's rows would be visible. Connect as "
        "a role created with NOSUPERUSER NOBYPASSRLS that belongs to no admin role."
    )


def _autocommit(dbapi_connection: Any) -> bool:
    """Whether the driver connection runs each statement in its own transaction, so the probe
    must open and roll back one itself."""
    return bool(getattr(dbapi_connection, "autocommit", False))


def _warn_no_probe(role: str) -> None:
    log.warning(
        "pgbulkhead could not run its row-level security probe for role %r (the probe needs "
        "the TEMP privilege on the database and a writable session); the connection was "
        "checked by its role attributes and admin-role membership only",
        role,
    )


async def _probe(conn: AsyncConnection, reasons: list[str]) -> None:
    for statement in _PROBE_STATEMENTS:
        await conn.execute(text(statement))
    if (await conn.execute(text(_PROBE_COUNT))).scalar_one() != 0:
        reasons.append(_PROBE_REASON)


_SAVEPOINT = "pgbulkhead_rls_probe"
_NO_ACTIVE_SQL_TRANSACTION = "25P01"


async def _savepoint(conn: AsyncConnection) -> bool:
    """Set the probe's savepoint, or return ``False`` when no transaction block is open."""
    try:
        await conn.execute(text(f"SAVEPOINT {_SAVEPOINT}"))
    except DBAPIError as error:
        if getattr(error.orig, "sqlstate", None) == _NO_ACTIVE_SQL_TRANSACTION:
            return False
        raise
    return True


async def check_role(
    conn: AsyncConnection, *, admin_roles: Iterable[str] = MANAGED_ADMIN_ROLES
) -> None:
    """Raise :class:`UnsafeRoleError` if ``conn``'s session bypasses row-level security.

    The probe runs in a savepoint that is rolled back, so a transaction ``conn`` holds is left
    as it was; on an ``AUTOCOMMIT`` connection with no transaction open it runs in a transaction
    of its own, rolled back.
    ``admin_roles`` replaces :data:`MANAGED_ADMIN_ROLES`.
    """
    row = (await conn.execute(text(_role_query(_admin_roles(admin_roles))))).one()
    role, superuser, bypassrls, member_of, can_probe = row
    reasons = _reasons(superuser, bypassrls, list(member_of))
    if not reasons:
        if not can_probe:
            _warn_no_probe(role)
        elif _autocommit((await conn.get_raw_connection()).dbapi_connection):
            # Autocommit does not say whether the caller opened a transaction with SQL BEGIN;
            # the server does, by refusing a savepoint outside one.
            owned = not await _savepoint(conn)
            if owned:
                await conn.execute(text("BEGIN"))
            try:
                await _probe(conn, reasons)
            finally:
                if owned:
                    await conn.execute(text("ROLLBACK"))
                else:
                    await conn.execute(text(f"ROLLBACK TO SAVEPOINT {_SAVEPOINT}"))
                    await conn.execute(text(f"RELEASE SAVEPOINT {_SAVEPOINT}"))
        else:
            savepoint = await conn.begin_nested()
            try:
                await _probe(conn, reasons)
            finally:
                await savepoint.rollback()
    _refuse(role, reasons)


def install_role_guard(
    engine: AsyncEngine, *, admin_roles: Iterable[str] = MANAGED_ADMIN_ROLES
) -> AsyncEngine:
    """Refuse every new connection ``engine`` makes whose session bypasses row-level security.

    The checks run when the pool opens a physical connection, in one transaction that is rolled
    back before the connection is handed out, on an ``AUTOCOMMIT`` engine too. A refused
    connection is closed here, before the error propagates, so the checkout that asked for it
    fails with :class:`UnsafeRoleError`, no session ever runs on it, and repeated attempts leave
    no connection open on the server.
    (Some SQLAlchemy 2.0 releases do not close a connection whose ``connect`` listener raised.)
    ``admin_roles`` replaces :data:`MANAGED_ADMIN_ROLES`. Returns ``engine``.
    """
    query = _role_query(_admin_roles(admin_roles))

    @event.listens_for(engine.sync_engine, "connect")
    def _guard(dbapi_connection: Any, _record: Any) -> None:
        try:
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute(query)
                role, superuser, bypassrls, member_of, can_probe = cursor.fetchone()
                reasons = _reasons(superuser, bypassrls, list(member_of))
                if not reasons and can_probe:
                    autocommit = _autocommit(dbapi_connection)
                    if autocommit:
                        cursor.execute("BEGIN")
                    try:
                        for statement in _PROBE_STATEMENTS:
                            cursor.execute(statement)
                        cursor.execute(_PROBE_COUNT)
                        if cursor.fetchone()[0] != 0:
                            reasons.append(_PROBE_REASON)
                    finally:
                        if autocommit:
                            cursor.execute("ROLLBACK")
            finally:
                cursor.close()
            dbapi_connection.rollback()
            if not reasons and not can_probe:
                _warn_no_probe(role)
            _refuse(role, reasons)
        except BaseException:
            # Close it ourselves, keeping the refusal (or the failed check) as the error the
            # caller sees.
            with contextlib.suppress(Exception):
                dbapi_connection.close()
            raise

    return engine
