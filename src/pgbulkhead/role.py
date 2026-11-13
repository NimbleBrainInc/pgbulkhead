"""Refuse a database role that row-level security does not apply to.

Postgres skips every row-level security policy for a superuser and for a role with
``BYPASSRLS``, ``FORCE ROW LEVEL SECURITY`` included. A server that connects as one sees and
writes every tenant's rows, and nothing in a query result says so. That one misconfiguration
voids every wall, so it is checked rather than trusted to the docs:

  * :func:`create_pooled_engine` installs :func:`install_role_guard` by default, so a pooled
    engine refuses each new connection made as such a role, before any session runs on it.
  * :func:`check_role` runs the same check on a connection you already hold, for an engine you
    built yourself.

The check reads the connected role's attributes once per new connection, not per session.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

__all__ = ["UnsafeRoleError", "check_role", "install_role_guard"]

_ROLE_QUERY = (
    "SELECT current_user, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
)


class UnsafeRoleError(RuntimeError):
    """The connection's database role is a superuser or has ``BYPASSRLS``, so row-level
    security does not apply to it and pgbulkhead refuses to use it."""


def _refuse(role: str, superuser: bool, bypassrls: bool) -> None:
    if not (superuser or bypassrls):
        return
    attribute = "a superuser" if superuser else "BYPASSRLS"
    raise UnsafeRoleError(
        f"database role {role!r} is {attribute}: Postgres applies no row-level security policy "
        "to it, so every tenant's rows would be visible. Connect as a role created with "
        "NOSUPERUSER NOBYPASSRLS."
    )


async def check_role(conn: AsyncConnection) -> None:
    """Raise :class:`UnsafeRoleError` if ``conn``'s role bypasses row-level security."""
    role, superuser, bypassrls = (await conn.execute(text(_ROLE_QUERY))).one()
    _refuse(role, superuser, bypassrls)


def install_role_guard(engine: AsyncEngine) -> AsyncEngine:
    """Refuse every new connection ``engine`` makes as a role that bypasses row-level security.

    The check runs when the pool opens a physical connection; raising there discards the
    connection, so the checkout that asked for it fails with :class:`UnsafeRoleError` and no
    session ever runs as that role. Returns ``engine``.
    """

    @event.listens_for(engine.sync_engine, "connect")
    def _guard(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute(_ROLE_QUERY)
            role, superuser, bypassrls = cursor.fetchone()
        finally:
            cursor.close()
        _refuse(role, superuser, bypassrls)

    return engine
