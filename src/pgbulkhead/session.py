"""Sessions that bind a context for row-level security, and return their connection when
cancelled.

**Binding.** A session sets the model's settings with ``set_config(name, value, true)`` inside a
transaction. ``true`` makes each one local to the transaction, so it ends at commit or rollback
and a pooled connection never carries one request's tenant into the next. Values are bound
parameters, never interpolated into SQL.

**Cancellation.** An MCP call runs under a cancel scope, and a cancelled scope raises again at
every await inside it. A session left by cancellation (a client that hung up, a host timeout)
would have its own rollback cancelled too, and SQLAlchemy would then terminate the connection
instead of returning it: every cancelled call would cost the pool a connection. Each session
here therefore ends its transaction and returns its connection inside a shielded scope. Each
cleanup step (the commit or rollback, then the return) is bounded by
:data:`CLEANUP_TIMEOUT_SECONDS`, so a database that stops answering cannot hold the exit
forever: past the bound a rollback or return is abandoned and the connection discarded, and a
commit raises ``TimeoutError``, because its writes may or may not have landed.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Iterable
from contextlib import asynccontextmanager

import anyio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from .context import SecurityContext
from .model import GucBypass, TenancyModel

__all__ = [
    "CLEANUP_TIMEOUT_SECONDS",
    "bind_context",
    "check_context",
    "scoped_session",
    "system_session",
    "transaction",
]

#: How long each cleanup step may run shielded from the caller's cancellation. The two steps
#: run in turn, so a whole exit is bounded by about twice this.
CLEANUP_TIMEOUT_SECONDS = 10.0


@asynccontextmanager
async def transaction(engine: AsyncEngine) -> AsyncGenerator[AsyncConnection, None]:
    """``engine.begin()`` with its exit shielded from the caller's cancellation.

    Commits when the body completes and rolls back when it raises (cancellation included), then
    returns the connection. Binds nothing: use it for work that needs no row-level scope.
    """
    conn = await engine.connect()
    try:
        trans = await conn.begin()
        try:
            yield conn
        except BaseException:
            if trans.is_active:
                with anyio.move_on_after(CLEANUP_TIMEOUT_SECONDS, shield=True):
                    await trans.rollback()
            raise
        if trans.is_active:
            with anyio.fail_after(CLEANUP_TIMEOUT_SECONDS, shield=True):
                await trans.commit()
    finally:
        with anyio.move_on_after(CLEANUP_TIMEOUT_SECONDS, shield=True):
            await conn.close()


async def _bind(conn: AsyncConnection, setting: str, value: str) -> None:
    await conn.execute(text(f"SELECT set_config('{setting}', :v, true)"), {"v": value})


async def bind_context(conn: AsyncConnection, model: TenancyModel, ctx: SecurityContext) -> None:
    """Bind ``ctx`` under ``model`` on ``conn``, for a transaction you already manage.

    Must run inside a transaction: outside one, each ``set_config(.., true)`` ends with its own
    statement and binds nothing. Binds the values as given; :func:`scoped_session` is the
    checked path, which refuses them first when they cannot be bound faithfully (see
    :func:`check_context`).

    The readable workspaces and the scopes are bound as one comma-joined value, and the policy
    splits it on commas again. A value containing a comma would therefore bind as several, and
    could make a workspace readable that the context never granted. Bind only checked values.
    """
    await _bind(conn, model.setting("tenant"), ctx.tenant_id)
    if model.has_workspace:
        readable = ctx.readable_workspaces() if model.active_is_readable else ctx.allowed_workspaces
        await _bind(conn, model.setting("workspace"), ctx.workspace_id or "")
        await _bind(conn, model.setting("readable"), ",".join(sorted(readable)))
    if model.scopes_setting is not None:
        await _bind(conn, model.setting("scopes"), ",".join(sorted(ctx.scopes)))


def check_context(model: TenancyModel, ctx: SecurityContext) -> None:
    """Raise :class:`ValueError` unless ``ctx`` can be bound under ``model`` faithfully.

    Refuses an empty tenant, and an empty workspace when the model has one, rather than binding
    a value that matches nothing: an unscoped read should be a deliberate act, not a typo that
    looks like an empty result. Refuses an empty or comma-bearing workspace, read grant or
    scope, because those are bound comma-joined and a comma inside one would split it into
    several on the database side, widening what the session may read.
    """
    if not ctx.tenant_id:
        raise ValueError("a scoped session requires a non-empty, verified tenant")
    if model.has_workspace:
        if not ctx.workspace_id:
            raise ValueError("this model requires a non-empty, verified workspace")
        _check_items((ctx.workspace_id, *ctx.allowed_workspaces), "workspace")
    if model.scopes_setting is not None:
        _check_items(ctx.scopes, "scope")


def _check_items(values: Iterable[str], what: str) -> None:
    for value in values:
        if not value or "," in value:
            raise ValueError(f"a {what} bound in a list must be non-empty and contain no comma")


@asynccontextmanager
async def scoped_session(
    engine: AsyncEngine, model: TenancyModel, ctx: SecurityContext
) -> AsyncGenerator[AsyncConnection, None]:
    """A transaction with ``ctx`` bound under ``model``.

    Every query inside sees only the context's tenant and, for a model with a workspace, the
    workspaces it may read; every write lands only in its tenant and active workspace. Raises
    :class:`ValueError` for a context :func:`check_context` refuses, before opening anything.
    """
    check_context(model, ctx)
    async with transaction(engine) as conn:
        await bind_context(conn, model, ctx)
        yield conn


@asynccontextmanager
async def system_session(
    engine: AsyncEngine, model: TenancyModel, tenant_id: str | None = None
) -> AsyncGenerator[AsyncConnection, None]:
    """A transaction that crosses the workspace wall through the model's :class:`GucBypass`.

    With ``tenant_id`` it reads and writes every workspace of that tenant. Without one it binds
    no tenant, so it matches no row until the body binds one itself: the tenant wall holds
    either way. Audit every use. Refused for a model without a ``GucBypass``: a
    :class:`~pgbulkhead.RoleBypass` is taken by connecting as the privileged role, so open a
    :func:`scoped_session` on an engine that connects as that role instead.
    """
    if not isinstance(model.bypass, GucBypass):
        raise ValueError("system_session needs a model whose bypass is a GucBypass")
    if tenant_id is not None and not tenant_id:
        raise ValueError("system_session requires a non-empty tenant when given one")
    async with transaction(engine) as conn:
        await conn.execute(
            text(f"SELECT set_config('{model.setting('bypass')}', '{model.bypass.value}', true)")
        )
        if tenant_id is not None:
            await _bind(conn, model.setting("tenant"), tenant_id)
        yield conn
