"""One server's database: its tenancy model, pool settings, pooled engine and workspace limiter.

A server declares one :class:`SecuredDatabase` per process::

    db = SecuredDatabase(model=MODEL, url_env="NOTES_DATABASE_URL", prefix="NOTES")

and calls :meth:`SecuredDatabase.check` once before it serves. The object reads and validates
the settings once, builds the engine lazily on the first session (importing the server needs no
database), and admits every :meth:`~SecuredDatabase.session` against the workspace's
concurrency limit before it checks a connection out.
"""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from .admission import (
    AdmittedSlot,
    Refusals,
    WorkspaceBusy,
    WorkspaceLimiter,
    _apply,
    admitted_session,
)
from .context import SecurityContext
from .model import TenancyModel
from .pool import PoolSettings, create_pooled_engine
from .session import scoped_session, system_session

__all__ = ["SecuredDatabase"]


class SecuredDatabase:
    """The model, settings, engine and limiter one server process uses for its own database.

    ``model`` is how its tables are isolated. ``url_env`` names the env var holding the async
    Postgres URL, for a role that is neither a superuser nor ``BYPASSRLS``; ``url`` instead
    supplies it with a callable. ``prefix`` is the env namespace of the pool settings
    (:class:`PoolSettings`), and ``defaults`` the server's own when its traffic needs more than
    the class defaults. ``refusals`` replaces the text of the overload errors its sessions raise.
    """

    def __init__(
        self,
        *,
        model: TenancyModel,
        prefix: str,
        url_env: str | None = None,
        url: Callable[[], str] | None = None,
        defaults: PoolSettings | None = None,
        refusals: Refusals | None = None,
    ) -> None:
        if url_env is None and url is None:
            raise ValueError("SecuredDatabase needs url_env or url")
        self.model = model
        self.url_env = url_env
        self.prefix = prefix
        self.refusals = refusals
        self._defaults = defaults
        self._url = url or self._url_from_env
        self._settings: PoolSettings | None = None
        self._limiter: WorkspaceLimiter | None = None
        self._engine: AsyncEngine | None = None

    def _url_from_env(self) -> str:
        assert self.url_env is not None
        url = os.environ.get(self.url_env, "").strip()
        if not url:
            raise RuntimeError(
                f"{self.url_env} is not set — the async Postgres URL for this server's app "
                "role (NOSUPERUSER NOBYPASSRLS) is required."
            )
        return url

    @property
    def settings(self) -> PoolSettings:
        """The pool and admission settings, read and validated on first use, then fixed."""
        if self._settings is None:
            self._settings = PoolSettings.from_env(self.prefix, defaults=self._defaults)
        return self._settings

    @property
    def limiter(self) -> WorkspaceLimiter:
        """The process-wide per-workspace limiter, sized with the pool."""
        if self._limiter is None:
            self._limiter = WorkspaceLimiter.from_settings(self.settings)
        return self._limiter

    def check(self) -> None:
        """Read and validate the settings and build the limiter; call it at startup.

        Raises :class:`~pgbulkhead.PoolConfigError` for settings that cannot hold, so a bad
        value fails the rollout rather than a user's call. Opens no connection.
        """
        _ = self.limiter

    def get_engine(self) -> AsyncEngine:
        """The pooled engine, built on first use."""
        if self._engine is None:
            self._engine = create_pooled_engine(self._url(), self.settings)
        return self._engine

    async def dispose(self) -> None:
        """Dispose the engine and its pool; the next session builds a new one."""
        if self._engine is not None:
            engine, self._engine = self._engine, None
            await engine.dispose()

    def session(self, ctx: SecurityContext) -> AbstractAsyncContextManager[AsyncConnection]:
        """The call's own scoped session, admitted against ``ctx``'s workspace limit first.

        Raises :class:`~pgbulkhead.Overloaded`, having run nothing, when no slot frees in time
        or, once admitted, no connection does.
        """
        return admitted_session(self.limiter, ctx, self.unadmitted_session, refusals=self.refusals)

    def unadmitted_session(
        self, ctx: SecurityContext
    ) -> AbstractAsyncContextManager[AsyncConnection]:
        """A scoped session with no admission, for one opened while the request holds a slot
        (a write committed apart from its session, say). Admitting that one too could deadlock
        a workspace whose every slot waits on a second session."""
        return scoped_session(self.get_engine(), self.model, ctx)

    @asynccontextmanager
    async def admitted(self, ctx: SecurityContext) -> AsyncGenerator[AdmittedSlot, None]:
        """Hold one of ``ctx``'s workspace slots across several sessions opened in turn."""
        try:
            async with self.limiter.admit(ctx):
                yield AdmittedSlot(ctx, self.unadmitted_session)
        except WorkspaceBusy as exc:
            _apply(exc, self.refusals)
            raise

    def system_session(
        self, tenant_id: str | None = None
    ) -> AbstractAsyncContextManager[AsyncConnection]:
        """A session through the model's :class:`~pgbulkhead.GucBypass`; never admitted, since
        it belongs to no one workspace. See :func:`pgbulkhead.system_session`."""
        return system_session(self.get_engine(), self.model, tenant_id)
