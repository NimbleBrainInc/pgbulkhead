"""Per-workspace admission: no one workspace can take every pooled connection on a pod.

Every call takes a pooled connection for its session, and the pool is shared by every
workspace the pod serves. Without a limit, one client that fires a burst of calls holds the
whole pool, and every other workspace's call waits behind it. :class:`WorkspaceLimiter` admits
at most ``limit`` calls per workspace at once, *before* the call checks a connection out, so a
burst queues behind its own workspace's slots while other workspaces keep theirs.

The key is the verified ``(tenant_id, workspace_id)`` of the call's :class:`SecurityContext`,
which a server builds from a verified identity alone; nothing a caller passes can choose it.

A call over the limit waits up to ``wait_seconds`` for a slot, then is refused with
:class:`WorkspaceBusy`. An admitted call whose checkout then waits past the pool's timeout is
refused with :class:`PoolExhausted`. Both are :class:`Overloaded`: the call ran nothing, so
retrying it is safe, and each server maps it onto its own error surface as ``rate_limited``.

State is bounded by the calls in flight: a workspace's entry exists only while some call holds
or waits for one of its slots, and is dropped when the last one leaves.

Admit only the call's own session (:func:`admitted_session`). A write a call commits apart
from its session opens a second session while the call already holds a slot; admitting that
one too could deadlock a workspace whose every slot is held by a call waiting for its second
session. A request that runs several sessions one after another holds one slot across them
all (:class:`AdmittedSlot`, from :meth:`SecuredDatabase.admitted
<pgbulkhead.SecuredDatabase.admitted>`).
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Callable, Mapping
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import anyio
from sqlalchemy.exc import TimeoutError as PoolTimeout

from .context import SecurityContext
from .pool import PoolSettings

__all__ = [
    "AdmittedSlot",
    "Overloaded",
    "RefusalText",
    "PoolExhausted",
    "WorkspaceBusy",
    "WorkspaceLimiter",
    "admitted_session",
]


class Overloaded(Exception):
    """The call was refused before it ran anything, because the server is at capacity.

    ``message`` and ``next_step`` are text a server can return to the agent as they are: they
    say nothing ran, so a retry is safe. Map it onto your error surface as a rate limit. Replace
    the text with ``refusals`` on :class:`~pgbulkhead.SecuredDatabase` or
    :func:`admitted_session`.
    """

    message = "The server is at capacity right now. Nothing was run."
    next_step = "Wait a few seconds, then retry the call."

    def __init__(self) -> None:
        super().__init__(self.message)


class WorkspaceBusy(Overloaded):
    """A call waited its bound for one of its workspace's slots and did not get one."""

    message = (
        "This workspace already has as many requests running as the server allows at once, "
        "and this one waited too long for its turn. Nothing was run."
    )
    next_step = "Wait a few seconds, then retry the call; send fewer calls at once."


class PoolExhausted(Overloaded):
    """An admitted call found no free database connection within the pool's timeout."""

    message = "The server has no free database connection right now. Nothing was run."
    next_step = "Wait a few seconds, then retry the call."


@dataclass(frozen=True, slots=True)
class RefusalText:
    """Text to return in place of an :class:`Overloaded` refusal's defaults."""

    message: str
    next_step: str


#: Replacement text per refusal class. A refusal takes its own class's entry, else the entry of
#: its nearest listed base class, else keeps its defaults.
Refusals = Mapping[type[Overloaded], RefusalText]


def _apply(exc: Overloaded, refusals: Refusals | None) -> Overloaded:
    """``exc`` carrying the text ``refusals`` gives its class, if any."""
    if refusals:
        for cls in type(exc).__mro__:
            text = refusals.get(cls)
            if text is not None:
                exc.message = text.message
                exc.next_step = text.next_step
                exc.args = (text.message,)
                break
    return exc


@dataclass(slots=True)
class _Slots:
    semaphore: anyio.Semaphore
    # The calls holding or waiting for one of these slots; the entry is dropped at zero.
    users: int = field(default=0)


class WorkspaceLimiter:
    """At most ``limit`` concurrent admitted calls per workspace, waiting ``wait_seconds``."""

    def __init__(self, *, limit: int, wait_seconds: float) -> None:
        if limit < 1:
            raise ValueError("limit must be at least 1")
        self.limit = limit
        self.wait_seconds = wait_seconds
        self._slots: dict[tuple[str, str | None], _Slots] = {}

    @classmethod
    def from_settings(cls, settings: PoolSettings) -> WorkspaceLimiter:
        """The limiter ``settings`` sized together with the pool."""
        return cls(
            limit=settings.workspace_concurrency, wait_seconds=settings.workspace_wait_seconds
        )

    def tracked(self) -> int:
        """How many workspaces have an entry: those with a call holding or waiting for a slot."""
        return len(self._slots)

    @asynccontextmanager
    async def admit(self, ctx: SecurityContext) -> AsyncGenerator[None, None]:
        """Hold one of ``ctx``'s workspace's slots for the body, or raise :class:`WorkspaceBusy`.

        The lookup and the count change run with no await between them, so on one event loop
        no other call can see the entry between its creation and its first user.
        """
        key = (ctx.tenant_id, ctx.workspace_id)
        slots = self._slots.get(key)
        if slots is None:
            slots = self._slots[key] = _Slots(anyio.Semaphore(self.limit))
        slots.users += 1
        try:
            try:
                with anyio.fail_after(self.wait_seconds):
                    await slots.semaphore.acquire()
            except TimeoutError:
                raise WorkspaceBusy from None
            try:
                yield
            finally:
                slots.semaphore.release()
        finally:
            slots.users -= 1
            if slots.users == 0:
                del self._slots[key]


@asynccontextmanager
async def _refusing_checkout_timeout[T](
    session: AbstractAsyncContextManager[T], refusals: Refusals | None = None
) -> AsyncGenerator[T, None]:
    """Enter ``session``, turning a pool timeout at its own checkout into :class:`PoolExhausted`.

    A pool timeout raised after the session is open belongs to the body (a second session it
    opened, say, which may follow a committed write), so it propagates unchanged.
    """
    entered = False
    try:
        async with session as opened:
            entered = True
            yield opened
    except PoolTimeout:
        if entered:
            raise
        raise _apply(PoolExhausted(), refusals) from None


class AdmittedSlot:
    """One of a workspace's slots, held by a request that opens several sessions in turn.

    Each :meth:`session` runs under the held slot, so the request uses one connection at a
    time and never waits on its own workspace's slots.

    Until a session under the slot has opened, nothing has run under it, so a checkout that
    times out raises :class:`PoolExhausted`, which says a retry is safe. Once one has opened, it
    may have committed, and a later checkout that times out raises the pool's own
    ``TimeoutError`` instead: the request as a whole is no longer safe to retry.
    """

    def __init__(
        self,
        ctx: SecurityContext,
        open_session: Callable[[SecurityContext], AbstractAsyncContextManager[Any]],
    ) -> None:
        self.ctx = ctx
        self._open_session = open_session
        self._opened = False

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[Any, None]:
        """A session for the slot's context, under the held slot.

        Whether a checkout timeout is a refusal is decided on entry, not when the context
        manager is made: one made earlier may be entered after another session has opened.
        """
        if self._opened:
            async with self._open_session(self.ctx) as session:
                yield session
            return
        async with _refusing_checkout_timeout(self._open_session(self.ctx)) as session:
            self._opened = True
            yield session


@asynccontextmanager
async def admitted_session[T](
    limiter: WorkspaceLimiter,
    ctx: SecurityContext,
    open_session: Callable[[SecurityContext], AbstractAsyncContextManager[T]],
    *,
    refusals: Refusals | None = None,
) -> AsyncGenerator[T, None]:
    """Admit the call for ``ctx``'s workspace, then open its session with ``open_session``.

    Raises :class:`WorkspaceBusy` when no slot frees within the limiter's wait, and
    :class:`PoolExhausted` when the session's own checkout times out. A pool timeout raised
    after the session is open belongs to the body, so it propagates unchanged.

    The slot is released by the same exit that returns the session's connection, so a call
    left by cancellation gives its slot back.
    """
    try:
        async with (
            limiter.admit(ctx),
            _refusing_checkout_timeout(open_session(ctx), refusals) as session,
        ):
            yield session
    except WorkspaceBusy as exc:
        # The same object, re-raised: a refusal from the body is this server's too.
        _apply(exc, refusals)
        raise
