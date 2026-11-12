"""The connection pool a server builds its engine with, sized together with admission.

Every server that owns a database serves many workspaces from one pool per pod. The pool's
size and the per-workspace admission limit (:mod:`pgbulkhead.admission`) are one
decision, so they are read, validated and held together in :class:`PoolSettings`:

  * ``pool_size`` / ``max_overflow`` — the connections the pool keeps open, and the ones it may
    open past that under load. Their sum is the most connections one pod holds.
  * ``pool_timeout_seconds`` — how long a checkout waits for a free connection before the pool
    gives up. A call that gives up here is refused as overloaded, having run nothing.
  * ``workspace_concurrency`` — how many calls one workspace may run at once on the pod.
  * ``workspace_wait_seconds`` — how long a call over that limit waits for a slot before it is
    refused as overloaded.

**The rule that ties them:** a call holds its session's connection, and at most one more for a
write it commits apart from its session (:data:`CONNECTIONS_PER_CALL`). So a workspace at its
limit holds at most ``CONNECTIONS_PER_CALL × workspace_concurrency`` connections, and that must
stay below the pool's total, or one workspace could hold every connection and every other
workspace's call would wait behind it. Settings that break the rule raise
:class:`PoolConfigError` on construction, which a server does at boot so a value that cannot
hold fails the rollout rather than a user's call.

The default waits sit well under a typical MCP host's tool-call budget (about a minute), so
an overloaded pod answers with a refusal the agent can retry instead of a call the host
abandons.

Each value is read from ``<PREFIX>_<NAME>`` (:meth:`PoolSettings.from_env`), the prefix being
the server's own env namespace. Unset, it takes the server's defaults: this module's conservative
ones unless the server passes its own because its traffic needs more.

**The connection budget.** A pod holds at most ``pool_size + max_overflow`` connections, so the
worst case on one database is::

    sum over the servers using it of (pool_size + max_overflow) × (replicas + max_surge)

where ``max_surge`` is the extra pods a rolling update runs at once (one per server rolling).
That sum, plus whatever else connects to the database, must stay below its
``max_connections``. Raising a pool setting or a replica count spends that budget.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

__all__ = [
    "CONNECTIONS_PER_CALL",
    "PoolConfigError",
    "PoolSettings",
    "create_pooled_engine",
]

#: The most connections one admitted call holds at once: its session, and one write committed
#: apart from it.
CONNECTIONS_PER_CALL = 2

# The env suffix of each setting, after the server's prefix and an underscore.
POOL_SIZE_ENV = "DB_POOL_SIZE"
MAX_OVERFLOW_ENV = "DB_POOL_MAX_OVERFLOW"
POOL_TIMEOUT_ENV = "DB_POOL_TIMEOUT_SECONDS"
WORKSPACE_CONCURRENCY_ENV = "WORKSPACE_CONCURRENCY"
WORKSPACE_WAIT_ENV = "WORKSPACE_WAIT_SECONDS"


class PoolConfigError(ValueError):
    """A pool or admission setting is malformed, or the settings together cannot hold."""


@dataclass(frozen=True, slots=True)
class PoolSettings:
    """One server's pool and per-workspace admission settings, validated on construction.

    The field defaults are conservative, sized for a server whose peak is a few calls in
    flight, so several servers sharing one database stay well inside its connection budget.
    """

    pool_size: int = 5
    max_overflow: int = 5
    pool_timeout_seconds: float = 10.0
    workspace_concurrency: int = 2
    workspace_wait_seconds: float = 15.0

    def __post_init__(self) -> None:
        if self.pool_size < 1:
            raise PoolConfigError(f"pool_size must be at least 1, got {self.pool_size}")
        if self.max_overflow < 0:
            raise PoolConfigError(f"max_overflow must be at least 0, got {self.max_overflow}")
        if self.workspace_concurrency < 1:
            raise PoolConfigError(
                f"workspace_concurrency must be at least 1, got {self.workspace_concurrency}"
            )
        for name in ("pool_timeout_seconds", "workspace_wait_seconds"):
            if not getattr(self, name) > 0:
                raise PoolConfigError(
                    f"{name} must be greater than zero, got {getattr(self, name)}"
                )
        held = CONNECTIONS_PER_CALL * self.workspace_concurrency
        if held >= self.total:
            raise PoolConfigError(
                f"workspace_concurrency={self.workspace_concurrency} lets one workspace hold "
                f"{held} of the pool's {self.total} connections; it must hold fewer, so other "
                "workspaces still get one"
            )

    @property
    def total(self) -> int:
        """The most connections the pool holds: ``pool_size + max_overflow``."""
        return self.pool_size + self.max_overflow

    @classmethod
    def from_env(
        cls,
        prefix: str,
        *,
        defaults: PoolSettings | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> PoolSettings:
        """Read ``<prefix>_DB_POOL_SIZE``, ``…_DB_POOL_MAX_OVERFLOW``,
        ``…_DB_POOL_TIMEOUT_SECONDS``, ``…_WORKSPACE_CONCURRENCY`` and
        ``…_WORKSPACE_WAIT_SECONDS``; an unset or blank one takes its value from ``defaults``
        (this class's when omitted).

        Raises :class:`PoolConfigError`, naming the variables, for a value that does not parse
        or settings that cannot hold together.
        """
        env = os.environ if environ is None else environ
        if defaults is None:
            defaults = cls()

        def raw(suffix: str) -> tuple[str, str | None]:
            name = f"{prefix}_{suffix}"
            value = env.get(name, "").strip()
            return name, value or None

        def integer(suffix: str, default: int) -> int:
            name, value = raw(suffix)
            if value is None:
                return default
            try:
                return int(value)
            except ValueError:
                raise PoolConfigError(f"{name} must be an integer, got {value!r}") from None

        def seconds(suffix: str, default: float) -> float:
            name, value = raw(suffix)
            if value is None:
                return default
            try:
                return float(value)
            except ValueError:
                raise PoolConfigError(
                    f"{name} must be a number of seconds, got {value!r}"
                ) from None

        values = {
            "pool_size": integer(POOL_SIZE_ENV, defaults.pool_size),
            "max_overflow": integer(MAX_OVERFLOW_ENV, defaults.max_overflow),
            "pool_timeout_seconds": seconds(POOL_TIMEOUT_ENV, defaults.pool_timeout_seconds),
            "workspace_concurrency": integer(
                WORKSPACE_CONCURRENCY_ENV, defaults.workspace_concurrency
            ),
            "workspace_wait_seconds": seconds(WORKSPACE_WAIT_ENV, defaults.workspace_wait_seconds),
        }
        try:
            return cls(**values)
        except PoolConfigError as exc:
            raise PoolConfigError(f"{exc} (read from the {prefix}_* settings)") from None

    def engine_options(self) -> dict[str, Any]:
        """The pool keywords for ``create_async_engine``."""
        return {
            "pool_pre_ping": True,
            "pool_size": self.pool_size,
            "max_overflow": self.max_overflow,
            "pool_timeout": self.pool_timeout_seconds,
        }


def create_pooled_engine(url: str, settings: PoolSettings, **options: Any) -> AsyncEngine:
    """An async engine whose pool is sized by ``settings``, with ``pool_pre_ping`` on.

    ``options`` pass through to ``create_async_engine`` and may override the pool keywords.
    """
    return create_async_engine(url, **{**settings.engine_options(), **options})
