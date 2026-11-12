"""pgbulkhead: tenant isolation for multi-tenant MCP servers on Postgres.

One database, many tenants and workspaces: Postgres enforces the walls, and no agent can talk
its way through them.

  * :class:`TenancyModel` names the walls (a tenant column, an optional workspace column) and
    the settings that carry them; :func:`policy_sql` renders its row-level security policies
    for a migration.
  * :class:`SecurityContext` is the verified identity of one request, and
    :func:`scoped_session` binds it for the length of a transaction, so every query runs
    inside its walls and a pooled connection never carries it to the next request.
  * :class:`SecuredDatabase` holds one server's engine, pool settings and per-workspace
    admission, so one agent's fan-out queues behind its own workspace's slots, and refuses
    an overloaded call with :class:`Overloaded` before it runs anything.

Isolation holds against query bugs and against identity taken from untrusted input. It does
not hold against arbitrary SQL executed as the app role, which can set any context setting.
The README's threat model says what each guarantee rests on.
"""

from .admission import (
    AdmittedSlot,
    Overloaded,
    PoolExhausted,
    RefusalText,
    WorkspaceBusy,
    WorkspaceLimiter,
    admitted_session,
)
from .context import ClaimNames, SecurityContext, context_from_claims
from .database import SecuredDatabase
from .model import GucBypass, RoleBypass, TenancyModel
from .policy import policy_sql, policy_statements
from .pool import CONNECTIONS_PER_CALL, PoolConfigError, PoolSettings, create_pooled_engine
from .session import (
    CLEANUP_TIMEOUT_SECONDS,
    bind_context,
    scoped_session,
    system_session,
    transaction,
)

__all__ = [
    "CLEANUP_TIMEOUT_SECONDS",
    "CONNECTIONS_PER_CALL",
    "AdmittedSlot",
    "ClaimNames",
    "GucBypass",
    "Overloaded",
    "PoolConfigError",
    "PoolExhausted",
    "PoolSettings",
    "RefusalText",
    "RoleBypass",
    "SecuredDatabase",
    "SecurityContext",
    "TenancyModel",
    "WorkspaceBusy",
    "WorkspaceLimiter",
    "admitted_session",
    "bind_context",
    "context_from_claims",
    "create_pooled_engine",
    "policy_sql",
    "policy_statements",
    "scoped_session",
    "system_session",
    "transaction",
]
