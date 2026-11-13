"""The verified identity a session binds.

A :class:`SecurityContext` is built **only** from something your server has verified: the
claims of a token it checked, or headers set by a gateway that checked one and that a caller
cannot reach past. Never from a tool argument or a request body. An agent writes those, and an
agent writes what its prompt steers it to, so a tenant taken from one is a tenant anyone who can
put text in front of the agent can choose. The body may *ask* for a workspace; the verified
identity decides whether it gets one.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, overload

__all__ = ["ClaimNames", "SecurityContext", "context_from_claims"]


@dataclass(frozen=True, slots=True)
class SecurityContext:
    """The identity and grants of one request.

    - ``tenant_id``: the hard wall. Never crossed.
    - ``workspace_id``: the active workspace, the soft wall inside the tenant, and the only one
      writes go to. ``None`` for a single-key model, which has no workspace.
    - ``allowed_workspaces``: the workspaces the request may **read**, from grants in the
      verified identity. A session reads the active workspace whether or not it is listed. A
      read grant never implies a write.
    - ``scopes``: capability scopes, checked with :meth:`require_scope`.
    """

    tenant_id: str
    workspace_id: str | None = None
    allowed_workspaces: frozenset[str] = frozenset()
    scopes: frozenset[str] = frozenset()
    user_id: str | None = None
    correlation_id: str | None = None

    def readable_workspaces(self) -> frozenset[str]:
        """The workspaces a session may read: the grants plus the active one."""
        if self.workspace_id is None:
            return self.allowed_workspaces
        return self.allowed_workspaces | {self.workspace_id}

    def require_scope(self, scope: str) -> None:
        """Raise :class:`PermissionError` unless the context carries ``scope``."""
        if scope not in self.scopes:
            raise PermissionError(f"missing required scope: {scope}")


@dataclass(frozen=True, slots=True)
class ClaimNames:
    """The claim each context field is read from. ``workspace`` is ``None`` for a single-key
    model, whose context has no workspace."""

    tenant: str = "tenant_id"
    workspace: str | None = "workspace_id"
    allowed_workspaces: str = "allowed_workspaces"
    scopes: str = "scopes"
    user_id: str = "user_id"
    correlation_id: str = "correlation_id"


@overload
def context_from_claims(
    claims: Mapping[str, object], names: ClaimNames | None = None
) -> SecurityContext: ...
@overload
def context_from_claims[C: SecurityContext](
    claims: Mapping[str, object], names: ClaimNames | None = None, *, cls: type[C]
) -> C: ...
def context_from_claims(
    claims: Mapping[str, object],
    names: ClaimNames | None = None,
    *,
    cls: type[Any] = SecurityContext,
) -> Any:
    """A context from **verified** token claims; ``cls`` builds a subclass.

    Fails closed: a missing or empty tenant (or workspace, when ``names.workspace`` is set)
    raises :class:`ValueError` rather than defaulting to a wider scope. The active workspace is
    always readable, so it is added to ``allowed_workspaces``. Scopes may be a list or OAuth's
    space-separated string; every other list claim must be a list.
    """
    names = names or ClaimNames()
    tenant = claims.get(names.tenant)
    if not isinstance(tenant, str) or not tenant:
        raise ValueError(f"security context requires a verified {names.tenant} claim")
    workspace: str | None = None
    if names.workspace is not None:
        value = claims.get(names.workspace)
        if not isinstance(value, str) or not value:
            raise ValueError(f"security context requires a verified {names.workspace} claim")
        workspace = value
    allowed = _str_set(claims.get(names.allowed_workspaces))
    return cls(
        tenant_id=tenant,
        workspace_id=workspace,
        allowed_workspaces=allowed | {workspace} if workspace else allowed,
        scopes=_scope_set(claims.get(names.scopes)),
        user_id=_opt_str(claims.get(names.user_id)),
        correlation_id=_opt_str(claims.get(names.correlation_id)),
    )


def _opt_str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _scope_set(value: object) -> frozenset[str]:
    """Scopes as a list, or as OAuth's single space-separated string (RFC 6749, section 3.3)."""
    if isinstance(value, str):
        return frozenset(value.split())
    return _str_set(value)


def _str_set(value: object) -> frozenset[str]:
    """A loosely typed claim (a list, tuple or set, or nothing) as a set of strings."""
    if isinstance(value, list | tuple | set | frozenset):
        return frozenset(str(x) for x in value)
    return frozenset()
