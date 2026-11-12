"""The tenancy model: which columns are the walls, and which settings carry them.

One :class:`TenancyModel` describes how a table set is isolated:

  * ``tenant_column`` is the **hard wall**. Every policy requires it to equal the session's
    tenant, and nothing bypasses it.
  * ``workspace_column`` is an optional **soft wall** inside a tenant. With it, reads span the
    session's readable workspaces (the active one plus any granted), and every write is bound
    to the active workspace. Without it (``None``) the model is single-key: read and write are
    both scoped on the tenant alone.
  * ``namespace`` is the prefix of the Postgres custom settings (GUCs) a session binds and the
    policies read: ``<namespace>.<tenant_column>`` and so on. Each setting can be named
    explicitly instead.
  * ``bypass`` lets a privileged session cross the **soft** wall, never the hard one. It is off
    unless you set it; see :class:`GucBypass` and :class:`RoleBypass` for what each costs.

Two models that use different settings cannot be confused: each policy reads only its own
settings, and ``current_setting(name, true)`` is NULL for one that is not bound, so a session
bound for one model matches no row of a table under another. Mixing models fails closed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

__all__ = ["GucBypass", "RoleBypass", "TenancyModel"]

_IDENTIFIER = re.compile(r"[a-z_][a-z0-9_]*")
_SETTING = re.compile(r"[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*")
#: Postgres truncates identifiers past 63 bytes, so two long names could collide silently.
_MAX_IDENTIFIER = 63


def check_identifier(value: str, what: str) -> str:
    """``value`` if it is a plain lower-case SQL identifier, else :class:`ValueError`.

    Names are interpolated into DDL, so anything else (quoting, a schema prefix, mixed case
    that Postgres would fold) is refused rather than escaped.
    """
    if not _IDENTIFIER.fullmatch(value) or len(value) > _MAX_IDENTIFIER:
        raise ValueError(f"{what} must be a lower-case SQL identifier of at most 63 bytes")
    return value


def _check_setting(value: str, what: str) -> str:
    if not _SETTING.fullmatch(value) or len(value) > _MAX_IDENTIFIER:
        raise ValueError(f"{what} must be a custom setting name like 'myapp.tenant_id'")
    return value


@dataclass(frozen=True, slots=True)
class GucBypass:
    """Cross the soft wall when a session sets ``setting`` to ``value``.

    The policies gain ``OR current_setting(setting, true) = value`` on the workspace predicate
    only; the tenant predicate is never gated by it. A session opts in with
    :func:`~pgbulkhead.system_session`.

    **What it costs.** The app role can set this setting, so any SQL the app role runs can
    take the bypass. That is the same exposure the tenant setting already has (see the threat
    model in the README): it holds against query bugs and against identity taken from
    untrusted input, not against arbitrary SQL in the app role. Use :class:`RoleBypass` when
    the privileged path should not be reachable from the app role at all.
    """

    setting: str | None = None
    value: str = "system"

    def __post_init__(self) -> None:
        if self.setting is not None:
            _check_setting(self.setting, "GucBypass.setting")
        check_identifier(self.value, "GucBypass.value")


@dataclass(frozen=True, slots=True)
class RoleBypass:
    """Cross the soft wall when the session's database role is a member of ``role``.

    The policies gain ``OR pg_has_role(current_user, role, 'MEMBER')`` on the workspace
    predicate only. A privileged job connects with its own login role (a member of ``role``)
    through its own engine; no setting grants the bypass, so SQL running as the app role cannot
    take it. **Never grant ``role`` to the app role**, or the app role is a member too.
    """

    role: str

    def __post_init__(self) -> None:
        check_identifier(self.role, "RoleBypass.role")


@dataclass(frozen=True, slots=True)
class TenancyModel:
    """How a set of tables is isolated. See the module docstring."""

    tenant_column: str = "tenant_id"
    workspace_column: str | None = "workspace_id"
    namespace: str = "pgbulkhead"
    tenant_setting: str | None = None
    workspace_setting: str | None = None
    readable_setting: str | None = None
    #: A setting the session binds the context's scopes to, for policies of your own that read
    #: them. ``None`` binds nothing.
    scopes_setting: str | None = None
    bypass: GucBypass | RoleBypass | None = None
    #: Bind the active workspace as readable whether or not the context lists it. ``False``
    #: binds ``allowed_workspaces`` exactly as given, for a context source that always lists
    #: the active workspace itself.
    active_is_readable: bool = True
    #: Also drop the other shape's policy names when rendering, so switching a table between
    #: the single-key and the per-command shape leaves no stale policy behind. Permissive
    #: policies combine with OR, so a stale one would widen access.
    drop_other_shape: bool = True
    _settings: dict[str, str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        check_identifier(self.tenant_column, "tenant_column")
        if self.workspace_column is not None:
            check_identifier(self.workspace_column, "workspace_column")
            if self.workspace_column == self.tenant_column:
                raise ValueError("workspace_column must differ from tenant_column")
        check_identifier(self.namespace, "namespace")
        if self.bypass is not None and self.workspace_column is None:
            raise ValueError(
                "a bypass crosses the workspace wall only; a single-key model has none, and "
                "nothing may cross the tenant wall"
            )
        ns = self.namespace
        settings = {"tenant": self.tenant_setting or f"{ns}.{self.tenant_column}"}
        if self.workspace_column is not None:
            settings["workspace"] = self.workspace_setting or f"{ns}.{self.workspace_column}"
            settings["readable"] = self.readable_setting or f"{ns}.allowed_workspaces"
        elif self.workspace_setting or self.readable_setting:
            raise ValueError("a single-key model binds no workspace or readable setting")
        if self.scopes_setting is not None:
            settings["scopes"] = self.scopes_setting
        if isinstance(self.bypass, GucBypass):
            settings["bypass"] = self.bypass.setting or f"{ns}.role"
        for name, value in settings.items():
            _check_setting(value, f"{name} setting")
        object.__setattr__(self, "_settings", settings)

    @property
    def has_workspace(self) -> bool:
        return self.workspace_column is not None

    def setting(self, name: str) -> str:
        """The resolved setting name for ``tenant``, ``workspace``, ``readable``, ``scopes``
        or ``bypass``. Raises ``KeyError`` for one the model does not use."""
        return self._settings[name]
