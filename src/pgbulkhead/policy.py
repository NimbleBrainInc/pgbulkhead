"""Row-level security policies for a :class:`~pgbulkhead.TenancyModel`, rendered as DDL.

Apply them in a migration, once per table. Every rendering enables **and forces** row-level
security, so the table owner is subject to the policy too, and every predicate reads its
setting with ``current_setting(name, true)``, which is NULL when the session bound nothing: an
unscoped session sees no row and can write none. Default deny.

**Per-command shape** (a model with a workspace column). Four policies, because one
``FOR ALL`` policy cannot hold the read/write asymmetry: Postgres applies ``WITH CHECK`` only
to the new row of an INSERT or UPDATE and never to DELETE, while ``USING`` picks the existing
rows an UPDATE or DELETE may touch. With a single policy the read predicate would govern those,
and a read grant on another workspace would let a session delete or relabel its rows.

  * ``SELECT``: tenant matches, and the workspace is one the session may read.
  * ``INSERT`` / ``UPDATE`` / ``DELETE``: tenant matches, and the workspace is the session's
    active one, on the row selected (``USING``) and on the row written (``WITH CHECK``).

**Single-key shape** (no workspace column). One policy scoping read and write on the tenant.

The rendering is idempotent: it drops its own policy names first (and, with
``drop_other_shape``, the other shape's), so it can be re-applied to change a table's policy.
"""

from __future__ import annotations

from .model import GucBypass, RoleBypass, TenancyModel, check_identifier

__all__ = ["policy_sql", "policy_statements"]

_COMMANDS = ("select", "insert", "update", "delete")
#: The longest suffix a policy name gets, so the table name leaves room for it.
_LONGEST_SUFFIX = len("_isolation")


def _bypass_predicate(model: TenancyModel) -> str | None:
    bypass = model.bypass
    if isinstance(bypass, GucBypass):
        return f"current_setting('{model.setting('bypass')}', true) = '{bypass.value}'"
    if isinstance(bypass, RoleBypass):
        return f"pg_has_role(current_user, '{bypass.role}', 'MEMBER')"
    return None


def policy_sql(model: TenancyModel, table: str) -> str:
    """The policy DDL for ``table`` under ``model``, as one string of ``;``-separated
    statements. Use :func:`policy_statements` for a driver that runs one statement at a time.
    """
    check_identifier(table, "table")
    if len(table) + _LONGEST_SUFFIX > 63:
        raise ValueError("table name is too long to suffix its policy names within 63 bytes")
    tenant = f"{model.tenant_column} = current_setting('{model.setting('tenant')}', true)"
    head = [
        f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;",
        f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;",
    ]
    if model.workspace_column is None:
        drops = [f"DROP POLICY IF EXISTS {table}_isolation ON {table};"]
        if model.drop_other_shape:
            drops += [f"DROP POLICY IF EXISTS {table}_{cmd} ON {table};" for cmd in _COMMANDS]
        return "\n".join(
            [
                *head,
                *drops,
                f"CREATE POLICY {table}_isolation ON {table}",
                f"  USING ({tenant})",
                f"  WITH CHECK ({tenant});",
            ]
        )

    ws = model.workspace_column
    readable = (
        f"{ws} = ANY (string_to_array(current_setting('{model.setting('readable')}', true), ','))"
    )
    active = f"{ws} = current_setting('{model.setting('workspace')}', true)"
    bypass = _bypass_predicate(model)
    read_ws = f"({readable} OR {bypass})" if bypass else f"({readable})"
    write_ws = f"({active} OR {bypass})" if bypass else f"({active})"
    read = f"{tenant} AND {read_ws}"
    write = f"{tenant} AND {write_ws}"
    drops = (
        [f"DROP POLICY IF EXISTS {table}_isolation ON {table};"] if model.drop_other_shape else []
    )
    drops += [f"DROP POLICY IF EXISTS {table}_{cmd} ON {table};" for cmd in _COMMANDS]
    return "\n".join(
        [
            *head,
            *drops,
            f"CREATE POLICY {table}_select ON {table}",
            "  FOR SELECT",
            f"  USING ({read});",
            f"CREATE POLICY {table}_insert ON {table}",
            "  FOR INSERT",
            f"  WITH CHECK ({write});",
            f"CREATE POLICY {table}_update ON {table}",
            "  FOR UPDATE",
            f"  USING ({write})",
            f"  WITH CHECK ({write});",
            f"CREATE POLICY {table}_delete ON {table}",
            "  FOR DELETE",
            f"  USING ({write});",
        ]
    )


def policy_statements(model: TenancyModel, table: str) -> list[str]:
    """:func:`policy_sql` split into single statements, without their trailing ``;``.

    No statement contains a ``;`` of its own, so the split is exact.
    """
    return [s.strip() for s in policy_sql(model, table).split(";") if s.strip()]
