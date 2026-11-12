"""The rendered policies encode the invariants the guarantee rests on."""

from __future__ import annotations

import pytest

from pgbulkhead import GucBypass, RoleBypass, TenancyModel, policy_sql, policy_statements

MODEL = TenancyModel(namespace="app")
TENANT = "tenant_id = current_setting('app.tenant_id', true)"


def _policy(sql: str, name: str) -> str:
    """The ``CREATE POLICY <name>`` block, up to the next one."""
    start = sql.index(f"CREATE POLICY {name} ")
    end = sql.find("CREATE POLICY ", start + 1)
    return sql[start:] if end == -1 else sql[start:end]


def test_rls_is_enabled_and_forced() -> None:
    for model in (MODEL, TenancyModel(workspace_column=None)):
        sql = policy_sql(model, "notes")
        assert "ALTER TABLE notes ENABLE ROW LEVEL SECURITY;" in sql
        assert "ALTER TABLE notes FORCE ROW LEVEL SECURITY;" in sql


def test_per_command_policies_with_the_tenant_on_every_clause() -> None:
    sql = policy_sql(MODEL, "notes")
    for cmd in ("SELECT", "INSERT", "UPDATE", "DELETE"):
        assert f"FOR {cmd}" in sql
    assert "FOR ALL" not in sql
    # SELECT USING, INSERT CHECK, UPDATE USING + CHECK, DELETE USING.
    assert sql.count(f"{TENANT} AND") == 5
    assert "USING" in _policy(sql, "notes_delete")


def test_reads_span_the_readable_set_and_writes_bind_the_active_workspace() -> None:
    sql = policy_sql(MODEL, "notes")
    assert "app.allowed_workspaces" in _policy(sql, "notes_select")
    for cmd in ("insert", "update", "delete"):
        stmt = _policy(sql, f"notes_{cmd}")
        assert "current_setting('app.workspace_id', true)" in stmt
        assert "app.allowed_workspaces" not in stmt


def test_without_a_bypass_nothing_escapes_the_workspace() -> None:
    sql = policy_sql(MODEL, "notes")
    assert " OR " not in sql
    assert "role" not in sql


@pytest.mark.parametrize(
    ("bypass", "predicate"),
    [
        (GucBypass(), "current_setting('app.role', true) = 'system'"),
        (RoleBypass("reconciler"), "pg_has_role(current_user, 'reconciler', 'MEMBER')"),
    ],
)
def test_a_bypass_widens_the_workspace_predicate_only(bypass, predicate: str) -> None:
    sql = policy_sql(TenancyModel(namespace="app", bypass=bypass), "notes")
    assert sql.count(f"OR {predicate})") == 5
    # The tenant predicate stands alone in front of every bypass.
    assert sql.count(f"{TENANT} AND (") == 5
    assert f"{predicate} OR" not in sql


def test_single_key_scopes_read_and_write_on_the_tenant() -> None:
    sql = policy_sql(TenancyModel(workspace_column=None, namespace="app"), "ledger")
    assert f"USING ({TENANT})" in sql
    assert f"WITH CHECK ({TENANT})" in sql
    assert "workspace" not in sql


def test_reapplying_drops_both_shapes_by_default() -> None:
    for model in (MODEL, TenancyModel(workspace_column=None)):
        sql = policy_sql(model, "notes")
        for suffix in ("isolation", "select", "insert", "update", "delete"):
            assert f"DROP POLICY IF EXISTS notes_{suffix} ON notes;" in sql
    narrow = TenancyModel(workspace_column=None, drop_other_shape=False)
    assert policy_sql(narrow, "notes").count("DROP POLICY") == 1
    narrow_ws = TenancyModel(drop_other_shape=False)
    assert "notes_isolation" not in policy_sql(narrow_ws, "notes")


@pytest.mark.parametrize("table", ["Notes", "public.notes", "notes; DROP TABLE x", "x" * 54])
def test_unsafe_table_names_are_refused(table: str) -> None:
    with pytest.raises(ValueError):
        policy_sql(MODEL, table)


def test_statements_split_exactly() -> None:
    statements = policy_statements(MODEL, "notes")
    assert len(statements) == 2 + 5 + 4
    assert all(";" not in s for s in statements)
    assert ";\n".join(statements) + ";" == policy_sql(MODEL, "notes")
