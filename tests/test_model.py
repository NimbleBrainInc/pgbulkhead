"""TenancyModel: names are validated, settings derived, and bypasses kept off the tenant wall."""

from __future__ import annotations

import pytest

from pgbulkhead import GucBypass, RoleBypass, TenancyModel


def test_settings_derive_from_the_namespace_and_columns() -> None:
    model = TenancyModel(tenant_column="org", workspace_column="team", namespace="acme")
    assert model.setting("tenant") == "acme.org"
    assert model.setting("workspace") == "acme.team"
    assert model.setting("readable") == "acme.allowed_workspaces"
    with pytest.raises(KeyError):
        model.setting("bypass")


def test_settings_can_be_named_explicitly() -> None:
    model = TenancyModel(
        tenant_setting="x.t",
        workspace_setting="x.w",
        readable_setting="x.r",
        scopes_setting="x.s",
        bypass=GucBypass(setting="x.priv", value="reconciler"),
    )
    assert [model.setting(n) for n in ("tenant", "workspace", "readable", "scopes", "bypass")] == [
        "x.t",
        "x.w",
        "x.r",
        "x.s",
        "x.priv",
    ]


def test_the_bypass_is_off_unless_set() -> None:
    assert TenancyModel().bypass is None


@pytest.mark.parametrize(
    "kwargs",
    [
        {"tenant_column": "Tenant"},
        {"tenant_column": "tenant id"},
        {"tenant_column": "public.tenant_id"},
        {"tenant_column": "x" * 64},
        {"workspace_column": "tenant_id"},
        {"namespace": "my-app"},
        {"tenant_setting": "no_dot"},
        {"tenant_setting": "a.b'; DROP TABLE x; --"},
        {"workspace_column": None, "workspace_setting": "x.w"},
        {"workspace_column": None, "bypass": GucBypass()},
        {"workspace_column": None, "bypass": RoleBypass("admin")},
        {"tenant_setting": "x.shared", "workspace_setting": "x.shared"},
        {"workspace_setting": "pgbulkhead.tenant_id"},
        {"readable_setting": "pgbulkhead.workspace_id"},
        {"scopes_setting": "pgbulkhead.allowed_workspaces"},
        {"bypass": GucBypass(setting="pgbulkhead.tenant_id")},
        {"workspace_column": None, "scopes_setting": "pgbulkhead.tenant_id"},
    ],
)
def test_unsafe_or_incoherent_models_are_refused(kwargs: dict) -> None:
    with pytest.raises(ValueError):
        TenancyModel(**kwargs)


@pytest.mark.parametrize(
    "build",
    [lambda: GucBypass(value="it's"), lambda: GucBypass(setting="x"), lambda: RoleBypass("A b")],
)
def test_bypass_names_are_validated(build) -> None:
    with pytest.raises(ValueError):
        build()
