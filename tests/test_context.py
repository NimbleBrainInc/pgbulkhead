"""SecurityContext from verified claims: fail closed, active workspace always readable."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from pgbulkhead import ClaimNames, SecurityContext, context_from_claims


def test_the_active_workspace_is_readable() -> None:
    ctx = context_from_claims({"tenant_id": "t1", "workspace_id": "w1"})
    assert ctx.allowed_workspaces == {"w1"}
    assert SecurityContext("t1", "w1").readable_workspaces() == {"w1"}


def test_read_grants_merge_with_the_active_workspace() -> None:
    ctx = context_from_claims(
        {"tenant_id": "t1", "workspace_id": "w1", "allowed_workspaces": ["w2", "w3"]}
    )
    assert ctx.allowed_workspaces == {"w1", "w2", "w3"}


@pytest.mark.parametrize(
    "claims",
    [
        {"workspace_id": "w1"},
        {"tenant_id": "t1"},
        {"tenant_id": "", "workspace_id": "w1"},
        {"tenant_id": ["t1"], "workspace_id": "w1"},
    ],
)
def test_missing_or_malformed_identity_fails_closed(claims: dict) -> None:
    with pytest.raises(ValueError):
        context_from_claims(claims)


def test_claim_names_are_configurable_and_workspace_optional() -> None:
    names = ClaimNames(tenant="org", workspace=None, scopes="scp")
    ctx = context_from_claims({"org": "o1", "scp": ["read"], "workspace_id": "ignored"}, names)
    assert (ctx.tenant_id, ctx.workspace_id, ctx.scopes) == ("o1", None, {"read"})
    with pytest.raises(ValueError, match="verified org claim"):
        context_from_claims({}, names)


def test_a_subclass_can_be_built() -> None:
    @dataclass(frozen=True, slots=True)
    class Mine(SecurityContext):
        pass

    assert type(context_from_claims({"tenant_id": "t", "workspace_id": "w"}, cls=Mine)) is Mine


def test_require_scope() -> None:
    ctx = SecurityContext("t1", "w1", scopes=frozenset({"notes:read"}))
    ctx.require_scope("notes:read")
    with pytest.raises(PermissionError):
        ctx.require_scope("notes:write")


def test_check_context_refuses_values_a_list_binding_would_split() -> None:
    from pgbulkhead import TenancyModel, check_context

    with_scopes = TenancyModel(scopes_setting="app.scopes")
    check_context(with_scopes, SecurityContext("t", "w", scopes=frozenset({"notes:read"})))
    for scopes in ({"read,admin"}, {""}):
        with pytest.raises(ValueError, match="comma"):
            check_context(with_scopes, SecurityContext("t", "w", scopes=frozenset(scopes)))
    # Scopes are only checked when the model binds them.
    check_context(TenancyModel(), SecurityContext("t", "w", scopes=frozenset({"a,b"})))


def test_scopes_read_from_an_oauth_space_separated_string() -> None:
    claims = {"tenant_id": "t", "workspace_id": "w", "scopes": "notes:read  notes:write"}
    assert context_from_claims(claims).scopes == frozenset({"notes:read", "notes:write"})


def test_allowed_workspaces_given_as_a_string_grant_nothing() -> None:
    """Only scopes take the OAuth string form; a string where a list of grants belongs is not
    split into grants."""
    claims = {"tenant_id": "t", "workspace_id": "w", "allowed_workspaces": "w2 w3"}
    assert context_from_claims(claims).allowed_workspaces == frozenset({"w"})
