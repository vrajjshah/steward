"""Tests for remediation simulation and the greedy revocation planner (R2)."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from steward.cli import app
from steward.findings import analyze_fleet
from steward.models import Fleet, ToolCatalog
from steward.remediation import (
    RemediationError,
    Revocation,
    apply_revocations,
    build_plan,
    simulate,
    validate_targets,
)

runner = CliRunner()


def _tools() -> ToolCatalog:
    return ToolCatalog.model_validate(
        {
            "tools": [
                {"id": "create_vendor", "name": "Create vendor"},
                {"id": "approve_payment", "name": "Approve payment"},
                {"id": "export_data", "name": "Export data"},
                {"id": "read_customer_pii", "name": "Read PII"},
                {"id": "send_external_email", "name": "Send email"},
                {"id": "read_calendar", "name": "Read calendar"},
            ]
        }
    )


def _fleet(agents: list[dict]) -> Fleet:
    return Fleet.model_validate({"agents": agents})


def _keys(fleet: Fleet, tools: ToolCatalog) -> set[tuple]:
    return {
        (f.check_type, f.agent_id, f.rule_id) for f in analyze_fleet(fleet, tools).findings
    }


def test_simulate_matches_hand_mutated_reanalysis() -> None:
    tools = _tools()
    fleet = _fleet(
        [
            {
                "id": "fin",
                "name": "Fin",
                "owner": "Finance",
                "granted_tools": ["create_vendor", "approve_payment"],
                "usage_log": ["create_vendor", "approve_payment"],
            }
        ]
    )
    hand_mutated = _fleet(
        [
            {
                "id": "fin",
                "name": "Fin",
                "owner": "Finance",
                "granted_tools": ["create_vendor"],
                "usage_log": ["create_vendor"],
            }
        ]
    )
    applied = apply_revocations(fleet, [Revocation("grant", "fin", "approve_payment")])
    # Simulating a revocation is exactly re-analyzing a hand-mutated fleet.
    assert _keys(applied, tools) == _keys(hand_mutated, tools)

    diff = simulate(fleet, tools, [Revocation("grant", "fin", "approve_payment")])
    assert any(f.check_type == "sod" and f.agent_id == "fin" for f in diff.findings_resolved)


def test_apply_revocations_does_not_mutate_input() -> None:
    tools = _tools()
    fleet = _fleet(
        [
            {
                "id": "fin",
                "name": "Fin",
                "owner": "Finance",
                "granted_tools": ["create_vendor", "approve_payment"],
                "can_delegate_to": [],
                "usage_log": ["create_vendor", "approve_payment"],
            }
        ]
    )
    apply_revocations(fleet, [Revocation("grant", "fin", "approve_payment")])
    # Original is untouched (nothing mutates on disk or in memory).
    assert fleet.agent_by_id("fin").granted_tools == ["create_vendor", "approve_payment"]
    assert tools  # unused-guard


def test_plan_applied_via_simulate_clears_claimed_findings() -> None:
    tools = _tools()
    fleet = _fleet(
        [
            {
                "id": "fin",
                "name": "Fin",
                "owner": "Finance",
                "granted_tools": ["create_vendor", "approve_payment"],
                "usage_log": ["create_vendor", "approve_payment"],
            },
            {
                "id": "sup",
                "name": "Sup",
                "owner": "Support",
                "granted_tools": ["read_customer_pii", "send_external_email"],
                "usage_log": ["read_customer_pii", "send_external_email"],
            },
            {
                "id": "ghost",
                "name": "Ghost",
                "granted_tools": ["read_calendar"],
                "usage_log": ["read_calendar"],
            },
        ]
    )
    plan = build_plan(fleet, tools)
    revocations = [
        Revocation(step.kind, step.subject, step.object) for step in plan.steps
    ]
    diff = simulate(fleet, tools, revocations)
    # Applying the whole plan resolves exactly the number of findings it claims.
    assert len(diff.findings_resolved) == plan.findings_cleared
    # The orphan (ownerless 'ghost') is not fixable by revocation and remains.
    assert plan.findings_remaining >= 1
    assert any("Ownerless" in title for title in plan.remaining_finding_titles)


def test_plan_prefers_unused_zero_impact_grant() -> None:
    # Agent P can clear its SoD by revoking either create_vendor (used) or
    # approve_payment (unused). Both clear exactly one finding; the plan takes
    # the unused, zero-business-impact grant.
    tools = _tools()
    fleet = _fleet(
        [
            {
                "id": "p",
                "name": "P",
                "owner": "Finance",
                "granted_tools": ["create_vendor", "approve_payment", "export_data"],
                "usage_log": ["create_vendor"],
            }
        ]
    )
    plan = build_plan(fleet, tools)
    revoked = {(step.subject, step.object) for step in plan.steps}
    # The used grant is never revoked; the unused one is.
    assert ("p", "create_vendor") not in revoked
    assert ("p", "approve_payment") in revoked
    sod_step = next(s for s in plan.steps if s.object == "approve_payment")
    assert sod_step.grant_observed_in_use is False


def test_plan_and_simulate_are_deterministic() -> None:
    tools = _tools()
    fleet = _fleet(
        [
            {
                "id": "fin",
                "name": "Fin",
                "owner": "Finance",
                "granted_tools": ["create_vendor", "approve_payment"],
                "usage_log": ["create_vendor"],
            }
        ]
    )
    assert build_plan(fleet, tools).model_dump() == build_plan(fleet, tools).model_dump()
    revs = [Revocation("grant", "fin", "approve_payment")]
    assert (
        simulate(fleet, tools, revs).model_dump()
        == simulate(fleet, tools, revs).model_dump()
    )


def test_validate_targets_rejects_bad_specs() -> None:
    tools = _tools()  # noqa: F841 - documents the catalog under test
    fleet = _fleet(
        [
            {
                "id": "a",
                "name": "A",
                "owner": "Owner",
                "granted_tools": ["create_vendor"],
                "can_delegate_to": [],
                "usage_log": ["create_vendor"],
            }
        ]
    )
    with pytest.raises(RemediationError, match="unknown agent"):
        validate_targets(fleet, [Revocation("grant", "nope", "create_vendor")])
    with pytest.raises(RemediationError, match="no direct grant"):
        validate_targets(fleet, [Revocation("grant", "a", "approve_payment")])
    with pytest.raises(RemediationError, match="does not delegate"):
        validate_targets(fleet, [Revocation("delegation", "a", "b")])


def test_revocation_spec_parsing() -> None:
    assert Revocation.parse_grant("a:t") == Revocation("grant", "a", "t")
    assert Revocation.parse_edge("a->b") == Revocation("delegation", "a", "b")
    with pytest.raises(RemediationError):
        Revocation.parse_grant("no-colon")
    with pytest.raises(RemediationError):
        Revocation.parse_edge("no-arrow")


def test_cli_simulate_requires_a_target(cli_text) -> None:
    result = runner.invoke(app, ["simulate"])
    assert result.exit_code != 0
    assert "at least one --revoke" in cli_text(result)


def test_cli_remediate_runs_on_shipped_fleet(cli_text) -> None:
    result = runner.invoke(app, ["remediate"])
    assert result.exit_code == 0, result.output
    assert "Remediation proposal" in cli_text(result)
    assert "PROPOSAL for human review" in cli_text(result)
