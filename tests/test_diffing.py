"""Tests for the deterministic access-diff / change-review feature (R1)."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from steward.cli import app
from steward.diffing import diff_fleets, introduced_findings_at_or_above
from steward.models import Fleet, ToolCatalog

runner = CliRunner()


def _tools() -> ToolCatalog:
    return ToolCatalog.model_validate(
        {
            "tools": [
                {"id": "create_vendor", "name": "Create vendor"},
                {"id": "approve_payment", "name": "Approve payment"},
                {"id": "run_payroll", "name": "Run payroll"},
                {"id": "read_calendar", "name": "Read calendar"},
                {"id": "web_search", "name": "Web search"},
            ]
        }
    )


def _fleet(agents: list[dict]) -> Fleet:
    return Fleet.model_validate({"agents": agents})


def _clean_agent(agent_id: str, owner: str = "Owner") -> dict:
    return {
        "id": agent_id,
        "name": agent_id.title(),
        "owner": owner,
        "granted_tools": ["read_calendar"],
        "usage_log": ["read_calendar"],
    }


def test_identical_snapshots_have_no_changes() -> None:
    fleet = _fleet([_clean_agent("a"), _clean_agent("b")])
    tools = _tools()
    diff = diff_fleets(fleet, tools, fleet, tools)
    assert not diff.has_changes
    assert diff.agents_added == []
    assert diff.agents_removed == []
    assert diff.agent_deltas == []
    assert diff.findings_introduced == []
    assert diff.findings_resolved == []
    assert diff.fleet_risk_delta == 0


def test_agent_added_and_removed() -> None:
    before = _fleet([_clean_agent("a"), _clean_agent("b")])
    after = _fleet([_clean_agent("a"), _clean_agent("c")])
    tools = _tools()
    diff = diff_fleets(before, tools, after, tools)
    assert diff.agents_added == ["c"]
    assert diff.agents_removed == ["b"]
    assert diff.has_changes


def test_owner_change_detected() -> None:
    before = _fleet([_clean_agent("a", owner="Alice")])
    after = _fleet([_clean_agent("a", owner="Bob")])
    tools = _tools()
    diff = diff_fleets(before, tools, after, tools)
    assert len(diff.agent_deltas) == 1
    delta = diff.agent_deltas[0]
    assert delta.owner_before == "Alice"
    assert delta.owner_after == "Bob"
    assert delta.owner_changed


def test_grant_and_delegation_deltas() -> None:
    before = _fleet(
        [
            {
                "id": "a",
                "name": "A",
                "owner": "Owner",
                "granted_tools": ["read_calendar"],
                "can_delegate_to": [],
                "usage_log": ["read_calendar"],
            },
            _clean_agent("b"),
        ]
    )
    after = _fleet(
        [
            {
                "id": "a",
                "name": "A",
                "owner": "Owner",
                "granted_tools": ["read_calendar", "run_payroll"],
                "can_delegate_to": ["b"],
                "usage_log": ["read_calendar", "run_payroll"],
            },
            _clean_agent("b"),
        ]
    )
    tools = _tools()
    diff = diff_fleets(before, tools, after, tools)
    delta = next(d for d in diff.agent_deltas if d.agent_id == "a")
    assert delta.granted_added == ["run_payroll"]
    assert delta.granted_removed == []
    assert delta.delegation_edges_added == ["a->b"]
    assert delta.delegation_edges_removed == []


def test_effective_access_expansion_flags_high_impact() -> None:
    # `a` gains payment-approval reach only by delegating to `b`.
    before = _fleet(
        [
            _clean_agent("a"),
            {
                "id": "b",
                "name": "B",
                "owner": "Finance",
                "granted_tools": ["approve_payment"],
                "usage_log": ["approve_payment"],
            },
        ]
    )
    after = _fleet(
        [
            {
                "id": "a",
                "name": "A",
                "owner": "Owner",
                "granted_tools": ["read_calendar"],
                "can_delegate_to": ["b"],
                "usage_log": ["read_calendar"],
            },
            {
                "id": "b",
                "name": "B",
                "owner": "Finance",
                "granted_tools": ["approve_payment"],
                "usage_log": ["approve_payment"],
            },
        ]
    )
    tools = _tools()
    diff = diff_fleets(before, tools, after, tools)
    delta = next(d for d in diff.agent_deltas if d.agent_id == "a")
    assert "approve_payment" in delta.effective_added
    assert delta.new_high_impact_access == ["approve_payment"]
    # The delegated payment-approval blast radius is a newly introduced finding.
    assert any(
        f.agent_id == "a" and f.check_type == "escalation" for f in diff.findings_introduced
    )


def _sod_agent(agent_id: str, grants: list[str]) -> dict:
    return {
        "id": agent_id,
        "name": agent_id.title(),
        "owner": "Finance",
        "granted_tools": grants,
        "usage_log": grants,
    }


def test_findings_introduced_resolved_persisting() -> None:
    before = _fleet(
        [
            _sod_agent("persist_bot", ["create_vendor", "approve_payment"]),
            _sod_agent("intro_bot", ["create_vendor"]),
            _sod_agent("resolve_bot", ["create_vendor", "approve_payment"]),
        ]
    )
    after = _fleet(
        [
            _sod_agent("persist_bot", ["create_vendor", "approve_payment"]),
            _sod_agent("intro_bot", ["create_vendor", "approve_payment"]),
            _sod_agent("resolve_bot", ["create_vendor"]),
        ]
    )
    tools = _tools()
    diff = diff_fleets(before, tools, after, tools)

    introduced = {(f.agent_id, f.check_type) for f in diff.findings_introduced}
    resolved = {(f.agent_id, f.check_type) for f in diff.findings_resolved}
    persisting = {(f.agent_id, f.check_type) for f in diff.findings_persisting}
    assert ("intro_bot", "sod") in introduced
    assert ("resolve_bot", "sod") in resolved
    assert ("persist_bot", "sod") in persisting
    # A persisting finding records its prior score so a reviewer can see drift.
    persist = next(f for f in diff.findings_persisting if f.agent_id == "persist_bot")
    assert persist.risk_score_before is not None
    assert persist.risk_score_delta == 0


def test_determinism() -> None:
    before = _fleet([_sod_agent("a", ["create_vendor"]), _clean_agent("b")])
    after = _fleet([_sod_agent("a", ["create_vendor", "approve_payment"])])
    tools = _tools()
    first = diff_fleets(before, tools, after, tools).model_dump(mode="json")
    second = diff_fleets(before, tools, after, tools).model_dump(mode="json")
    assert first == second


def test_introduced_findings_at_or_above_threshold() -> None:
    before = _fleet([_sod_agent("a", ["create_vendor"])])
    after = _fleet([_sod_agent("a", ["create_vendor", "approve_payment"])])
    tools = _tools()
    diff = diff_fleets(before, tools, after, tools)
    assert introduced_findings_at_or_above(diff, "critical")  # SoD is critical
    # Nothing above 'critical' means the same set; a clean before/after is empty.
    empty = diff_fleets(after, tools, after, tools)
    assert introduced_findings_at_or_above(empty, "low") == []


# --- CLI gating -----------------------------------------------------------


def _write_inventory(tmp_path, name: str, agents: list[dict]) -> str:
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps({"agents": agents}), encoding="utf-8")
    return str(path)


def _write_tools(tmp_path) -> str:
    path = tmp_path / "tools.json"
    path.write_text(_tools().model_dump_json(), encoding="utf-8")
    return str(path)


def test_cli_fail_on_new_fires_on_introduced_critical(tmp_path, cli_text) -> None:
    tools = _write_tools(tmp_path)
    before = _write_inventory(tmp_path, "before", [_sod_agent("a", ["create_vendor"])])
    after = _write_inventory(
        tmp_path, "after", [_sod_agent("a", ["create_vendor", "approve_payment"])]
    )
    result = runner.invoke(
        app,
        [
            "diff",
            "--before-fleet",
            before,
            "--after-fleet",
            after,
            "--before-tools",
            tools,
            "--after-tools",
            tools,
            "--fail-on-new",
            "critical",
        ],
    )
    assert result.exit_code == 1
    assert "GATE FAILED" in cli_text(result)


def test_cli_fail_on_new_ignores_persisting_critical(tmp_path, cli_text) -> None:
    tools = _write_tools(tmp_path)
    # The critical SoD already exists in the before snapshot, so it is NOT new.
    both = [_sod_agent("a", ["create_vendor", "approve_payment"])]
    before = _write_inventory(tmp_path, "before", both)
    after = _write_inventory(tmp_path, "after", both)
    result = runner.invoke(
        app,
        [
            "diff",
            "--before-fleet",
            before,
            "--after-fleet",
            after,
            "--before-tools",
            tools,
            "--after-tools",
            tools,
            "--fail-on-new",
            "critical",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "GATE FAILED" not in cli_text(result)


def test_cli_rejects_bad_severity(tmp_path, cli_text) -> None:
    tools = _write_tools(tmp_path)
    fleet = _write_inventory(tmp_path, "f", [_clean_agent("a")])
    result = runner.invoke(
        app,
        [
            "diff",
            "--before-fleet",
            fleet,
            "--after-fleet",
            fleet,
            "--before-tools",
            tools,
            "--after-tools",
            tools,
            "--fail-on-new",
            "spicy",
        ],
    )
    assert result.exit_code != 0
    assert "critical, high, medium, low" in cli_text(result)


def test_cli_writes_json_and_markdown(tmp_path) -> None:
    tools = _write_tools(tmp_path)
    before = _write_inventory(tmp_path, "before", [_sod_agent("a", ["create_vendor"])])
    after = _write_inventory(
        tmp_path, "after", [_sod_agent("a", ["create_vendor", "approve_payment"])]
    )
    json_out = tmp_path / "diff.json"
    md_out = tmp_path / "diff.md"
    result = runner.invoke(
        app,
        [
            "diff",
            "--before-fleet",
            before,
            "--after-fleet",
            after,
            "--before-tools",
            tools,
            "--after-tools",
            tools,
            "--json",
            str(json_out),
            "--markdown",
            str(md_out),
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert payload["findings_introduced"]
    assert "# Steward access change review" in md_out.read_text(encoding="utf-8")
