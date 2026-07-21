"""Tests for runtime-trace ingestion and Granted vs. Used vs. Needed reconciliation."""

from __future__ import annotations

import json

from steward.findings import analyze_fleet
from steward.loaders import load_inventory, validate_inventory
from steward.traces import apply_usage, load_traces, reconcile


def _write_traces(tmp_path, lines):
    path = tmp_path / "traces.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_load_traces_aggregates_and_tolerates_malformed_lines(tmp_path) -> None:
    path = _write_traces(
        tmp_path,
        [
            json.dumps(
                {"timestamp": "2026-07-15T10:00:00Z", "agent_id": "a", "tool_id": "t"}
            ),
            json.dumps(
                {
                    "timestamp": "2026-07-14T09:00:00Z",
                    "agent_id": "a",
                    "tool_id": "t",
                    "status": "error",
                    # Payload-bearing fields must be ignored, never retained.
                    "arguments": {"query": "SELECT * FROM customers"},
                }
            ),
            "not json at all",
            json.dumps({"timestamp": "2026-07-15T10:00:00Z", "agent_id": "", "tool_id": "t"}),
            json.dumps({"timestamp": "2026-07-15T11:00:00Z", "agent_id": "b", "tool_id": "u"}),
        ],
    )
    log = load_traces(path)
    assert log.events_total == 5
    assert log.events_malformed == 2
    record = log.usage["a"]["t"]
    assert record.invocations == 2
    assert record.error_invocations == 1
    assert record.first_seen == "2026-07-14T09:00:00Z"
    assert record.last_seen == "2026-07-15T10:00:00Z"
    # The dropped payload never survives into the parsed structure.
    assert "SELECT" not in log.model_dump_json()


def test_apply_usage_only_marks_observed_agents(tmp_path) -> None:
    fleet, tools = load_inventory("data/fleet.json", "data/tools.json")
    path = _write_traces(
        tmp_path,
        [
            json.dumps(
                {
                    "timestamp": "2026-07-15T10:00:00Z",
                    "agent_id": "report_bot",
                    "tool_id": "read_db",
                }
            ),
            # A known agent invoking a tool the catalog has never heard of:
            # it cannot enter the usage log (inventory validation would fail)
            # and must surface through reconcile instead.
            json.dumps(
                {
                    "timestamp": "2026-07-15T10:01:00Z",
                    "agent_id": "report_bot",
                    "tool_id": "mystery_tool",
                }
            ),
        ],
    )
    log = load_traces(path)
    updated = apply_usage(fleet, log, tools)
    validate_inventory(updated, tools)
    report_bot = updated.agent_by_id("report_bot")
    assert report_bot.usage_log == ["read_db"]
    assert report_bot.usage_log_available is True
    # Unobserved agents keep their inventory usage untouched.
    support_bot = updated.agent_by_id("support_bot")
    assert support_bot.usage_log == fleet.agent_by_id("support_bot").usage_log


def test_reconcile_reports_all_three_runtime_signals() -> None:
    fleet, tools = load_inventory("data/fleet.json", "data/tools.json")
    log = load_traces("examples/traces.jsonl")
    result = analyze_fleet(apply_usage(fleet, log, tools), tools)
    # Simulate the optional model tier having concluded scheduler_bot's
    # declared purpose does not require create_calendar_event.
    result.granted_vs_needed_gaps = {"scheduler_bot": ["create_calendar_event"]}
    reconciliation = reconcile(result, log)

    assert reconciliation.drift_detected
    by_agent = {entry.agent_id: entry for entry in reconciliation.agents}
    # Used but not granted: scheduler_bot invoked export_data.
    assert by_agent["scheduler_bot"].used_not_granted == ["export_data"]
    # Granted but never used, from observed runtime data.
    assert by_agent["report_bot"].granted_never_used == ["delete_records", "export_data"]
    # Used but not needed (model-assisted review signal).
    assert by_agent["scheduler_bot"].used_not_needed == ["create_calendar_event"]
    assert by_agent["scheduler_bot"].needed_inference_available is True
    assert by_agent["report_bot"].needed_inference_available is False
    # Unknown identities and unknown tools stay visible instead of vanishing.
    assert reconciliation.unrecognized_agent_ids == ["retired_bot"]
    assert reconciliation.unrecognized_tool_ids == {"support_bot": ["legacy_crm_export"]}


def test_traced_usage_drives_the_over_privilege_check(tmp_path) -> None:
    """An agent whose trace shows no use of a high-risk grant gets flagged."""

    fleet, tools = load_inventory("data/fleet.json", "data/tools.json")
    # marketing_bot is a clean control in the inventory; a trace window where
    # it only reads analytics leaves its other grant visibly unused.
    marketing = fleet.agent_by_id("marketing_bot")
    assert len(marketing.granted_tools) >= 2
    used = marketing.granted_tools[0]
    path = _write_traces(
        tmp_path,
        [
            json.dumps(
                {"timestamp": "2026-07-15T10:00:00Z", "agent_id": "marketing_bot", "tool_id": used}
            )
        ],
    )
    result = analyze_fleet(apply_usage(fleet, load_traces(path), tools), tools)
    over_privilege = [
        finding
        for finding in result.findings
        if finding.check_type == "over_privilege" and finding.agent_id == "marketing_bot"
    ]
    assert len(over_privilege) == 1
