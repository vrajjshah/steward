"""Tests for the CI gating flags on `steward analyze`."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from steward.cli import app

runner = CliRunner()


def _clean_inventory(tmp_path):
    fleet = tmp_path / "fleet.json"
    tools = tmp_path / "tools.json"
    tools.write_text(
        json.dumps(
            {"tools": [{"id": "read_calendar", "name": "Read calendar", "description": "Reads."}]}
        ),
        encoding="utf-8",
    )
    fleet.write_text(
        json.dumps(
            {
                "agents": [
                    {
                        "id": "clean_bot",
                        "name": "CleanBot",
                        "owner": "Fixture Owner",
                        "description": "Reads calendars.",
                        "granted_tools": ["read_calendar"],
                        "can_delegate_to": [],
                        "usage_log": ["read_calendar"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return fleet, tools


def test_fail_on_exits_nonzero_when_findings_meet_the_threshold(tmp_path) -> None:
    result = runner.invoke(
        app,
        [
            "analyze",
            "--no-llm",
            "--fail-on",
            "critical",
            "--state-dir",
            str(tmp_path / "state"),
        ],
    )
    # The synthetic fleet plants critical findings, so the gate must fail —
    # after the findings have been printed for the human reading the CI log.
    assert result.exit_code == 1
    assert "GATE FAILED" in result.output
    assert "cited findings" in result.output


def test_fail_on_exits_zero_for_a_clean_fleet(tmp_path) -> None:
    fleet, tools = _clean_inventory(tmp_path)
    result = runner.invoke(
        app,
        [
            "analyze",
            "--no-llm",
            "--fleet",
            str(fleet),
            "--tools",
            str(tools),
            "--fail-on",
            "low",
            "--state-dir",
            str(tmp_path / "state"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "GATE FAILED" not in result.output


def test_fail_on_rejects_unknown_severity(tmp_path) -> None:
    result = runner.invoke(
        app,
        ["analyze", "--no-llm", "--fail-on", "spicy", "--state-dir", str(tmp_path / "state")],
    )
    assert result.exit_code != 0
    assert "critical, high, medium, low" in result.output


def test_fail_on_drift_requires_traces(tmp_path) -> None:
    result = runner.invoke(
        app,
        ["analyze", "--no-llm", "--fail-on-drift", "--state-dir", str(tmp_path / "state")],
    )
    assert result.exit_code != 0
    assert "--traces" in result.output


def test_fail_on_drift_exits_nonzero_on_reconciliation_drift(tmp_path) -> None:
    result = runner.invoke(
        app,
        [
            "analyze",
            "--no-llm",
            "--traces",
            "examples/traces.jsonl",
            "--fail-on-drift",
            "--state-dir",
            str(tmp_path / "state"),
        ],
    )
    # The sample trace deliberately contains used-but-not-granted drift.
    assert result.exit_code == 1
    assert "runtime drift detected" in result.output
