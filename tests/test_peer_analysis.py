"""Tests for peer-group outlier analytics (R5)."""

from __future__ import annotations

from pathlib import Path

from steward.findings import analyze_fleet
from steward.loaders import load_inventory
from steward.peer_analysis import analyze_peer_groups, jaccard
from steward.reporting import build_fleet_audit_report, render_markdown_report

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_jaccard() -> None:
    assert jaccard({"a", "b"}, {"a", "b"}) == 1.0
    assert jaccard({"a"}, {"b"}) == 0.0
    assert jaccard(set(), set()) == 0.0
    assert jaccard({"a", "b"}, {"a"}) == 0.5


def _clustered_access() -> dict[str, list[str]]:
    cluster_a = ["read_calendar", "read_email", "send_email"]
    cluster_b = ["read_db", "write_db", "run_query"]
    outlier = ["approve_payment", "delete_records", "grant_access"]
    return {
        "a1": cluster_a,
        "a2": cluster_a,
        "a3": cluster_a,
        "b1": cluster_b,
        "b2": cluster_b,
        "b3": cluster_b,
        "x": outlier,
    }


def test_planted_outlier_is_flagged() -> None:
    analysis = analyze_peer_groups(_clustered_access())
    assert analysis.applicable
    outlier_ids = [o.agent_id for o in analysis.outliers]
    assert outlier_ids == ["x"]
    # Cluster members are never flagged (each has an identical twin).
    assert "a1" not in outlier_ids
    # The reason counts high-impact tools via capability_classes.
    outlier = analysis.outliers[0]
    assert outlier.high_impact_count == 3
    assert outlier.max_similarity == 0.0


def test_determinism() -> None:
    first = analyze_peer_groups(_clustered_access()).model_dump()
    second = analyze_peer_groups(_clustered_access()).model_dump()
    assert first == second


def test_small_fleet_is_not_applicable() -> None:
    for access in ({}, {"solo": ["a", "b", "c"]}, {"a": ["x"], "b": ["y"]}):
        analysis = analyze_peer_groups(access)
        assert analysis.applicable is False
        assert analysis.outliers == []


def test_agents_below_min_tools_are_ignored() -> None:
    # Five agents; the dissimilar one holds only two tools, below min_tools.
    access = {
        "a1": ["read_calendar", "read_email", "send_email"],
        "a2": ["read_calendar", "read_email", "send_email"],
        "a3": ["read_calendar", "read_email", "send_email"],
        "a4": ["read_calendar", "read_email", "send_email"],
        "tiny": ["obscure_a", "obscure_b"],
    }
    analysis = analyze_peer_groups(access)
    assert [o.agent_id for o in analysis.outliers] == []


def test_shipped_fleet_has_no_absurd_noise() -> None:
    # Pinned after eyeballing: the demo fleet yields exactly one sensible
    # outlier (a report bot holding delete + export unlike its peers).
    fleet, tools = load_inventory(
        PROJECT_ROOT / "data" / "fleet.json", PROJECT_ROOT / "data" / "tools.json"
    )
    result = analyze_fleet(fleet, tools)
    analysis = analyze_peer_groups(result.effective_access)
    assert analysis.applicable
    assert [o.agent_id for o in analysis.outliers] == ["report_bot"]


def test_report_includes_peer_analytics() -> None:
    fleet, tools = load_inventory(
        PROJECT_ROOT / "data" / "fleet.json", PROJECT_ROOT / "data" / "tools.json"
    )
    result = analyze_fleet(fleet, tools)
    report = build_fleet_audit_report(
        result.fleet, result.findings, effective_access=result.effective_access
    )
    assert report["peer_analytics"]["applicable"]
    assert report["executive_summary"]["peer_outliers"] == 1
    rendered = render_markdown_report(report)
    assert "## Peer-group outlier analytics" in rendered
    assert "report_bot" in rendered


def test_html_report_renders_the_peer_outlier_section() -> None:
    """The outlier must be visible on every report surface, not only Markdown.

    Regression guard: the section originally rendered in JSON and Markdown but
    no HTML template showed it, so a flagged outlier was invisible in the
    report a reviewer actually opens.
    """

    from fastapi.testclient import TestClient

    from steward.app import create_app
    from steward.web_service import StewardService

    client = TestClient(create_app(StewardService(demo_mode=True)))
    html = client.get("/api/report.html").text
    assert "Peer-group outliers" in html
    assert "/risk-cards/report_bot" in html
    assert "Heuristic, not a finding" in html


def test_report_without_effective_access_has_no_peer_section() -> None:
    fleet, tools = load_inventory(
        PROJECT_ROOT / "data" / "fleet.json", PROJECT_ROOT / "data" / "tools.json"
    )
    result = analyze_fleet(fleet, tools)
    report = build_fleet_audit_report(result.fleet, result.findings)
    assert report["peer_analytics"] is None
