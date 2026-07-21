"""Tests for the deterministic control-framework mapping (auditor context)."""

from __future__ import annotations

from steward.control_mapping import (
    annotate_findings_with_control_frameworks,
    control_framework_coverage,
)
from steward.findings import analyze_fleet
from steward.loaders import load_inventory
from steward.reporting import build_fleet_audit_report, render_markdown_report


def _analyzed():
    fleet, tools = load_inventory("data/fleet.json", "data/tools.json")
    return analyze_fleet(fleet, tools)


def test_every_verified_finding_carries_versioned_framework_context() -> None:
    result = _analyzed()
    assert result.findings
    for finding in result.findings:
        assert finding.control_frameworks, finding.id
        frameworks = {reference.framework for reference in finding.control_frameworks}
        # Version strings are part of the data, not just prose.
        assert any("800-53 Rev. 5" in framework for framework in frameworks)

    by_check = {finding.check_type: finding for finding in result.findings}
    sod_ids = {ref.control_id for ref in by_check["sod"].control_frameworks}
    assert {"AC-5", "CC6.3", "Art. 14"} <= sod_ids
    assert {"AC-6 / AC-6(1)"} <= {
        ref.control_id for ref in by_check["over_privilege"].control_frameworks
    }
    assert {"AC-2", "CC6.2", "A.5.16"} <= {
        ref.control_id for ref in by_check["orphan"].control_frameworks
    }
    assert {"AC-6", "AC-5"} <= {
        ref.control_id for ref in by_check["escalation"].control_frameworks
    }


def test_annotation_is_idempotent() -> None:
    result = _analyzed()
    once = result.findings
    twice = annotate_findings_with_control_frameworks(once)
    assert [len(finding.control_frameworks) for finding in twice] == [
        len(finding.control_frameworks) for finding in once
    ]


def test_coverage_matrix_aggregates_by_framework_and_control() -> None:
    result = _analyzed()
    coverage = control_framework_coverage(result.findings)
    frameworks = {row["framework"] for row in coverage}
    assert "NIST SP 800-53 Rev. 5" in frameworks
    assert "EU AI Act (Regulation (EU) 2024/1689)" in frameworks
    nist = next(row for row in coverage if row["framework"] == "NIST SP 800-53 Rev. 5")
    ac5 = next(control for control in nist["controls"] if control["control_id"] == "AC-5")
    # AC-5 is touched by every SoD finding and every escalation finding.
    sod_and_escalation = sum(
        1 for finding in result.findings if finding.check_type in ("sod", "escalation")
    )
    assert ac5["findings"] == sod_and_escalation
    assert set(ac5["check_types"]) == {"sod", "escalation"}


def test_report_surfaces_framework_context_without_claiming_certification() -> None:
    result = _analyzed()
    report = build_fleet_audit_report(
        result.fleet,
        result.findings,
        tools=result.tools,
        effective_access=result.effective_access,
    )
    assert report["control_framework_coverage"]
    assert report["governance_process_controls"]
    assert any(
        item["control_id"] == "Art. 12" for item in report["governance_process_controls"]
    )
    for finding in report["findings"]:
        assert finding["control_frameworks"]

    markdown = render_markdown_report(report)
    assert "## Control-framework coverage" in markdown
    assert "not a compliance certification" in markdown
    assert "Art. 14" in markdown
