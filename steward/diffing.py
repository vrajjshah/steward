"""Deterministic access-diff between two fleet snapshots.

Change review is *the* recurring IGA artifact: given the access posture before
and after a change, what actually moved? This module answers that with pure
graph facts — agents added/removed, owner changes, direct-grant and delegation
deltas, effective-access expansions (highlighting newly reachable high-impact
capabilities), and the deterministic findings introduced, resolved, or still
persisting. It makes zero model calls, so two runs on the same inputs are
byte-identical.

Honest limitation: this is a *config-time snapshot* diff, not an event log. A
renamed agent (new id) reads as one removal plus one addition, because ids are
the only stable identity Steward has.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from .capability_classes import HIGH_IMPACT_TOOL_IDS
from .findings import RulePack, analyze_fleet
from .graph import delegation_edge_id
from .models import Finding, Fleet, ToolCatalog

FindingStatus = Literal["introduced", "resolved", "persisting"]

# A finding is "the same finding" across snapshots when its check type, subject
# agent, and rule all match. Severity or score may move; identity does not.
FindingKey = tuple[str, str, str | None]


class AgentDelta(BaseModel):
    """Per-agent change between two snapshots (only emitted when non-empty)."""

    agent_id: str
    name: str
    owner_before: str | None = None
    owner_after: str | None = None
    granted_added: list[str] = Field(default_factory=list)
    granted_removed: list[str] = Field(default_factory=list)
    delegation_edges_added: list[str] = Field(default_factory=list)
    delegation_edges_removed: list[str] = Field(default_factory=list)
    effective_added: list[str] = Field(default_factory=list)
    effective_removed: list[str] = Field(default_factory=list)
    # Newly reachable capabilities whose misuse has direct financial,
    # destructive, or privilege consequences — the deltas that matter most.
    new_high_impact_access: list[str] = Field(default_factory=list)
    top_risk_score_before: int = 0
    top_risk_score_after: int = 0
    top_risk_score_delta: int = 0

    @property
    def owner_changed(self) -> bool:
        return self.owner_before != self.owner_after


class FindingDelta(BaseModel):
    """One finding's lifecycle across the two snapshots."""

    check_type: str
    agent_id: str
    rule_id: str | None
    severity: str
    title: str
    status: FindingStatus
    # Current-side score: the after score for introduced/persisting findings,
    # the before score for a resolved one.
    risk_score: int | None = None
    # Only populated for persisting findings, where a score can move without
    # the finding appearing or disappearing.
    risk_score_before: int | None = None
    risk_score_delta: int | None = None


class FleetDiff(BaseModel):
    """The full deterministic delta between a before and an after snapshot."""

    before_label: str
    after_label: str
    agents_added: list[str] = Field(default_factory=list)
    agents_removed: list[str] = Field(default_factory=list)
    agent_deltas: list[AgentDelta] = Field(default_factory=list)
    findings_introduced: list[FindingDelta] = Field(default_factory=list)
    findings_resolved: list[FindingDelta] = Field(default_factory=list)
    findings_persisting: list[FindingDelta] = Field(default_factory=list)
    # Aggregate exposure = the sum of every finding's composite risk score.
    # Reported before/after so a reviewer sees whether a change reduced or
    # enlarged total risk, not just the finding count.
    fleet_risk_before: int = 0
    fleet_risk_after: int = 0
    fleet_risk_delta: int = 0

    @property
    def has_changes(self) -> bool:
        return bool(
            self.agents_added
            or self.agents_removed
            or self.agent_deltas
            or self.findings_introduced
            or self.findings_resolved
        )


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _finding_key(finding: Finding) -> FindingKey:
    return (finding.check_type, finding.agent_id, finding.rule_id)


def _finding_delta(finding: Finding, status: FindingStatus) -> FindingDelta:
    return FindingDelta(
        check_type=finding.check_type,
        agent_id=finding.agent_id,
        rule_id=finding.rule_id,
        severity=finding.severity,
        title=finding.title,
        status=status,
        risk_score=finding.risk_score,
    )


def _delegation_edges(agent_id: str, delegates: list[str]) -> set[str]:
    return {delegation_edge_id(agent_id, target) for target in delegates}


def _top_risk_score(findings: list[Finding], agent_id: str) -> int:
    return max((f.risk_score or 0 for f in findings if f.agent_id == agent_id), default=0)


def diff_fleets(
    before_fleet: Fleet,
    before_tools: ToolCatalog,
    after_fleet: Fleet,
    after_tools: ToolCatalog,
    *,
    before_label: str = "before",
    after_label: str = "after",
    rule_pack: RulePack | None = None,
) -> FleetDiff:
    """Compute the deterministic access delta between two loaded snapshots.

    Both sides are analyzed with the deterministic floor only (no model calls),
    so the diff — including its findings — is reproducible and CI-safe. An
    optional ``rule_pack`` is applied to both sides so custom rules diff too.
    """

    before = analyze_fleet(before_fleet, before_tools, rule_pack=rule_pack)
    after = analyze_fleet(after_fleet, after_tools, rule_pack=rule_pack)

    before_ids = before_fleet.agent_ids
    after_ids = after_fleet.agent_ids
    agents_added = sorted(after_ids - before_ids)
    agents_removed = sorted(before_ids - after_ids)

    agent_deltas: list[AgentDelta] = []
    for agent_id in sorted(before_ids & after_ids):
        before_agent = before_fleet.agent_by_id(agent_id)
        after_agent = after_fleet.agent_by_id(agent_id)

        granted_before = set(before_agent.granted_tools)
        granted_after = set(after_agent.granted_tools)
        edges_before = _delegation_edges(agent_id, before_agent.can_delegate_to)
        edges_after = _delegation_edges(agent_id, after_agent.can_delegate_to)
        effective_before = set(before.effective_access.get(agent_id, []))
        effective_after = set(after.effective_access.get(agent_id, []))
        effective_added = effective_after - effective_before

        top_before = _top_risk_score(before.findings, agent_id)
        top_after = _top_risk_score(after.findings, agent_id)

        delta = AgentDelta(
            agent_id=agent_id,
            name=after_agent.name,
            owner_before=before_agent.owner,
            owner_after=after_agent.owner,
            granted_added=sorted(granted_after - granted_before),
            granted_removed=sorted(granted_before - granted_after),
            delegation_edges_added=sorted(edges_after - edges_before),
            delegation_edges_removed=sorted(edges_before - edges_after),
            effective_added=sorted(effective_added),
            effective_removed=sorted(effective_before - effective_after),
            new_high_impact_access=sorted(effective_added & HIGH_IMPACT_TOOL_IDS),
            top_risk_score_before=top_before,
            top_risk_score_after=top_after,
            top_risk_score_delta=top_after - top_before,
        )
        # Skip agents whose access and risk are unchanged; the diff should show
        # only what moved.
        if (
            delta.owner_changed
            or delta.granted_added
            or delta.granted_removed
            or delta.delegation_edges_added
            or delta.delegation_edges_removed
            or delta.effective_added
            or delta.effective_removed
            or delta.top_risk_score_delta
        ):
            agent_deltas.append(delta)

    before_findings = {_finding_key(f): f for f in before.findings}
    after_findings = {_finding_key(f): f for f in after.findings}

    findings_introduced = [
        _finding_delta(finding, "introduced")
        for key, finding in after_findings.items()
        if key not in before_findings
    ]
    findings_resolved = [
        _finding_delta(finding, "resolved")
        for key, finding in before_findings.items()
        if key not in after_findings
    ]
    findings_persisting: list[FindingDelta] = []
    for key, finding in after_findings.items():
        if key not in before_findings:
            continue
        previous = before_findings[key]
        item = _finding_delta(finding, "persisting")
        item.risk_score_before = previous.risk_score
        if finding.risk_score is not None and previous.risk_score is not None:
            item.risk_score_delta = finding.risk_score - previous.risk_score
        findings_persisting.append(item)

    findings_introduced.sort(key=_finding_delta_sort_key)
    findings_resolved.sort(key=_finding_delta_sort_key)
    findings_persisting.sort(key=_finding_delta_sort_key)

    fleet_risk_before = sum(f.risk_score or 0 for f in before.findings)
    fleet_risk_after = sum(f.risk_score or 0 for f in after.findings)

    return FleetDiff(
        before_label=before_label,
        after_label=after_label,
        agents_added=agents_added,
        agents_removed=agents_removed,
        agent_deltas=agent_deltas,
        findings_introduced=findings_introduced,
        findings_resolved=findings_resolved,
        findings_persisting=findings_persisting,
        fleet_risk_before=fleet_risk_before,
        fleet_risk_after=fleet_risk_after,
        fleet_risk_delta=fleet_risk_after - fleet_risk_before,
    )


def _finding_delta_sort_key(delta: FindingDelta) -> tuple[int, str, str, str]:
    # Highest severity first, then a stable lexical order for reproducibility.
    return (
        -SEVERITY_ORDER.get(delta.severity, 0),
        delta.agent_id,
        delta.check_type,
        delta.rule_id or "",
    )


def introduced_findings_at_or_above(diff: FleetDiff, severity: str) -> list[FindingDelta]:
    """Newly introduced findings meeting a severity threshold (for CI gating)."""

    threshold = SEVERITY_ORDER.get(severity.strip().lower())
    if threshold is None:
        raise ValueError(f"unknown severity {severity!r}; use critical|high|medium|low")
    return [
        finding
        for finding in diff.findings_introduced
        if SEVERITY_ORDER.get(finding.severity, 0) >= threshold
    ]


def _signed(value: int) -> str:
    return f"+{value}" if value > 0 else str(value)


def render_diff_summary(diff: FleetDiff) -> str:
    """A concise, plain-text summary for the terminal."""

    lines = [f"Access change review: {diff.before_label} -> {diff.after_label}"]
    if not diff.has_changes and diff.fleet_risk_delta == 0:
        lines.append("No access or finding changes detected.")
        return "\n".join(lines)

    lines.append(
        f"Fleet risk exposure: {diff.fleet_risk_before} -> {diff.fleet_risk_after} "
        f"({_signed(diff.fleet_risk_delta)})"
    )
    lines.append(
        f"Findings: {len(diff.findings_introduced)} introduced, "
        f"{len(diff.findings_resolved)} resolved, {len(diff.findings_persisting)} persisting"
    )
    if diff.agents_added:
        lines.append(f"Agents added: {', '.join(diff.agents_added)}")
    if diff.agents_removed:
        lines.append(f"Agents removed: {', '.join(diff.agents_removed)}")

    for finding in diff.findings_introduced:
        lines.append(
            f"- NEW [{finding.severity.upper()}] {finding.agent_id}: {finding.title} "
            f"(score {finding.risk_score})"
        )
    for finding in diff.findings_resolved:
        lines.append(
            f"- RESOLVED [{finding.severity.upper()}] {finding.agent_id}: {finding.title}"
        )

    for delta in diff.agent_deltas:
        parts: list[str] = []
        if delta.owner_changed:
            parts.append(f"owner {delta.owner_before or 'null'} -> {delta.owner_after or 'null'}")
        if delta.granted_added:
            parts.append(f"+grants {', '.join(delta.granted_added)}")
        if delta.granted_removed:
            parts.append(f"-grants {', '.join(delta.granted_removed)}")
        if delta.delegation_edges_added:
            parts.append(f"+delegation {', '.join(delta.delegation_edges_added)}")
        if delta.delegation_edges_removed:
            parts.append(f"-delegation {', '.join(delta.delegation_edges_removed)}")
        if delta.new_high_impact_access:
            parts.append(
                f"newly reaches high-impact {', '.join(delta.new_high_impact_access)}"
            )
        if delta.top_risk_score_delta:
            parts.append(f"top risk {_signed(delta.top_risk_score_delta)}")
        if parts:
            lines.append(f"- {delta.agent_id}: {'; '.join(parts)}")
    return "\n".join(lines)


def render_diff_markdown(diff: FleetDiff) -> str:
    """A readable Markdown change-review report for export."""

    lines = [
        "# Steward access change review",
        "",
        f"**Before:** `{diff.before_label}`  ",
        f"**After:** `{diff.after_label}`",
        "",
        "## Summary",
        "",
        f"- Fleet risk exposure: **{diff.fleet_risk_before} → {diff.fleet_risk_after}** "
        f"({_signed(diff.fleet_risk_delta)})",
        f"- Findings introduced: **{len(diff.findings_introduced)}** · "
        f"resolved: **{len(diff.findings_resolved)}** · "
        f"persisting: **{len(diff.findings_persisting)}**",
        f"- Agents added: {len(diff.agents_added)} · removed: {len(diff.agents_removed)}",
        "",
    ]
    if not diff.has_changes and diff.fleet_risk_delta == 0:
        lines.append("_No access or finding changes detected._")
        return "\n".join(lines) + "\n"

    if diff.findings_introduced:
        lines += ["## Findings introduced", ""]
        for finding in diff.findings_introduced:
            lines.append(
                f"- **[{finding.severity.upper()}]** `{finding.agent_id}` — {finding.title} "
                f"(risk {finding.risk_score})"
            )
        lines.append("")
    if diff.findings_resolved:
        lines += ["## Findings resolved", ""]
        for finding in diff.findings_resolved:
            lines.append(
                f"- **[{finding.severity.upper()}]** `{finding.agent_id}` — {finding.title}"
            )
        lines.append("")
    if diff.agents_added or diff.agents_removed:
        lines += ["## Fleet membership", ""]
        if diff.agents_added:
            lines.append(f"- Added: {', '.join(f'`{a}`' for a in diff.agents_added)}")
        if diff.agents_removed:
            lines.append(f"- Removed: {', '.join(f'`{a}`' for a in diff.agents_removed)}")
        lines.append("")
    if diff.agent_deltas:
        lines += ["## Per-agent access changes", ""]
        for delta in diff.agent_deltas:
            lines.append(f"### `{delta.agent_id}` — {delta.name}")
            if delta.owner_changed:
                lines.append(
                    f"- Owner: {delta.owner_before or '_null_'} → {delta.owner_after or '_null_'}"
                )
            if delta.granted_added:
                lines.append(f"- Grants added: {', '.join(delta.granted_added)}")
            if delta.granted_removed:
                lines.append(f"- Grants removed: {', '.join(delta.granted_removed)}")
            if delta.delegation_edges_added:
                lines.append(
                    f"- Delegation added: {', '.join(delta.delegation_edges_added)}"
                )
            if delta.delegation_edges_removed:
                lines.append(
                    f"- Delegation removed: {', '.join(delta.delegation_edges_removed)}"
                )
            if delta.new_high_impact_access:
                lines.append(
                    f"- ⚠️ Newly reaches high-impact capabilities: "
                    f"{', '.join(delta.new_high_impact_access)}"
                )
            if delta.top_risk_score_delta:
                lines.append(
                    f"- Top risk score: {delta.top_risk_score_before} → "
                    f"{delta.top_risk_score_after} ({_signed(delta.top_risk_score_delta)})"
                )
            lines.append("")
    lines += [
        "---",
        "",
        "_Config-time snapshot diff (not an event log). A renamed agent id reads "
        "as one removal plus one addition._",
    ]
    return "\n".join(lines) + "\n"
