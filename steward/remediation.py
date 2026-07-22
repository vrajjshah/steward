"""Remediation simulation and a greedy minimal-revocation planner.

Detection answers "what is wrong?"; remediation answers "what do I actually
do?" — with recomputed facts, never estimates. Two capabilities:

* **Simulate** applies hypothetical revocations (direct grants and/or
  delegation edges) to an in-memory fleet copy, re-runs the deterministic
  analysis, and expresses the result as an R1 diff of current → simulated.
* **Plan** greedily selects a small revocation set from the levers already
  cited in current findings, each step clearing the most remaining findings.

Nothing is ever mutated on disk. The plan is a *proposal for human review*: it
optimizes finding count and score, not business feasibility, and greedy is not
provably minimal. A person decides.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, Field

from .diffing import FleetDiff, diff_fleets
from .findings import analyze_fleet
from .graph import EffectiveAccessGraph
from .models import Agent, Finding, Fleet, ToolCatalog

RevocationKind = Literal["grant", "delegation"]


class RemediationError(ValueError):
    """Raised when a revocation target does not exist in the fleet."""


@dataclass(frozen=True)
class Revocation:
    """A single hypothetical revocation of a direct grant or a delegation edge."""

    kind: RevocationKind
    subject: str  # the agent holding the grant, or the delegation source
    object: str  # the tool id (grant) or the delegate agent id (delegation)

    @property
    def label(self) -> str:
        return f"{self.subject}:{self.object}" if self.kind == "grant" else f"{self.subject}->{self.object}"

    @classmethod
    def parse_grant(cls, spec: str) -> Revocation:
        agent_id, sep, tool_id = spec.partition(":")
        if not sep or not agent_id.strip() or not tool_id.strip():
            raise RemediationError(
                f"invalid --revoke {spec!r}; expected 'agent_id:tool_id'"
            )
        return cls("grant", agent_id.strip(), tool_id.strip())

    @classmethod
    def parse_edge(cls, spec: str) -> Revocation:
        source, sep, target = spec.partition("->")
        if not sep or not source.strip() or not target.strip():
            raise RemediationError(
                f"invalid --revoke-edge {spec!r}; expected 'source_agent->target_agent'"
            )
        return cls("delegation", source.strip(), target.strip())


class PlanStep(BaseModel):
    """One revocation in the ordered remediation proposal."""

    order: int
    action: str
    kind: RevocationKind
    subject: str
    object: str
    findings_cleared: list[str] = Field(default_factory=list)
    findings_cleared_count: int = 0
    fleet_risk_before: int = 0
    fleet_risk_after: int = 0
    fleet_risk_delta: int = 0
    # True/False when telemetry is available for a grant, None when unknown
    # (delegation edges, or agents with no usage data). An unused grant is a
    # zero-business-impact revocation and is preferred on ties.
    grant_observed_in_use: bool | None = None


class RemediationPlan(BaseModel):
    """A proposed, ordered set of revocations for human review."""

    fleet_label: str
    total_findings: int
    findings_cleared: int
    findings_remaining: int
    remaining_finding_titles: list[str] = Field(default_factory=list)
    fleet_risk_before: int = 0
    fleet_risk_after: int = 0
    steps: list[PlanStep] = Field(default_factory=list)


def _finding_key(finding: Finding) -> tuple[str, str, str | None]:
    return (finding.check_type, finding.agent_id, finding.rule_id)


def _fleet_risk(findings: list[Finding]) -> int:
    return sum(f.risk_score or 0 for f in findings)


def validate_targets(fleet: Fleet, revocations: list[Revocation]) -> None:
    """Ensure every revocation names a grant or edge that actually exists."""

    for revocation in revocations:
        if revocation.subject not in fleet.agent_ids:
            raise RemediationError(f"unknown agent {revocation.subject!r}")
        agent = fleet.agent_by_id(revocation.subject)
        if revocation.kind == "grant" and revocation.object not in agent.granted_tools:
            raise RemediationError(
                f"{revocation.subject!r} has no direct grant {revocation.object!r} to revoke"
            )
        if revocation.kind == "delegation" and revocation.object not in agent.can_delegate_to:
            raise RemediationError(
                f"{revocation.subject!r} does not delegate to {revocation.object!r}"
            )


def apply_revocations(fleet: Fleet, revocations: list[Revocation]) -> Fleet:
    """Return a copy of the fleet with the given grants and edges removed.

    Pure: the input fleet is never mutated, and nothing touches disk.
    """

    grant_removals: dict[str, set[str]] = {}
    edge_removals: dict[str, set[str]] = {}
    for revocation in revocations:
        target = grant_removals if revocation.kind == "grant" else edge_removals
        target.setdefault(revocation.subject, set()).add(revocation.object)

    agents: list[Agent] = []
    for agent in fleet.agents:
        data = agent.model_dump()
        if agent.id in grant_removals:
            data["granted_tools"] = [
                tool for tool in data["granted_tools"] if tool not in grant_removals[agent.id]
            ]
        if agent.id in edge_removals:
            data["can_delegate_to"] = [
                delegate
                for delegate in data["can_delegate_to"]
                if delegate not in edge_removals[agent.id]
            ]
        agents.append(Agent.model_validate(data))
    return Fleet(
        schema_version=fleet.schema_version, fleet_name=fleet.fleet_name, agents=agents
    )


def simulate(
    fleet: Fleet, tools: ToolCatalog, revocations: list[Revocation]
) -> FleetDiff:
    """Apply revocations to a fleet copy and diff current vs. simulated."""

    validate_targets(fleet, revocations)
    simulated = apply_revocations(fleet, revocations)
    return diff_fleets(
        fleet, tools, simulated, tools, before_label="current", after_label="simulated"
    )


def _grant_usage_state(fleet: Fleet, revocation: Revocation) -> bool | None:
    """Whether a grant revocation targets an observed-in-use grant.

    Returns None when usage cannot be determined (delegation edges or agents
    whose telemetry is unavailable), so 'unknown' is never reported as 'unused'.
    """

    if revocation.kind != "grant":
        return None
    holder = fleet.agent_by_id(revocation.subject)
    if not holder.usage_log_available:
        return None
    return revocation.object in holder.usage_log


def _candidate_revocations(fleet: Fleet, findings: list[Finding]) -> set[Revocation]:
    """Levers cited by current findings: direct grants and delegation edges.

    A tool reached only through delegation is revoked at its direct grant
    holder; a delegation edge in the evidence path is revoked directly. Findings
    with no such lever (an orphan cites only its ownerless agent) contribute no
    candidate and are simply not clearable by revocation.
    """

    graph = EffectiveAccessGraph(fleet)
    candidates: set[Revocation] = set()
    for finding in findings:
        for evidence in finding.evidence:
            if evidence.entity_type == "tool":
                provenance = graph.provenance_for(finding.agent_id, evidence.entity_id)
                if provenance is not None:
                    candidates.add(
                        Revocation("grant", provenance.grantor_agent_id, evidence.entity_id)
                    )
            elif evidence.entity_type == "delegation_edge":
                source, _, target = evidence.entity_id.partition("->")
                if target:
                    candidates.add(Revocation("delegation", source, target))
    return candidates


def build_plan(fleet: Fleet, tools: ToolCatalog, *, fleet_label: str = "fleet") -> RemediationPlan:
    """Greedily choose a small revocation set that clears the most findings.

    Each step picks the candidate clearing the most still-open findings, with
    ties broken by (1) larger fleet-risk reduction, (2) preferring an unused
    grant (zero business impact), then (3) a lexical order for determinism. The
    loop stops when findings are cleared or no candidate helps (e.g. remaining
    orphans, which revocation cannot fix).
    """

    result = analyze_fleet(fleet, tools)
    original_findings = result.findings
    key_to_title = {_finding_key(f): f.title for f in original_findings}
    total = len(original_findings)
    original_risk = _fleet_risk(original_findings)

    candidates = _candidate_revocations(fleet, original_findings)
    applied: list[Revocation] = []
    steps: list[PlanStep] = []
    current_keys = {_finding_key(f) for f in original_findings}
    current_risk = original_risk

    while current_keys:
        best: tuple | None = None
        for candidate in candidates:
            if candidate in applied:
                continue
            trial_findings = analyze_fleet(
                apply_revocations(fleet, [*applied, candidate]), tools
            ).findings
            trial_keys = {_finding_key(f) for f in trial_findings}
            cleared = current_keys - trial_keys
            if not cleared:
                continue
            trial_risk = _fleet_risk(trial_findings)
            zero_impact = _grant_usage_state(fleet, candidate) is False
            sort_key = (-len(cleared), trial_risk, not zero_impact, candidate.label)
            if best is None or sort_key < best[0]:
                best = (sort_key, candidate, cleared, trial_risk)
        if best is None:
            break

        _, candidate, cleared, trial_risk = best
        steps.append(
            PlanStep(
                order=len(steps) + 1,
                action=candidate.label,
                kind=candidate.kind,
                subject=candidate.subject,
                object=candidate.object,
                findings_cleared=[key_to_title[key] for key in sorted(cleared)],
                findings_cleared_count=len(cleared),
                fleet_risk_before=current_risk,
                fleet_risk_after=trial_risk,
                fleet_risk_delta=trial_risk - current_risk,
                grant_observed_in_use=_grant_usage_state(fleet, candidate),
            )
        )
        applied.append(candidate)
        current_keys -= cleared
        current_risk = trial_risk

    remaining_titles = sorted(key_to_title[key] for key in current_keys)
    return RemediationPlan(
        fleet_label=fleet_label,
        total_findings=total,
        findings_cleared=total - len(current_keys),
        findings_remaining=len(current_keys),
        remaining_finding_titles=remaining_titles,
        fleet_risk_before=original_risk,
        fleet_risk_after=current_risk,
        steps=steps,
    )


def render_plan(plan: RemediationPlan) -> str:
    """A concise, human-readable rendering of the remediation proposal."""

    lines = [
        f"Remediation proposal for {plan.fleet_label} "
        f"(PROPOSAL for human review — nothing is changed on disk).",
        f"Findings: {plan.total_findings} total -> "
        f"{plan.findings_cleared} cleared by this plan, {plan.findings_remaining} remaining.",
        f"Fleet risk exposure: {plan.fleet_risk_before} -> {plan.fleet_risk_after}.",
    ]
    if not plan.steps:
        lines.append("No single revocation clears a finding (remaining findings need owner/policy fixes).")
    for step in plan.steps:
        if step.kind == "grant":
            usage = (
                "unused — zero business impact"
                if step.grant_observed_in_use is False
                else "observed in use"
                if step.grant_observed_in_use
                else "usage unknown"
            )
            action = f"revoke grant {step.action} ({usage})"
        else:
            action = f"revoke delegation {step.action}"
        lines.append(
            f"{step.order}. {action}: clears {step.findings_cleared_count} finding(s) "
            f"[{'; '.join(step.findings_cleared)}], fleet risk {step.fleet_risk_before} -> "
            f"{step.fleet_risk_after}."
        )
    if plan.findings_remaining:
        lines.append(
            "Not resolved by this single-lever plan (assign an owner, or apply each "
            f"finding's own recommended action): {', '.join(plan.remaining_finding_titles)}."
        )
    return "\n".join(lines)
