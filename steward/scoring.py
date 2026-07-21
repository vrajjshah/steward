"""Deterministic composite risk scoring for verified findings.

An auditor sorting findings must get the same ranking on every run, so the
score is a pure function of the finding and the loaded graph — no model call,
no randomness, and an explicit factor breakdown a reviewer can recompute by
hand:

* **base severity** — critical 40 / high 30 / medium 20 / low 10 (the 4/3/2/1
  ordering scaled to points);
* **blast radius** — +4 per high-impact capability in the subject's *effective*
  access (payment approval, payroll, deletion, export, external egress, access
  grant), capped at +20;
* **data sensitivity** — +10 when effective access includes a sensitive-data
  read;
* **exploitability** — +10 when the finding cites a directly granted tool,
  +5 when every cited tool is reachable only through delegation, and a further
  +10 when the agent is exposed to untrusted content (the prompt-injection
  ingress that turns standing access into an exploitable path).

The total is capped at 100. Scores are attached after citation verification
and never create, suppress, or reorder the *set* of findings — only their
presentation rank.
"""

from __future__ import annotations

from collections.abc import Iterable

from .capability_classes import (
    HIGH_IMPACT_TOOL_IDS,
    SENSITIVE_READ_TOOL_IDS,
    UNTRUSTED_CONTENT_TOOL_IDS,
)
from .graph import EffectiveAccessGraph
from .models import Finding, Fleet

SEVERITY_BASE_POINTS = {"critical": 40, "high": 30, "medium": 20, "low": 10}
BLAST_RADIUS_POINTS_PER_CAPABILITY = 4
BLAST_RADIUS_CAP = 20
DATA_SENSITIVITY_POINTS = 10
DIRECT_GRANT_POINTS = 10
DELEGATED_ONLY_POINTS = 5
UNTRUSTED_EXPOSURE_POINTS = 10
MAX_SCORE = 100


def score_finding(finding: Finding, graph: EffectiveAccessGraph) -> Finding:
    """Return a copy of the finding carrying its reproducible score breakdown."""

    effective = graph.effective_tools(finding.agent_id)
    direct = graph.direct_tools(finding.agent_id)
    cited_tools = {
        evidence.entity_id for evidence in finding.evidence if evidence.entity_type == "tool"
    }

    base = SEVERITY_BASE_POINTS.get(finding.severity, SEVERITY_BASE_POINTS["low"])
    blast_radius = min(
        len(effective & HIGH_IMPACT_TOOL_IDS) * BLAST_RADIUS_POINTS_PER_CAPABILITY,
        BLAST_RADIUS_CAP,
    )
    data_sensitivity = DATA_SENSITIVITY_POINTS if effective & SENSITIVE_READ_TOOL_IDS else 0
    if cited_tools & direct:
        exploitability = DIRECT_GRANT_POINTS
    elif cited_tools:
        exploitability = DELEGATED_ONLY_POINTS
    else:
        exploitability = 0
    untrusted_exposure = (
        UNTRUSTED_EXPOSURE_POINTS if effective & UNTRUSTED_CONTENT_TOOL_IDS else 0
    )

    factors = {
        "base_severity": base,
        "blast_radius": blast_radius,
        "data_sensitivity": data_sensitivity,
        "exploitability": exploitability,
        "untrusted_exposure": untrusted_exposure,
    }
    return finding.model_copy(
        update={
            "risk_score": min(sum(factors.values()), MAX_SCORE),
            "risk_factors": factors,
        }
    )


def score_and_rank_findings(
    findings: Iterable[Finding],
    fleet: Fleet,
    graph: EffectiveAccessGraph | None = None,
) -> list[Finding]:
    """Score every finding and order the list by descending risk.

    Ties break on finding id so the ranking is total and stable. Re-applying
    the function recomputes identical scores (pure function of graph + finding),
    so the pipeline can safely score at more than one boundary.
    """

    graph = graph or EffectiveAccessGraph(fleet)
    scored = [score_finding(finding, graph) for finding in findings]
    return sorted(scored, key=lambda finding: (-(finding.risk_score or 0), finding.id))
