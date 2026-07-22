"""Optional configured-model enrichment around Steward's deterministic trust core.

The deterministic graph and checks always run first.  Bedrock may add useful
context for unfamiliar tools, but it never gets to invent graph entities or
bypass citation verification.  If no model tier is configured, this module
returns a fully useful deterministic result with an explicit metadata note.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from steward.control_mapping import annotate_findings_with_control_frameworks
from steward.findings import RulePack, filter_valid_findings, verify_finding_evidence
from steward.findings import analyze_fleet as deterministic_analyze_fleet
from steward.graph import EffectiveAccessGraph, delegation_edge_id
from steward.incident_grounding import ground_findings_in_real_world_context
from steward.llm import (
    BedrockLLM,
    LLMUnavailableError,
    classify_tools,
    create_llm,
    identify_toxic_combinations,
    infer_needed_access,
    narrate_finding,
)
from steward.models import AnalysisResult, Evidence, Finding, Fleet, Tool, ToolCatalog
from steward.redaction import redact_text
from steward.scoring import score_and_rank_findings


def _clean_text(value: Any, *, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = " ".join(value.split()).strip()
    if not cleaned:
        return None
    # Do not allow an unexpectedly large response to become report content.
    return redact_text(cleaned[:limit])


def _model_available(llm: BedrockLLM, tier: Literal["sol", "terra", "luna"]) -> bool:
    try:
        llm.model_id(tier)
    except LLMUnavailableError:
        return False
    return True


TOOL_CLASSIFICATION_BATCH_SIZE = 6
TOOL_CLASSIFICATION_BATCH_MAX_TOKENS = 1_800
TOOL_CLASSIFICATION_SINGLE_MAX_TOKENS = 700
NEEDED_ACCESS_BATCH_SIZE = 6


@dataclass
class ToolClassificationOutcome:
    """The recoverable result of classifying a catalog in bounded requests.

    ``capabilities`` always covers the full catalog once recovery has finished.
    ``model_classified_tool_ids`` deliberately excludes deterministic fallback
    labels so an LLM-proposed finding cannot quietly rely on a fabricated
    capability classification.
    """

    capabilities: dict[str, str] = field(default_factory=dict)
    model_classified_tool_ids: set[str] = field(default_factory=set)
    unclassified_tool_ids: set[str] = field(default_factory=set)
    failed_batch_tool_ids: list[list[str]] = field(default_factory=list)
    individual_retry_tool_ids: set[str] = field(default_factory=set)

    def merge(self, other: ToolClassificationOutcome) -> None:
        self.capabilities.update(other.capabilities)
        self.model_classified_tool_ids.update(other.model_classified_tool_ids)
        self.unclassified_tool_ids.update(other.unclassified_tool_ids)
        # A successful on-demand retry supersedes an earlier fallback label.
        self.unclassified_tool_ids.difference_update(other.model_classified_tool_ids)
        self.failed_batch_tool_ids.extend(other.failed_batch_tool_ids)
        self.individual_retry_tool_ids.update(other.individual_retry_tool_ids)


def _tool_payload(tools: Iterable[Tool]) -> list[dict[str, str]]:
    """Build a display-safe, redacted classification payload for a tool batch."""

    return [
        {
            "tool_id": tool.id,
            "name": redact_text(tool.name),
            "description": redact_text(tool.description),
        }
        for tool in sorted(tools, key=lambda item: item.id)
    ]


def _validated_capabilities(response: Any, allowed_tool_ids: Iterable[str]) -> dict[str, str]:
    if not isinstance(response, Mapping):
        return {}
    entries = response.get("capabilities")
    if not isinstance(entries, list):
        return {}
    allowed = set(allowed_tool_ids)
    result: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        tool_id = entry.get("tool_id")
        capability = _clean_text(entry.get("business_capability"), limit=240)
        if isinstance(tool_id, str) and tool_id in allowed and capability:
            result[tool_id] = capability
    return result


def _fallback_capability(tool: Tool) -> str:
    """A deliberately marked label for a tool whose live classification failed."""

    return f"Unclassified capability for {redact_text(tool.name)}"


def _chunked[T](items: Sequence[T], size: int) -> Iterable[Sequence[T]]:
    for index in range(0, len(items), size):
        yield items[index : index + size]


def _classify_tools_with_recovery(
    llm: BedrockLLM,
    tools: Iterable[Tool],
) -> ToolClassificationOutcome:
    """Classify ≤6 tools per request, then retry gaps one tool at a time.

    ``BedrockLLM.call_json`` already handles transient retry/backoff for each
    request.  This layer adds semantic recovery: an incomplete-but-valid JSON
    response, or a batch that exhausts those retries, is narrowed to isolated
    tools.  Remaining tools receive a visibly unclassified deterministic label
    so the map is complete without pretending the model classified them.
    """

    ordered_tools = sorted(tools, key=lambda item: item.id)
    outcome = ToolClassificationOutcome()
    unresolved: dict[str, Tool] = {}

    for batch in _chunked(ordered_tools, TOOL_CLASSIFICATION_BATCH_SIZE):
        batch_ids = {tool.id for tool in batch}
        try:
            classified = _validated_capabilities(
                classify_tools(
                    llm,
                    _tool_payload(batch),
                    max_tokens=TOOL_CLASSIFICATION_BATCH_MAX_TOKENS,
                ),
                batch_ids,
            )
        except Exception:
            classified = {}
            outcome.failed_batch_tool_ids.append(sorted(batch_ids))
        outcome.capabilities.update(classified)
        outcome.model_classified_tool_ids.update(classified)
        unresolved.update({tool.id: tool for tool in batch if tool.id not in classified})

    for tool_id, tool in sorted(unresolved.items()):
        outcome.individual_retry_tool_ids.add(tool_id)
        try:
            classified = _validated_capabilities(
                classify_tools(
                    llm,
                    _tool_payload([tool]),
                    max_tokens=TOOL_CLASSIFICATION_SINGLE_MAX_TOKENS,
                ),
                {tool_id},
            )
        except Exception:
            classified = {}
        if capability := classified.get(tool_id):
            outcome.capabilities[tool_id] = capability
            outcome.model_classified_tool_ids.add(tool_id)
            continue
        outcome.capabilities[tool_id] = _fallback_capability(tool)
        outcome.unclassified_tool_ids.add(tool_id)

    # A complete batch needs no fallback handling; retain this invariant in
    # case the batching implementation changes later.
    for tool in ordered_tools:
        if tool.id not in outcome.capabilities:
            outcome.capabilities[tool.id] = _fallback_capability(tool)
            outcome.unclassified_tool_ids.add(tool.id)
    return outcome


def _needed_payload(
    result: AnalysisResult, capabilities: Mapping[str, str]
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    agents = [
        {"agent_id": agent.id, "name": agent.name, "description": agent.description}
        for agent in sorted(result.fleet.agents, key=lambda item: item.id)
    ]
    catalog = [
        {"tool_id": tool_id, "business_capability": capability}
        for tool_id, capability in sorted(capabilities.items())
    ]
    return agents, catalog


def _parse_needed(
    response: Any,
    result: AnalysisResult,
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    if not isinstance(response, Mapping) or not isinstance(response.get("agents"), list):
        return {}, {}
    known_agents = result.fleet.agent_ids
    needed: dict[str, list[str]] = {}
    needed_tool_ids: dict[str, list[str]] = {}
    for entry in response["agents"]:
        if not isinstance(entry, Mapping):
            continue
        agent_id = entry.get("agent_id")
        if not isinstance(agent_id, str) or agent_id not in known_agents:
            continue
        phrases = entry.get("needed_capabilities", [])
        if isinstance(phrases, list):
            cleaned = [
                phrase
                for phrase in (_clean_text(item, limit=240) for item in phrases)
                if phrase is not None
            ]
            if cleaned:
                needed[agent_id] = list(dict.fromkeys(cleaned))[:12]

        # ``needed_tool_ids`` is a supporting, optional model output. It is
        # constrained to known effective access and powers the concrete Granted
        # vs. Needed gap without turning an inference into a new finding.
        candidates = entry.get("needed_tool_ids", [])
        if isinstance(candidates, list):
            allowed = set(result.effective_access.get(agent_id, []))
            ids = [item for item in candidates if isinstance(item, str) and item in allowed]
            # An explicit empty list means the model found no candidate tool
            # justified by the declared purpose. Preserve that signal so the
            # review card can show all effective grants as a gap.
            needed_tool_ids[agent_id] = list(dict.fromkeys(ids))
    return needed, needed_tool_ids


def _infer_needed_access_with_recovery(
    llm: BedrockLLM,
    result: AnalysisResult,
    capabilities: Mapping[str, str],
) -> tuple[dict[str, list[str]], dict[str, list[str]], list[list[str]]]:
    """Infer Needed in bounded agent batches so one failure cannot erase all.

    A whole-fleet request grew past the response budget as the fleet expanded
    (30 agents of capabilities + rationale exceed the structured-output token
    cap), which silently produced zero Needed inference. Batching mirrors the
    tool-classification recovery pattern; a parsed entry only counts for an
    agent actually in the requested batch, so an echoed foreign id cannot
    smuggle in an inference.
    """

    agent_payload, capability_catalog = _needed_payload(result, capabilities)
    needed: dict[str, list[str]] = {}
    needed_tool_ids: dict[str, list[str]] = {}
    failed_batches: list[list[str]] = []
    for batch in _chunked(agent_payload, NEEDED_ACCESS_BATCH_SIZE):
        batch_agent_ids = {str(entry["agent_id"]) for entry in batch}
        try:
            parsed = infer_needed_access(llm, list(batch), capability_catalog)
        except Exception:
            failed_batches.append(sorted(batch_agent_ids))
            continue
        batch_needed, batch_tool_ids = _parse_needed(parsed, result)
        needed.update(
            {agent_id: value for agent_id, value in batch_needed.items() if agent_id in batch_agent_ids}
        )
        needed_tool_ids.update(
            {
                agent_id: value
                for agent_id, value in batch_tool_ids.items()
                if agent_id in batch_agent_ids
            }
        )
    return needed, needed_tool_ids, failed_batches


def _evidence_for_effective_tool(
    agent_id: str,
    graph: EffectiveAccessGraph,
    tool_id: str,
) -> list[Evidence]:
    provenance = graph.provenance_for(agent_id, tool_id)
    if provenance is None:
        return []
    agent = graph.fleet.agent_by_id(agent_id)
    if provenance.is_direct:
        return [
            Evidence(
                entity_type="tool",
                entity_id=tool_id,
                detail=f"{agent.name} has a direct grant of {tool_id}.",
            )
        ]
    evidence: list[Evidence] = []
    for source_id, target_id in zip(provenance.path, provenance.path[1:], strict=False):
        evidence.append(
            Evidence(
                entity_type="delegation_edge",
                entity_id=delegation_edge_id(source_id, target_id),
                detail=f"{source_id} can delegate to {target_id}.",
            )
        )
    evidence.extend(
        [
            Evidence(
                entity_type="agent",
                entity_id=provenance.grantor_agent_id,
                detail=(
                    f"{provenance.grantor_agent_id} directly holds {tool_id} and is reached through "
                    f"{' -> '.join(provenance.path)}."
                ),
            ),
            Evidence(
                entity_type="tool",
                entity_id=tool_id,
                detail=f"{agent.name} effectively reaches {tool_id} through {' -> '.join(provenance.path)}.",
            ),
        ]
    )
    return evidence


def _deduplicate_evidence(evidence: Iterable[Evidence]) -> list[Evidence]:
    seen: set[tuple[str, str]] = set()
    result: list[Evidence] = []
    for item in evidence:
        key = (item.entity_type, item.entity_id)
        if key not in seen:
            result.append(item)
            seen.add(key)
    return result


def _existing_sod_tool_sets(findings: Iterable[Finding]) -> set[tuple[str, frozenset[str]]]:
    return {
        (
            finding.agent_id,
            frozenset(
                evidence.entity_id
                for evidence in finding.evidence
                if evidence.entity_type == "tool"
            ),
        )
        for finding in findings
        if finding.check_type == "sod"
    }


def _grounded_llm_business_risk(
    *,
    agent_name: str,
    tool_ids: list[str],
    capabilities: Mapping[str, str],
    catalog: Mapping[str, Any],
) -> str:
    """Describe a proposal using only model-classified, graph-known metadata.

    ``identify_toxic_combinations`` may supply a free-form reason, but the
    response is not itself trusted report content.  This fallback restates the
    proposed pair from the verified tool catalog and constrained capability
    labels.  A later grounded narrative call may improve it, but cannot bypass
    its own citation contract either.
    """

    descriptions = [
        f"{catalog[tool_id].name} ({capabilities[tool_id]})" for tool_id in sorted(tool_ids)
    ]
    return (
        "The configured model proposed this capability pair for review. Steward independently verified that "
        f"{agent_name} effectively holds both {descriptions[0]} and {descriptions[1]}. "
        "Combining those capabilities in one identity can bypass an intended separation or review boundary; "
        "confirm the business workflow and split the grants if they are not jointly required."
    )


def _llm_sod_findings(
    response: Any,
    result: AnalysisResult,
    capabilities: Mapping[str, str],
    *,
    model_classified_tool_ids: set[str] | None = None,
    expected_agent_id: str | None = None,
) -> list[Finding]:
    """Turn LLM pair proposals into graph-evidenced SoD findings.

    The model proposes only an *idea* for a two-tool conflict.  Steward then
    independently resolves those exact tool IDs against effective access,
    builds evidence from the graph, and calls the same verifier used by the
    deterministic checks.  Nothing from a model response becomes public until
    that verifier succeeds.
    """

    if not isinstance(response, Mapping) or not isinstance(response.get("pairs"), list):
        return []
    graph = EffectiveAccessGraph(result.fleet)
    existing_pairs = _existing_sod_tool_sets(result.findings)
    catalog = {tool.id: tool for tool in result.tools.tools}
    candidates: list[Finding] = []
    for proposal in response["pairs"]:
        if not isinstance(proposal, Mapping):
            continue
        agent_id = proposal.get("agent_id")
        tool_ids = proposal.get("tool_ids")
        # A non-empty model rationale is required to distinguish an intentional
        # proposal from malformed output, but it is never copied straight into
        # the user-visible finding. Only graph-verified metadata is rendered
        # until the separately grounded narrative step accepts richer prose.
        reason = _clean_text(proposal.get("reason"), limit=1_200)
        if (
            not isinstance(agent_id, str)
            or not isinstance(tool_ids, list)
            or not reason
            or (expected_agent_id is not None and agent_id != expected_agent_id)
        ):
            continue
        valid_ids = [
            tool_id for tool_id in tool_ids if isinstance(tool_id, str) and tool_id in catalog
        ]
        valid_ids = list(dict.fromkeys(valid_ids))
        if agent_id not in graph.agent_ids or len(valid_ids) != 2:
            continue
        tool_set = frozenset(valid_ids)
        finding_key = (agent_id, tool_set)
        if (
            finding_key in existing_pairs
            or not tool_set.issubset(graph.effective_tools(agent_id))
            # Toxic-combination reasoning must use actual classified
            # capabilities, not a fallback derived from a tool ID.
            or not tool_set.issubset(capabilities)
            or (
                model_classified_tool_ids is not None
                and not tool_set.issubset(model_classified_tool_ids)
            )
        ):
            continue

        evidence = [
            Evidence(
                entity_type="agent",
                entity_id=agent_id,
                detail="holds the cited effective-access combination.",
            )
        ]
        for tool_id in sorted(valid_ids):
            evidence.extend(_evidence_for_effective_tool(agent_id, graph, tool_id))
        labels = [catalog[tool_id].name for tool_id in sorted(valid_ids)]
        rule_suffix = re.sub(r"[^a-z0-9_]+", "_", "_".join(sorted(valid_ids)).lower()).strip("_")
        candidate = Finding(
            id=f"sod:{agent_id}:llm_toxic_{rule_suffix}",
            rule_id=f"llm_toxic_{rule_suffix}",
            source="llm_generalized",
            agent_id=agent_id,
            check_type="sod",
            severity="high",
            title=f"AI-generalized toxic capability combination: {labels[0]} + {labels[1]}",
            business_risk=_grounded_llm_business_risk(
                agent_name=graph.fleet.agent_by_id(agent_id).name,
                tool_ids=valid_ids,
                capabilities=capabilities,
                catalog=catalog,
            ),
            evidence=_deduplicate_evidence(evidence),
            recommended_action=(
                "Separate the cited capabilities across independently owned identities and require an "
                "approval boundary before the consequential action is executed."
            ),
            control_mapping="Identity governance — GPT-identified segregation-of-duties candidate",
        )
        # Do the explicit per-finding gate here rather than relying only on
        # the final list filter.  This is the boundary that turns a model
        # proposal into a Steward finding.
        if verify_finding_evidence(candidate, result.fleet, graph=graph, tools=result.tools):
            candidates.append(candidate)
            existing_pairs.add(finding_key)
    return filter_valid_findings(candidates, result.fleet, graph=graph, tools=result.tools)


SEEDED_SOD_PRINCIPLES = [
    "finance: initiation must be separate from approval",
    "HR: employee creation must be separate from payroll execution",
    "IT: access request must be separate from access grant",
]


def _toxic_combination_payload(
    result: AnalysisResult,
    graph: EffectiveAccessGraph,
    agent_id: str,
    capabilities: Mapping[str, str],
) -> dict[str, Any]:
    """Build the smallest model payload that can assess one agent's access."""

    effective_tool_ids = sorted(graph.effective_tools(agent_id))
    catalog = {tool.id: tool for tool in result.tools.tools}
    paths = result.delegation_paths.get(agent_id, {})
    return {
        "seeded_sod_principles": SEEDED_SOD_PRINCIPLES,
        "agent": {
            "agent_id": agent_id,
            "effective_tool_ids": effective_tool_ids,
            "delegation_paths": {
                tool_id: paths[tool_id]
                for tool_id in effective_tool_ids
                if tool_id in paths
            },
        },
        "tools": [
            {
                "tool_id": tool_id,
                "name": redact_text(catalog[tool_id].name),
                "business_capability": capabilities[tool_id],
            }
            for tool_id in effective_tool_ids
            if tool_id in capabilities
        ],
    }


def _valid_proposed_pair_tool_ids(
    response: Any,
    *,
    agent_id: str,
    graph: EffectiveAccessGraph,
    tools: ToolCatalog,
) -> set[str]:
    """Return graph-valid proposed tool IDs so missing labels can be retried.

    This is intentionally narrower than finding construction: it trusts neither
    the model's reasoning nor its evidence, and only identifies known,
    effective pairs for an on-demand classification retry.
    """

    if not isinstance(response, Mapping) or not isinstance(response.get("pairs"), list):
        return set()
    known_tool_ids = tools.tool_ids
    effective_tool_ids = graph.effective_tools(agent_id)
    proposed: set[str] = set()
    for pair in response["pairs"]:
        if not isinstance(pair, Mapping) or pair.get("agent_id") != agent_id:
            continue
        raw_tool_ids = pair.get("tool_ids")
        if not isinstance(raw_tool_ids, list):
            continue
        tool_ids = list(
            dict.fromkeys(
                tool_id
                for tool_id in raw_tool_ids
                if isinstance(tool_id, str) and tool_id in known_tool_ids
            )
        )
        if len(tool_ids) == 2 and set(tool_ids).issubset(effective_tool_ids):
            proposed.update(tool_ids)
    return proposed


def _narrative_payload(finding: Finding, result: AnalysisResult) -> dict[str, Any]:
    agent = result.fleet.agent_by_id(finding.agent_id)
    return {
        "finding": {
            "id": finding.id,
            "source": finding.source,
            "check_type": finding.check_type,
            "severity": finding.severity,
            "title": finding.title,
            "control_mapping": finding.control_mapping,
        },
        "agent": {"id": agent.id, "name": agent.name, "description": agent.description},
        "evidence": [item.model_dump(mode="json") for item in finding.evidence],
    }


def _narrative_is_grounded(
    response: Mapping[str, Any], finding: Finding, result: AnalysisResult
) -> bool:
    """Accept prose only when the model explicitly ties it to cited graph IDs.

    A narrative is useful explanation, not evidence. Requiring an explicit list
    of cited IDs gives the model a small, machine-checkable grounding contract;
    otherwise Steward retains its deterministic prose. Any identifier-shaped
    string in the prose must also be a real graph entity.
    """

    citations = response.get("cited_entity_ids")
    if not isinstance(citations, list) or not citations:
        return False
    cited_by_finding = {evidence.entity_id for evidence in finding.evidence}
    cited_by_model = {item for item in citations if isinstance(item, str)}
    if not cited_by_model or not cited_by_model.issubset(cited_by_finding):
        return False

    known_ids = result.fleet.agent_ids | result.tools.tool_ids
    identifier_pattern = re.compile(r"\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b")
    prose = " ".join(
        value
        for value in (
            _clean_text(response.get("business_risk"), limit=1_800),
            _clean_text(response.get("recommended_action"), limit=900),
        )
        if value
    )
    return all(identifier in known_ids for identifier in identifier_pattern.findall(prose))


def _narrate_findings(llm: BedrockLLM, result: AnalysisResult) -> tuple[list[Finding], int]:
    narratives: list[Finding] = []
    accepted = 0
    for finding in result.findings:
        try:
            response = narrate_finding(llm, _narrative_payload(finding, result))
        except Exception:
            narratives.append(finding)
            continue
        if not isinstance(response, Mapping):
            narratives.append(finding)
            continue
        risk = _clean_text(response.get("business_risk"), limit=1_800)
        action = _clean_text(response.get("recommended_action"), limit=900)
        if risk and action and _narrative_is_grounded(response, finding, result):
            narratives.append(
                finding.model_copy(update={"business_risk": risk, "recommended_action": action})
            )
            accepted += 1
        else:
            narratives.append(finding)
    return narratives, accepted


def _enrich(result: AnalysisResult, llm: BedrockLLM) -> AnalysisResult:
    metadata: dict[str, Any] = {"enabled": True, "operations": {}}
    terra_available = _model_available(llm, "terra")
    sol_available = _model_available(llm, "sol")
    if not terra_available and not sol_available:
        result.metadata = {
            "llm_enrichment": {
                "enabled": False,
                "reason": "MODEL_TERRA and MODEL_SOL are not configured; deterministic analysis completed.",
            }
        }
        return result

    all_tools = sorted(result.tools.tools, key=lambda tool: tool.id)
    all_tool_ids = [tool.id for tool in all_tools]
    classification = ToolClassificationOutcome()
    if terra_available:
        try:
            classification = _classify_tools_with_recovery(llm, all_tools)
        except Exception:
            # The recovery helper normally contains individual call failures.
            # Preserve full catalog coverage even if an unexpected local error
            # occurs while preparing a request.
            classification = ToolClassificationOutcome(
                capabilities={tool.id: _fallback_capability(tool) for tool in all_tools},
                unclassified_tool_ids=set(all_tool_ids),
                failed_batch_tool_ids=[all_tool_ids],
            )

        if classification.capabilities:
            try:
                needed, needed_tool_ids, failed_batches = _infer_needed_access_with_recovery(
                    llm, result, classification.capabilities
                )
                result.needed_capabilities = needed
                result.granted_vs_needed_gaps = {
                    agent_id: sorted(
                        set(result.effective_access.get(agent_id, []))
                        - set(needed_tool_ids.get(agent_id, []))
                    )
                    for agent_id in needed_tool_ids
                }
                for agent_id, summary in result.access_summaries.items():
                    result.access_summaries[agent_id] = summary.model_copy(
                        update={
                            "needed_capabilities": needed.get(agent_id, []),
                            "granted_vs_needed_gap": result.granted_vs_needed_gaps.get(
                                agent_id, []
                            ),
                        }
                    )
                unavailable_agents = sorted(
                    agent_id for batch in failed_batches for agent_id in batch
                )
                if failed_batches and not needed and not needed_tool_ids:
                    status = "unavailable"
                elif failed_batches:
                    status = "partial"
                else:
                    status = "ok"
                metadata["operations"]["needed_access"] = {
                    "status": status,
                    "agents_with_inference": len(needed),
                    "agents_with_concrete_gap": len(needed_tool_ids),
                    "agents_unavailable": unavailable_agents,
                }
            except Exception as exc:
                metadata["operations"]["needed_access"] = {
                    "status": "unavailable",
                    "detail": type(exc).__name__,
                }
    else:
        classification = ToolClassificationOutcome(
            capabilities={tool.id: _fallback_capability(tool) for tool in all_tools},
            unclassified_tool_ids=set(all_tool_ids),
        )
        metadata["operations"]["needed_access"] = {
            "status": "unavailable",
            "detail": "classification_model_unavailable",
        }

    # Keep a complete map for reports and for reviewers investigating a partial
    # model run.  Only ``model_classified_tool_ids`` can support a model-derived
    # finding below; fallback labels are explicitly not treated as inference.
    result.tool_capabilities = classification.capabilities

    graph = EffectiveAccessGraph(result.fleet)
    eligible_agents = [
        agent
        for agent in sorted(result.fleet.agents, key=lambda item: item.id)
        if len(graph.effective_tools(agent.id)) >= 2
    ]
    toxic_incomplete_agents: list[str] = []
    on_demand_tool_retry_ids: set[str] = set()
    extra: list[Finding] = []
    if not sol_available:
        toxic_incomplete_agents = [agent.id for agent in eligible_agents]
        metadata["operations"]["toxic_combination_reasoning"] = {
            "status": "unavailable",
            "detail": "reasoning_model_unavailable",
            "agents_analyzed": 0,
            "agents_total": len(eligible_agents),
            "agents_incomplete": toxic_incomplete_agents,
            "new_cited_findings": 0,
        }
    elif not classification.model_classified_tool_ids:
        toxic_incomplete_agents = [agent.id for agent in eligible_agents]
        metadata["operations"]["toxic_combination_reasoning"] = {
            "status": "partial",
            "detail": "no_model_classified_tools",
            "agents_analyzed": 0,
            "agents_total": len(eligible_agents),
            "agents_incomplete": toxic_incomplete_agents,
            "new_cited_findings": 0,
        }
    else:
        completed_agents: list[str] = []
        for agent in eligible_agents:
            try:
                response = identify_toxic_combinations(
                    llm,
                    _toxic_combination_payload(
                        result,
                        graph,
                        agent.id,
                        classification.capabilities,
                    ),
                )
            except Exception:
                toxic_incomplete_agents.append(agent.id)
                continue
            completed_agents.append(agent.id)

            # A valid graph pair must never be discarded just because its
            # original batch received a fallback label. Retry only those two
            # cited tools with a tiny classification request before applying
            # the normal model-finding/citation gate.
            proposed_tool_ids = _valid_proposed_pair_tool_ids(
                response,
                agent_id=agent.id,
                graph=graph,
                tools=result.tools,
            )
            missing_classifications = proposed_tool_ids - classification.model_classified_tool_ids
            if missing_classifications and terra_available:
                retry_tools = [
                    result.tools.tool_by_id(tool_id) for tool_id in sorted(missing_classifications)
                ]
                on_demand_tool_retry_ids.update(missing_classifications)
                classification.merge(_classify_tools_with_recovery(llm, retry_tools))
                result.tool_capabilities = classification.capabilities

            extra.extend(
                _llm_sod_findings(
                    response,
                    result,
                    classification.capabilities,
                    model_classified_tool_ids=classification.model_classified_tool_ids,
                    expected_agent_id=agent.id,
                )
            )
        result.findings = filter_valid_findings(
            [*result.findings, *extra], result.fleet, graph=graph, tools=result.tools
        )
        metadata["operations"]["toxic_combination_reasoning"] = {
            "status": "partial" if toxic_incomplete_agents else "ok",
            "agents_analyzed": len(completed_agents),
            "agents_total": len(eligible_agents),
            "agents_incomplete": toxic_incomplete_agents,
            "on_demand_tool_retry_ids": sorted(on_demand_tool_retry_ids),
            "new_cited_findings": len(extra),
        }

    metadata["operations"]["tool_classification"] = {
        "status": "partial" if classification.unclassified_tool_ids else "ok",
        "classified_tools": len(classification.model_classified_tool_ids),
        "total_tools": len(all_tools),
        "unclassified_tool_ids": sorted(classification.unclassified_tool_ids),
        "failed_batch_tool_ids": classification.failed_batch_tool_ids,
        "individual_retry_tool_ids": sorted(classification.individual_retry_tool_ids),
    }

    if sol_available:
        narratives, accepted_narratives = _narrate_findings(llm, result)
        # Narrative changes never alter evidence, but retain this final gate as
        # a defense-in-depth invariant at the public pipeline boundary.
        result.findings = filter_valid_findings(narratives, result.fleet, tools=result.tools)
        metadata["operations"]["finding_narratives"] = {
            "status": "ok",
            "findings": len(result.findings),
            "accepted_grounded_narratives": accepted_narratives,
        }

    classification_partial = bool(classification.unclassified_tool_ids)
    toxic_partial = bool(toxic_incomplete_agents)
    metadata["status"] = "partial" if classification_partial or toxic_partial else "complete"
    metadata["completion"] = {
        "classified_tools": len(classification.model_classified_tool_ids),
        "total_tools": len(all_tools),
        "unclassified_tool_ids": sorted(classification.unclassified_tool_ids),
        "agents_incomplete": toxic_incomplete_agents,
    }
    result.metadata = {"llm_enrichment": metadata}
    return result


def analyze_fleet(
    fleet: Fleet,
    tools: ToolCatalog,
    *,
    llm: BedrockLLM | None = None,
    enable_llm: bool | None = None,
    rule_pack: RulePack | None = None,
) -> AnalysisResult:
    """Run deterministic analysis and optional redaction-first Bedrock enrichment.

    ``enable_llm`` defaults to true outside demo mode. Missing model IDs simply
    yield deterministic results; no network request is attempted in that case.
    Tests can pass a fake :class:`BedrockLLM` to exercise the constrained
    enrichment path without AWS credentials. An optional ``rule_pack`` adds
    client-specific SoD rules and capability classes to the deterministic tier.
    """

    result = deterministic_analyze_fleet(fleet, tools, rule_pack=rule_pack)
    if enable_llm is None:
        demo_mode = os.getenv("STEWARD_DEMO", "").strip().lower() in {"1", "true", "yes"}
        enable_llm = not demo_mode
    if not enable_llm:
        result.metadata = {"llm_enrichment": {"enabled": False, "reason": "disabled for demo mode"}}
        return result
    result = _enrich(result, llm or create_llm())
    # LLM-generalized findings are generated after the deterministic tier, so
    # apply the same deterministic external-context and control-framework
    # mappings — and the reproducible risk score/rank — at the final public
    # pipeline boundary. This never changes whether a finding exists.
    capability_classes = (rule_pack or RulePack()).capability_classes
    result.findings = score_and_rank_findings(
        annotate_findings_with_control_frameworks(
            ground_findings_in_real_world_context(result.findings)
        ),
        result.fleet,
        capability_classes=capability_classes,
    )
    return result
