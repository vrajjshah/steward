"""Certification-packet and audit-report builders.

This module intentionally accepts Pydantic models *or* plain mappings.  The
analysis engine is the source of truth for findings; this layer only turns
verified findings into reviewable artifacts.  Keeping that boundary loose also
makes it useful for the MCP adapter, the synthetic demo, and future SDK
adapters.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Any

from steward.control_mapping import PROCESS_CONTROLS, control_framework_coverage
from steward.incident_grounding import TOKEN_REPLAY_CONTEXT
from steward.peer_analysis import analyze_peer_groups

CONTROL_MAPPINGS: dict[str, str] = {
    "sod": "SOX ITGC — segregation of duties",
    "over_privilege": "Least privilege — periodic access certification",
    "escalation": "Delegated authority — confused-deputy control",
    "orphan": "Accountability — named ownership",
}

CHECK_LABELS: dict[str, str] = {
    "sod": "Segregation of duties",
    "over_privilege": "Over-privilege",
    "escalation": "Delegation escalation",
    "orphan": "Orphaned agent",
}

FINDING_SOURCES: dict[str, dict[str, str]] = {
    "deterministic": {
        "label": "Deterministic check",
        "description": (
            "Rule-based detection from Steward's deterministic safety floor. The deterministic tier is "
            "covered by the labeled synthetic-fleet regression and precision gate."
        ),
        "css_class": "source-deterministic",
    },
    "llm_generalized": {
        "label": "LLM-generalized",
        "description": (
            "The configured model proposed this additional combination; Steward verified its graph citations "
            "before showing it. It is evaluated separately from the deterministic golden-set gate."
        ),
        "css_class": "source-llm-generalized",
    },
}

UNKNOWN_FINDING_SOURCE = {
    "label": "Unclassified source",
    "description": "The finding source was not recognized; review its evidence before relying on it.",
    "css_class": "source-unclassified",
}

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}

_ENRICHMENT_OPERATION_LABELS = {
    "tool_classification": "Tool classification",
    "needed_access": "Needed-access inference",
    "toxic_combination_reasoning": "Toxic-combination reasoning",
    "finding_narratives": "Finding narratives",
}
_INCOMPLETE_OPERATION_STATUSES = {"error", "failed", "incomplete", "partial", "skipped", "unavailable"}


def _optional_int(value: Any) -> int | None:
    """Return a non-negative count when a metadata value safely represents one."""

    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _metadata_identifiers(value: Any, *, limit: int = 8) -> list[str]:
    """Keep a small, display-safe list of known graph identifiers from metadata."""

    if not isinstance(value, (list, tuple, set, frozenset)):
        return []
    identifiers = [str(item).strip() for item in value if str(item).strip()]
    return identifiers[:limit]


def _nested_metadata_identifiers(value: Any, *, limit: int = 8) -> list[str]:
    """Flatten small metadata batches while retaining only display-safe IDs."""

    if not isinstance(value, (list, tuple, set, frozenset)):
        return []
    flattened: list[str] = []
    for item in value:
        if isinstance(item, (list, tuple, set, frozenset)):
            flattened.extend(_metadata_identifiers(item, limit=limit))
        elif str(item).strip():
            flattened.append(str(item).strip())
        if len(flattened) >= limit:
            break
    return flattened[:limit]


def _operation_metadata(enrichment: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    """Support both live ``operations`` metadata and the cached-demo shape."""

    operations: dict[str, Mapping[str, Any]] = {}
    nested = enrichment.get("operations", {})
    if isinstance(nested, Mapping):
        operations.update(
            {
                str(name): value
                for name, value in nested.items()
                if isinstance(value, Mapping)
            }
        )
    for name in _ENRICHMENT_OPERATION_LABELS:
        value = enrichment.get(name)
        if isinstance(value, Mapping):
            operations.setdefault(name, value)
    return operations


def _operation_public(name: str, raw_operation: Mapping[str, Any]) -> dict[str, Any]:
    """Select safe, reviewer-useful completeness facts from one operation."""

    operation = as_dict(raw_operation)
    status = str(operation.get("status", "not recorded")).strip().lower() or "not recorded"
    classified = _optional_int(operation.get("classified_tools"))
    total_tools = _optional_int(operation.get("total_tools"))
    if total_tools is None:
        total_tools = _optional_int(operation.get("tools_total"))
    agents_analyzed = _optional_int(operation.get("agents_analyzed"))
    if agents_analyzed is None:
        agents_analyzed = _optional_int(operation.get("agents_checked"))
    agents_total = _optional_int(operation.get("agents_total"))
    incomplete_agents = _metadata_identifiers(
        operation.get("agents_incomplete", operation.get("incomplete_agents", []))
    )
    incomplete_tools = _metadata_identifiers(
        operation.get(
            "unclassified_tool_ids",
            operation.get(
                "unclassified_tools",
                operation.get("incomplete_tools", operation.get("tools_incomplete", [])),
            ),
        )
    )
    failed_batch_tools = _nested_metadata_identifiers(operation.get("failed_batch_tool_ids", []))
    individual_retry_tools = _metadata_identifiers(operation.get("individual_retry_tool_ids", []))
    on_demand_retry_tools = _metadata_identifiers(operation.get("on_demand_tool_retry_ids", []))
    new_findings = _optional_int(operation.get("new_cited_findings"))
    accepted_narratives = _optional_int(operation.get("accepted_grounded_narratives"))

    coverage: list[str] = []
    if classified is not None:
        if total_tools is not None:
            coverage.append(f"{classified}/{total_tools} tools classified")
        else:
            coverage.append(f"{classified} tools classified")
    if agents_analyzed is not None:
        if agents_total is not None:
            coverage.append(f"{agents_analyzed}/{agents_total} agents analyzed")
        else:
            coverage.append(f"{agents_analyzed} agents analyzed")
    if new_findings is not None:
        coverage.append(f"{new_findings} new cited finding{'s' if new_findings != 1 else ''}")
    if accepted_narratives is not None:
        coverage.append(
            f"{accepted_narratives} grounded narrative{'s' if accepted_narratives != 1 else ''}"
        )
    if incomplete_tools:
        coverage.append(f"{len(incomplete_tools)} tool{'s' if len(incomplete_tools) != 1 else ''} incomplete")
    if incomplete_agents:
        coverage.append(f"{len(incomplete_agents)} agent{'s' if len(incomplete_agents) != 1 else ''} incomplete")
    if failed_batch_tools:
        coverage.append(
            f"{len(failed_batch_tools)} tool{'s' if len(failed_batch_tools) != 1 else ''} "
            "retried after a batch failure"
        )
    if individual_retry_tools:
        coverage.append(
            f"{len(individual_retry_tools)} individual tool "
            f"retr{'y' if len(individual_retry_tools) == 1 else 'ies'}"
        )
    if on_demand_retry_tools:
        coverage.append(
            f"{len(on_demand_retry_tools)} on-demand tool "
            f"retr{'y' if len(on_demand_retry_tools) == 1 else 'ies'}"
        )

    incomplete = (
        status in _INCOMPLETE_OPERATION_STATUSES
        or bool(incomplete_tools)
        or bool(incomplete_agents)
        or (classified is not None and total_tools is not None and classified < total_tools)
        or (agents_analyzed is not None and agents_total is not None and agents_analyzed < agents_total)
    )
    return {
        "key": name,
        "label": _ENRICHMENT_OPERATION_LABELS.get(name, name.replace("_", " ").title()),
        "status": status,
        "status_label": status.replace("_", " "),
        "coverage": coverage,
        "incomplete": incomplete,
        "incomplete_agents": incomplete_agents,
        "incomplete_tools": incomplete_tools,
        "failed_batch_tools": failed_batch_tools,
        "individual_retry_tools": individual_retry_tools,
        "on_demand_retry_tools": on_demand_retry_tools,
    }


def _completion_public(raw_completion: Any) -> dict[str, Any]:
    """Normalize the core pipeline's top-level completeness contract."""

    completion = as_dict(raw_completion)
    if not isinstance(completion, Mapping):
        completion = {}
    classified = _optional_int(completion.get("classified_tools"))
    total_tools = _optional_int(completion.get("total_tools"))
    incomplete_tools = _metadata_identifiers(completion.get("unclassified_tool_ids", []))
    incomplete_agents = _metadata_identifiers(completion.get("agents_incomplete", []))
    coverage: list[str] = []
    if classified is not None:
        coverage.append(
            f"{classified}/{total_tools} tools classified"
            if total_tools is not None
            else f"{classified} tools classified"
        )
    if incomplete_tools:
        coverage.append(f"{len(incomplete_tools)} tool{'s' if len(incomplete_tools) != 1 else ''} unclassified")
    if incomplete_agents:
        coverage.append(f"{len(incomplete_agents)} agent{'s' if len(incomplete_agents) != 1 else ''} incomplete")
    return {
        "coverage": coverage,
        "classified_tools": classified,
        "total_tools": total_tools,
        "incomplete_tools": incomplete_tools,
        "incomplete_agents": incomplete_agents,
    }


def summarize_llm_enrichment(metadata: Mapping[str, Any] | None) -> dict[str, Any]:
    """Create a compact provenance/completeness summary for reports and the API.

    This intentionally does not infer whether a model *should* have found a
    risk. It only makes the pipeline's recorded completeness state visible so
    reviewers can distinguish a completed enrichment pass from a partial,
    disabled, or replayed result.
    """

    normalized = as_dict(metadata or {})
    raw = normalized.get("llm_enrichment", {}) if isinstance(normalized, Mapping) else {}
    if not isinstance(raw, Mapping):
        raw = {}

    enabled = raw.get("enabled")
    mode = str(raw.get("mode", "")).strip()
    reason = str(raw.get("reason", "")).strip()
    disclosure = _runtime_model_prose(raw.get("disclosure", "")).strip()
    recorded_status = str(raw.get("status", "")).strip().lower()
    completion = _completion_public(raw.get("completion", {}))
    operations = [_operation_public(name, value) for name, value in sorted(_operation_metadata(raw).items())]
    completion_incomplete = (
        bool(completion["incomplete_tools"])
        or bool(completion["incomplete_agents"])
        or (
            completion["classified_tools"] is not None
            and completion["total_tools"] is not None
            and completion["classified_tools"] < completion["total_tools"]
        )
    )
    any_incomplete = (
        recorded_status in _INCOMPLETE_OPERATION_STATUSES
        or completion_incomplete
        or any(operation["incomplete"] for operation in operations)
    )
    mode_lower = mode.lower()

    if enabled is False:
        state = "not_run"
        label = "Enrichment not run"
        description = reason or "Optional model enrichment did not run; deterministic analysis completed."
    elif any_incomplete:
        state = "partial"
        label = "Enrichment partial"
        description = (
            "One or more optional model-enrichment operations did not finish. "
            "Deterministic findings remain complete, but model-derived signals may be incomplete."
        )
    elif "fixture" in mode_lower or "cached" in mode_lower:
        state = "recorded"
        label = "Recorded enrichment result"
        description = (
            "This analysis replays recorded enrichment metadata. Inspect the provenance note "
            "before treating it as a live model run."
        )
    elif enabled is True and operations:
        state = "complete"
        label = "Enrichment completed"
        description = (
            "All recorded optional model-enrichment operations completed. "
            "Any surfaced finding still requires graph-citation verification."
        )
    else:
        state = "not_recorded"
        label = "Enrichment status not recorded"
        description = "No interpretable optional model-enrichment metadata was recorded for this analysis."

    return {
        "state": state,
        "label": label,
        "description": description,
        "css_class": f"enrichment-{state}",
        "mode": mode or None,
        "recorded_status": recorded_status or None,
        "reason": reason or None,
        "disclosure": disclosure or None,
        "completion": completion,
        "operations": operations,
    }


def as_dict(value: Any) -> Any:
    """Turn Pydantic/dataclass-ish values into JSON-safe primitives.

    We deliberately do not use ``dict(value)`` as a fallback: several SDK
    objects expose credentials through an iterator.  Public report fields are
    selected below, and this helper only normalizes already selected values.
    """

    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if hasattr(value, "model_dump"):
        return as_dict(value.model_dump(mode="json"))
    if isinstance(value, Mapping):
        return {str(key): as_dict(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [as_dict(item) for item in value]
    if hasattr(value, "__dict__"):
        return {
            str(key): as_dict(item)
            for key, item in vars(value).items()
            if not str(key).startswith("_")
        }
    return str(value)


def _runtime_model_prose(value: Any) -> str:
    """Keep legacy cached runtime prose model-neutral in public artifacts.

    Older fixture records used a GPT-5.6-specific fallback phrase. The finding
    remains the same cited graph fact, but reports should describe the model as
    configured at runtime rather than naming a model the current deployment
    may not use. This does not mutate the underlying cache or metadata.
    """

    return (
        str(value)
        .replace("GPT-5.6 proposed", "The configured model proposed")
        .replace("GPT-identified", "Model-identified")
        .replace("live GPT-5.6 enrichment", "live configured-model enrichment")
    )


def value_for(value: Any, key: str, default: Any = None) -> Any:
    """Read a mapping or model attribute without coupling reports to models."""

    if isinstance(value, Mapping):
        return value.get(key, default)
    return getattr(value, key, default)


def list_for(value: Any, key: str) -> list[Any]:
    candidate = value_for(value, key, [])
    if candidate is None:
        return []
    if isinstance(candidate, (list, tuple, set, frozenset)):
        return list(candidate)
    return [candidate]


def fleet_agents(fleet: Any) -> list[Any]:
    """Return agents from a Fleet model or common fleet JSON shapes."""

    if isinstance(fleet, list):
        return fleet
    agents = value_for(fleet, "agents")
    if agents is not None:
        return list(agents)
    # A handful of adapters call their root entity ``fleet``.
    nested = value_for(fleet, "fleet")
    if nested is not None:
        return fleet_agents(nested)
    return []


def fleet_tools(fleet: Any, tools: Any | None = None) -> list[Any]:
    if tools is not None:
        if isinstance(tools, Mapping):
            nested = tools.get("tools")
            return list(nested) if nested is not None else list(tools.values())
        nested = value_for(tools, "tools")
        if nested is not None:
            return list(nested)
        return list(tools)
    catalog = value_for(fleet, "tools") or value_for(fleet, "tool_catalog") or []
    if isinstance(catalog, Mapping):
        catalog = catalog.get("tools", catalog.values())
    return list(catalog)


def _agent_id(agent: Any) -> str:
    return str(value_for(agent, "id", "unknown-agent"))


def _agent_public(agent: Any, effective_access: Mapping[str, Iterable[str]]) -> dict[str, Any]:
    agent_id = _agent_id(agent)
    direct = [str(item) for item in list_for(agent, "granted_tools")]
    effective = list(effective_access.get(agent_id, direct))
    return {
        "id": agent_id,
        "name": str(value_for(agent, "name", agent_id)),
        "owner": value_for(agent, "owner"),
        "description": str(value_for(agent, "description", "")),
        "granted_tools": sorted(direct),
        "effective_access": sorted({str(item) for item in effective}),
        "can_delegate_to": [str(item) for item in list_for(agent, "can_delegate_to")],
        "usage_log": [str(item) for item in list_for(agent, "usage_log")],
        "usage_log_available": bool(value_for(agent, "usage_log_available", True)),
    }


def compute_effective_access(fleet: Any) -> dict[str, list[str]]:
    """Compute direct grants plus grants reachable along delegation edges.

    The core engine owns the authoritative graph calculation.  This small,
    defensive implementation exists so exported packets remain complete when a
    caller only passes a serialized analysis result.
    """

    agents = fleet_agents(fleet)
    by_id = {_agent_id(agent): agent for agent in agents}
    result: dict[str, list[str]] = {}

    def reachable_tools(agent_id: str) -> set[str]:
        seen: set[str] = set()
        stack = [agent_id]
        tools: set[str] = set()
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            agent = by_id.get(current)
            if agent is None:
                continue
            tools.update(str(item) for item in list_for(agent, "granted_tools"))
            stack.extend(
                str(item)
                for item in list_for(agent, "can_delegate_to")
                if str(item) in by_id and str(item) not in seen
            )
        return tools

    for agent_id in by_id:
        result[agent_id] = sorted(reachable_tools(agent_id))
    return result


def _finding_public(finding: Any) -> dict[str, Any]:
    raw = as_dict(finding)
    check_type = str(raw.get("check_type", "unknown"))
    evidence = raw.get("evidence") or []
    source = str(raw.get("source") or "deterministic").lower()
    source_display = FINDING_SOURCES.get(source, UNKNOWN_FINDING_SOURCE)
    return {
        "id": str(raw.get("id", "unidentified-finding")),
        "rule_id": raw.get("rule_id"),
        "agent_id": str(raw.get("agent_id", "unknown-agent")),
        "check_type": check_type,
        "check_label": CHECK_LABELS.get(check_type, check_type.replace("_", " ").title()),
        "source": source,
        "source_label": source_display["label"],
        "source_description": source_display["description"],
        "source_css_class": source_display["css_class"],
        "severity": str(raw.get("severity", "low")).lower(),
        "title": str(raw.get("title", "Untitled finding")),
        "business_risk": _runtime_model_prose(raw.get("business_risk", "")),
        "evidence": [as_dict(item) for item in evidence],
        "recommended_action": str(raw.get("recommended_action", "Investigate this access path.")),
        "control_mapping": _runtime_model_prose(
            raw.get("control_mapping") or CONTROL_MAPPINGS.get(check_type, "Access governance")
        ),
        "owasp_mcp": _external_references(raw.get("owasp_mcp"), kind="owasp"),
        "real_world_incident": _external_references(
            raw.get("real_world_incident"), kind="incident"
        ),
        "control_frameworks": _control_framework_references(raw.get("control_frameworks")),
        "risk_score": raw.get("risk_score"),
        "risk_factors": {
            str(name): int(points)
            for name, points in (as_dict(raw.get("risk_factors")) or {}).items()
            if isinstance(points, (int, float)) and not isinstance(points, bool)
        }
        if isinstance(raw.get("risk_factors"), Mapping)
        else {},
    }


def _control_framework_references(value: Any) -> list[dict[str, str]]:
    """Select display-safe control references; tolerate their absence in old caches."""

    raw_items = as_dict(value)
    if not isinstance(raw_items, list):
        return []
    references: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in raw_items:
        if not isinstance(item, Mapping):
            continue
        framework = str(item.get("framework", "")).strip()
        control_id = str(item.get("control_id", "")).strip()
        control_name = str(item.get("control_name", "")).strip()
        relevance = _runtime_model_prose(item.get("relevance", "")).strip()
        if not framework or not control_id or (framework, control_id) in seen:
            continue
        references.append(
            {
                "framework": framework,
                "control_id": control_id,
                "control_name": control_name,
                "relevance": relevance,
            }
        )
        seen.add((framework, control_id))
    return references


def _external_references(value: Any, *, kind: str) -> list[dict[str, str]]:
    """Select display-safe external context without requiring it in old caches.

    These references never participate in citation verification; they are
    threat-context links attached after a graph finding has already passed its
    entity-evidence gate.  Selecting known fields prevents arbitrary cached
    objects from becoming browser/report content.
    """

    raw_items = as_dict(value)
    if not isinstance(raw_items, list):
        return []
    references: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in raw_items:
        if not isinstance(item, Mapping):
            continue
        title = str(item.get("title", "")).strip()
        url = str(item.get("url", "")).strip()
        relevance = _runtime_model_prose(item.get("relevance", "")).strip()
        key = url or title
        if not title or not url or not relevance or key in seen:
            continue
        reference = {"title": title, "url": url, "relevance": relevance}
        if kind == "owasp":
            reference["id"] = str(item.get("id", "OWASP MCP")).strip() or "OWASP MCP"
        else:
            reference["date"] = str(item.get("date", "Documented date unavailable")).strip()
        references.append(reference)
        seen.add(key)
    return references


def normalize_findings(findings: Iterable[Any]) -> list[dict[str, Any]]:
    """Normalize and deterministically order findings for API/report output.

    The composite risk score leads the ordering so every surface presents the
    same auditor-reproducible ranking; severity and identity fields break ties
    and keep older cached results (with no recorded score) deterministic.
    """

    public = [_finding_public(item) for item in findings]
    return sorted(
        public,
        key=lambda item: (
            -(item.get("risk_score") or 0),
            -SEVERITY_ORDER.get(item["severity"], 0),
            item["check_type"],
            item["agent_id"],
            item["id"],
        ),
    )


def risk_tier(findings: Iterable[Mapping[str, Any]]) -> str:
    highest = max((SEVERITY_ORDER.get(str(item.get("severity", "low")), 1) for item in findings), default=0)
    return {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "clear"}[highest]


def _needed_for(needed_capabilities: Any, agent_id: str) -> list[str]:
    if not needed_capabilities:
        return []
    if isinstance(needed_capabilities, Mapping):
        values = needed_capabilities.get(agent_id, [])
    else:
        values = value_for(needed_capabilities, agent_id, [])
    if values is None:
        return []
    return sorted(str(item) for item in values)


def build_certification_packet(
    fleet: Any,
    findings: Iterable[Any],
    *,
    effective_access: Mapping[str, Iterable[str]] | None = None,
    needed_capabilities: Any | None = None,
    granted_vs_needed_gaps: Any | None = None,
    reviews: Mapping[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a per-agent certification packet suitable for reviewer action.

    ``needed_capabilities`` is deliberately kept distinct from effective access:
    it captures the LLM-assisted *Granted vs. Needed* signal without making it a
    deterministic finding or silently treating an inference as a fact.
    """

    effective_access = effective_access or compute_effective_access(fleet)
    public_findings = normalize_findings(findings)
    findings_by_agent: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in public_findings:
        findings_by_agent[finding["agent_id"]].append(finding)

    cards: list[dict[str, Any]] = []
    for agent in fleet_agents(fleet):
        identity = _agent_public(agent, effective_access)
        agent_id = identity["id"]
        needed = _needed_for(needed_capabilities, agent_id)
        granted = identity["effective_access"]
        supplied_gap = _needed_for(granted_vs_needed_gaps, agent_id)
        # Tool IDs and inferred natural-language capabilities are not necessarily
        # comparable. Only derive a gap from tool IDs; an enrichment layer may
        # pass a reviewed capability gap explicitly.
        if supplied_gap:
            gap = supplied_gap
        elif needed and all(" " not in item for item in needed):
            gap = sorted(set(granted) - set(needed))
        else:
            gap = []
        card_findings = findings_by_agent.get(agent_id, [])
        review = as_dict((reviews or {}).get(agent_id, {}))
        top_risk_score = max(
            (finding.get("risk_score") or 0 for finding in card_findings), default=0
        )
        cards.append(
            {
                "agent": identity,
                "risk_tier": risk_tier(card_findings),
                "top_risk_score": top_risk_score,
                "findings": card_findings,
                "needed_capabilities": needed,
                "granted_vs_needed_gap": gap,
                "recommended_actions": [finding["recommended_action"] for finding in card_findings],
                "review": {
                    "status": review.get("status", "pending"),
                    "note": review.get("note", ""),
                    "updated_at": review.get("updated_at"),
                },
            }
        )

    # The review queue is ranked by the same reproducible score as the
    # findings themselves; agents with no findings keep inventory order at the
    # tail via the id tiebreak.
    cards.sort(key=lambda card: (-card["top_risk_score"], card["agent"]["id"]))

    return {
        "schema_version": "0.1",
        "generated_at": generated_at or datetime.now(UTC).isoformat(),
        "packet_type": "agent_access_certification",
        "summary": {
            "agents": len(cards),
            "findings": len(public_findings),
            "critical_agents": sum(card["risk_tier"] == "critical" for card in cards),
            "pending_reviews": sum(card["review"]["status"] == "pending" for card in cards),
        },
        "risk_cards": cards,
    }


def _severity_counts(findings: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    counts = {severity: 0 for severity in ("critical", "high", "medium", "low")}
    for finding in findings:
        severity = str(finding.get("severity", "low")).lower()
        if severity in counts:
            counts[severity] += 1
    return counts


def build_fleet_audit_report(
    fleet: Any,
    findings: Iterable[Any],
    *,
    tools: Any | None = None,
    effective_access: Mapping[str, Iterable[str]] | None = None,
    needed_capabilities: Any | None = None,
    granted_vs_needed_gaps: Any | None = None,
    reviews: Mapping[str, Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
    campaigns: Mapping[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Create the fleet-level report used by the API and HTML/Markdown views."""

    public_findings = normalize_findings(findings)
    packet = build_certification_packet(
        fleet,
        public_findings,
        effective_access=effective_access,
        needed_capabilities=needed_capabilities,
        granted_vs_needed_gaps=granted_vs_needed_gaps,
        reviews=reviews,
        generated_at=generated_at,
    )
    by_check: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in public_findings:
        by_check[finding["check_type"]].append(finding)
    controls = []
    for check_type, group in sorted(by_check.items()):
        controls.append(
            {
                "check_type": check_type,
                "label": CHECK_LABELS.get(check_type, check_type.replace("_", " ").title()),
                "control_mapping": CONTROL_MAPPINGS.get(check_type, group[0]["control_mapping"]),
                "findings": len(group),
                "highest_severity": risk_tier(group),
            }
        )
    agents = fleet_agents(fleet)
    delegation_edges = [
        {"source": _agent_id(agent), "target": str(target)}
        for agent in agents
        for target in list_for(agent, "can_delegate_to")
    ]

    framework_coverage = control_framework_coverage(public_findings)
    review_status_counts: dict[str, int] = defaultdict(int)
    for card in packet["risk_cards"]:
        review_status_counts[str(card["review"].get("status", "pending"))] += 1
    top_risks = [
        {
            "rank": index + 1,
            "agent_id": finding["agent_id"],
            "title": finding["title"],
            "severity": finding["severity"],
            "risk_score": finding.get("risk_score"),
            "check_type": finding["check_type"],
        }
        for index, finding in enumerate(public_findings[:5])
    ]

    executive_summary: dict[str, Any] = {
        "findings": len(public_findings),
        "severity_counts": _severity_counts(public_findings),
        "critical_agents": packet["summary"]["critical_agents"],
        "review_status": packet["summary"]["pending_reviews"],
        # Board-facing one-page rollup: what a CISO hands upward. Every number
        # is derived from the same verified findings as the rest of the report —
        # reproducible, not editorialized.
        "top_risks": top_risks,
        "framework_coverage": {
            "frameworks": len(framework_coverage),
            "controls": sum(len(row["controls"]) for row in framework_coverage),
        },
        "review_status_counts": dict(sorted(review_status_counts.items())),
    }
    if campaigns:
        # Recurring-recertification posture: what an auditor asks after "are you
        # reviewing agent access?" — how many campaigns, how complete, how many
        # overdue. Signed decisions live in the ledger; this is the rollup.
        executive_summary["certification_campaigns"] = {
            "total": campaigns.get("total", 0),
            "open": campaigns.get("open", 0),
            "complete": campaigns.get("complete", 0),
            "overdue": campaigns.get("overdue", 0),
        }

    # Peer-group outlier analytics: a heuristic derived purely from effective
    # access, clearly labeled as analytics (not findings). Computed here so both
    # the CLI report and the dashboard surface it without extra wiring.
    peer_analysis = (
        analyze_peer_groups(effective_access).model_dump(mode="json")
        if effective_access
        else None
    )
    if peer_analysis and peer_analysis.get("outliers"):
        executive_summary["peer_outliers"] = len(peer_analysis["outliers"])

    return {
        "schema_version": "0.1",
        "generated_at": packet["generated_at"],
        "report_type": "fleet_agent_access_audit",
        "scope": {
            "agents": len(agents),
            "tools": len(fleet_tools(fleet, tools)),
            "delegation_edges": len(delegation_edges),
            "what_was_analyzed": "Agent configuration metadata: grants, declared purpose, ownership, usage, and delegation. No agent payload data was analyzed.",
        },
        "executive_summary": executive_summary,
        "certification_campaigns": dict(campaigns) if campaigns else None,
        "peer_analytics": peer_analysis,
        "control_mapping": controls,
        # Structured, versioned framework references aggregated across the
        # verified findings — auditor context, not a compliance certification.
        "control_framework_coverage": framework_coverage,
        # Controls the governance process itself (signed ledger, certification
        # queue) speaks to, independent of any individual finding.
        "governance_process_controls": [
            reference.model_dump(mode="json") for reference in PROCESS_CONTROLS
        ],
        "findings": public_findings,
        "delegation_edges": delegation_edges,
        "certification_packet": packet,
        "analysis_metadata": as_dict(metadata or {}),
        "llm_enrichment": summarize_llm_enrichment(metadata),
        # This is a documented MCP01 security note, deliberately separate
        # from a finding because the synthetic fleet does not contain graph
        # evidence of token mishandling or token replay.
        "mcp_threat_context": [as_dict(TOKEN_REPLAY_CONTEXT)],
    }


def finding_evidence_lines(finding: Mapping[str, Any]) -> list[str]:
    lines: list[str] = []
    for evidence in finding.get("evidence", []):
        evidence = as_dict(evidence)
        entity_type = evidence.get("entity_type", "entity")
        entity_id = evidence.get("entity_id", "unknown")
        detail = evidence.get("detail", "")
        lines.append(f"{entity_type}: `{entity_id}` — {detail}")
    return lines


def render_markdown_report(report: Mapping[str, Any]) -> str:
    """Render a readable, portable audit report without a template engine."""

    summary = report.get("executive_summary", {})
    scope = report.get("scope", {})
    lines = [
        "# Steward fleet audit report",
        "",
        f"Generated: {report.get('generated_at', 'unknown')}",
        "",
        "## Scope",
        "",
        f"- Agents analyzed: {scope.get('agents', 0)}",
        f"- Tools analyzed: {scope.get('tools', 0)}",
        f"- Delegation edges: {scope.get('delegation_edges', 0)}",
        f"- Data discipline: {scope.get('what_was_analyzed', '')}",
        "",
        "## Executive summary",
        "",
        f"{summary.get('findings', 0)} cited findings across {summary.get('critical_agents', 0)} critical-risk agents. "
        f"Fleet: {scope.get('agents', 0)} agent identities, {scope.get('tools', 0)} tools, "
        f"{scope.get('delegation_edges', 0)} delegation edges.",
        "",
    ]
    top_risks = summary.get("top_risks", [])
    if top_risks:
        lines.extend(
            [
                "**Top risks (composite score, reproducible every run):**",
                "",
            ]
        )
        for risk in top_risks:
            score = risk.get("risk_score")
            score_text = f"{score}/100" if score is not None else risk.get("severity", "")
            lines.append(
                f"{risk.get('rank', '?')}. `{risk.get('agent_id', '')}` — {risk.get('title', '')} ({score_text})"
            )
        lines.append("")
    framework_summary = summary.get("framework_coverage", {})
    review_counts = summary.get("review_status_counts", {})
    if framework_summary or review_counts:
        if framework_summary.get("frameworks"):
            lines.append(
                f"Findings map to {framework_summary.get('controls', 0)} controls across "
                f"{framework_summary.get('frameworks', 0)} published frameworks (see coverage matrix; "
                "context, not a certification)."
            )
        if review_counts:
            lines.append(
                "Certification review status: "
                + ", ".join(f"{count} {status}" for status, count in review_counts.items())
                + "."
            )
        lines.append("")

    campaigns = report.get("certification_campaigns")
    if campaigns:
        lines.extend(
            [
                "## Certification campaigns",
                "",
                f"{campaigns.get('total', 0)} campaign(s): "
                f"{campaigns.get('open', 0)} open, {campaigns.get('complete', 0)} complete, "
                f"{campaigns.get('overdue', 0)} overdue, {campaigns.get('closed', 0)} closed. "
                "Each decision is a signed, tamper-evident ledger event.",
                "",
                "| Campaign | Status | Progress | Due |",
                "| --- | --- | ---: | --- |",
            ]
        )
        for row in campaigns.get("campaigns", []):
            lines.append(
                f"| {row.get('name', '')} | {row.get('status', '')} | "
                f"{row.get('decided', 0)}/{row.get('agents', 0)} ({row.get('completion_pct', 0)}%) | "
                f"{row.get('due_at') or '—'} |"
            )
        lines.append("")

    peer = report.get("peer_analytics")
    if peer and peer.get("applicable") and peer.get("outliers"):
        lines.extend(
            [
                "## Peer-group outlier analytics",
                "",
                f"_{peer.get('note', '')}_ (heuristic, not a finding; "
                f"similarity threshold {peer.get('similarity_threshold')}).",
                "",
            ]
        )
        for outlier in peer["outliers"]:
            lines.append(f"- `{outlier.get('agent_id', '')}` — {outlier.get('reason', '')}")
        lines.append("")

    lines.extend(
        [
            "## Control mapping",
            "",
            "| Signal | Control language | Findings | Highest risk |",
            "| --- | --- | ---: | --- |",
        ]
    )
    for control in report.get("control_mapping", []):
        lines.append(
            f"| {control.get('label', '')} | {control.get('control_mapping', '')} | "
            f"{control.get('findings', 0)} | {control.get('highest_severity', 'clear')} |"
        )

    coverage = report.get("control_framework_coverage", [])
    if coverage:
        lines.extend(
            [
                "",
                "## Control-framework coverage",
                "",
                "Findings mapped to published control frameworks (versions cited). "
                "This matrix is auditor context — it is not a compliance certification.",
                "",
                "| Framework | Control | Name | Findings | Signals |",
                "| --- | --- | --- | ---: | --- |",
            ]
        )
        for framework_row in coverage:
            for control in framework_row.get("controls", []):
                lines.append(
                    f"| {framework_row.get('framework', '')} | {control.get('control_id', '')} | "
                    f"{control.get('control_name', '')} | {control.get('findings', 0)} | "
                    f"{', '.join(control.get('check_types', []))} |"
                )
        process_controls = report.get("governance_process_controls", [])
        if process_controls:
            lines.extend(
                [
                    "",
                    "The governance process itself (signed audit ledger, certification queue) speaks to: "
                    + "; ".join(
                        f"{item.get('framework', '')} {item.get('control_id', '')} ({item.get('control_name', '')})"
                        for item in process_controls
                    )
                    + ".",
                ]
            )

    enrichment = report.get("llm_enrichment", {})
    if enrichment:
        lines.extend(
            [
                "",
                "## Optional model enrichment",
                "",
                f"**Status:** {enrichment.get('label', 'Enrichment status not recorded')}",
                "",
                str(enrichment.get("description", "")),
            ]
        )
        if enrichment.get("mode"):
            lines.append(f"- Provenance mode: {enrichment['mode']}")
        if enrichment.get("reason"):
            lines.append(f"- Note: {enrichment['reason']}")
        if enrichment.get("disclosure"):
            lines.append(f"- Disclosure: {enrichment['disclosure']}")
        completion = enrichment.get("completion", {})
        if completion.get("coverage"):
            lines.append(f"- Completion: {', '.join(completion['coverage'])}")
        for operation in enrichment.get("operations", []):
            coverage = ", ".join(operation.get("coverage", [])) or "no coverage count recorded"
            lines.append(
                f"- {operation.get('label', 'Operation')}: "
                f"{operation.get('status_label', 'not recorded')} ({coverage})"
            )

    threat_context = report.get("mcp_threat_context", [])
    if threat_context:
        lines.extend(
            [
                "",
                "## Grounded MCP threat context",
                "",
                "These documented references provide context only. They are not additional Steward findings "
                "and do not replace the graph-entity evidence required for a finding to surface.",
            ]
        )
        for context in threat_context:
            context = as_dict(context)
            if not isinstance(context, Mapping):
                continue
            owasp = as_dict(context.get("owasp_mcp", {}))
            incident = as_dict(context.get("incident", {}))
            lines.extend(["", f"### {context.get('title', 'MCP threat context')}"])
            if isinstance(owasp, Mapping):
                lines.append(
                    f"- OWASP: [{owasp.get('id', 'MCP')}: {owasp.get('title', '')}]({owasp.get('url', '')})"
                )
            if isinstance(incident, Mapping):
                lines.append(
                    f"- Reference: [{incident.get('title', '')}]({incident.get('url', '')}) "
                    f"({incident.get('date', '')})"
                )
                lines.append(f"- Note: {incident.get('relevance', '')}")

    lines.extend(["", "## Findings", ""])
    findings = report.get("findings", [])
    if not findings:
        lines.append("No verified findings were emitted.")
    for finding in findings:
        score_suffix = (
            f" · risk score {finding.get('risk_score')}/100"
            if finding.get("risk_score") is not None
            else ""
        )
        lines.extend(
            [
                f"### [{str(finding.get('severity', 'low')).upper()}{score_suffix}] {finding.get('title', '')}",
                "",
                f"**Agent:** `{finding.get('agent_id', '')}`  ",
                f"**Control:** {finding.get('control_mapping', '')}",
                f"**Finding source:** {finding.get('source_label', 'Unclassified source')} — "
                f"{finding.get('source_description', '')}",
                "",
                finding.get("business_risk", ""),
                "",
                f"**Recommended action:** {finding.get('recommended_action', '')}",
                "",
                "**Evidence:**",
            ]
        )
        lines.extend(f"- {line}" for line in finding_evidence_lines(finding))
        framework_references = finding.get("control_frameworks", [])
        if framework_references:
            lines.extend(["", "**Control-framework context (not a certification):**"])
            lines.extend(
                f"- {reference.get('framework', '')} {reference.get('control_id', '')} "
                f"({reference.get('control_name', '')}) — {reference.get('relevance', '')}"
                for reference in framework_references
            )
        owasp_references = finding.get("owasp_mcp", [])
        incident_references = finding.get("real_world_incident", [])
        if owasp_references or incident_references:
            lines.extend(["", "**Grounded MCP context (not graph evidence):**"])
            for reference in owasp_references:
                lines.append(
                    f"- OWASP: [{reference.get('id', 'MCP')}: {reference.get('title', '')}]"
                    f"({reference.get('url', '')}) — {reference.get('relevance', '')}"
                )
            for incident in incident_references:
                lines.append(
                    f"- Documented analogue: [{incident.get('title', '')}]({incident.get('url', '')}) "
                    f"({incident.get('date', '')}) — {incident.get('relevance', '')}"
                )
        lines.append("")

    lines.extend(["## Certification queue (ranked by composite risk score)", ""])
    for card in report.get("certification_packet", {}).get("risk_cards", []):
        agent = card.get("agent", {})
        score = card.get("top_risk_score") or 0
        score_text = f", top score: {score}/100" if score else ""
        lines.append(
            f"- `{agent.get('id', '')}` ({agent.get('name', '')}) — "
            f"risk: **{card.get('risk_tier', 'clear')}**{score_text}, "
            f"review: {card.get('review', {}).get('status', 'pending')}"
        )
    return "\n".join(lines).rstrip() + "\n"
