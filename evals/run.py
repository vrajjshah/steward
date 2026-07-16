"""Run Steward's evidence-first synthetic-fleet regression measurements.

The deterministic floor is the CI gate: it must maintain perfect precision and
recall on the labeled crown-jewel fixture, with graph-valid citations. A
separate offline LLM fixture exercises the same optional enrichment interface
without AWS and reports a non-gating generalization score for the novel
SalesBot combination. Neither measurement reimplements production checks or
accepts a cached demo result.

Run from the repository root:

    python -m evals.run
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CHECK_TYPES = ("sod", "over_privilege", "escalation", "orphan")
LLM_GENERALIZED_SOURCE = "llm_generalized"
REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FLEET_PATH = REPOSITORY_ROOT / "data" / "fleet.json"
DEFAULT_TOOLS_PATH = REPOSITORY_ROOT / "data" / "tools.json"
DEFAULT_ANSWER_KEY_PATH = REPOSITORY_ROOT / "data" / "answer_key.json"


class EvaluationFailure(AssertionError):
    """Raised when the synthetic fleet no longer meets Steward's trust gate."""


@dataclass(frozen=True)
class CheckMetrics:
    """Precision/recall and matching counts for one deterministic check."""

    check_type: str
    expected: int
    actual: int
    true_positive: int
    false_positive: int
    false_negative: int

    @property
    def precision(self) -> float:
        denominator = self.true_positive + self.false_positive
        return 1.0 if denominator == 0 and self.expected == 0 else self.true_positive / denominator

    @property
    def recall(self) -> float:
        denominator = self.true_positive + self.false_negative
        return 1.0 if denominator == 0 else self.true_positive / denominator


@dataclass(frozen=True)
class CitationValidation:
    """Result of checking every emitted citation against the input graph."""

    findings_checked: int
    evidence_checked: int
    errors: tuple[str, ...] = ()

    @property
    def valid(self) -> bool:
        return not self.errors

    @property
    def validity_rate(self) -> float:
        return 1.0 if self.valid else 0.0


@dataclass
class LlmTierResult:
    """A non-gating score for the offline LLM-generalization integration path."""

    metrics: dict[str, CheckMetrics]
    citations: CitationValidation
    thresholds: dict[str, float]
    unexpected_findings: list[str] = field(default_factory=list)
    missing_findings: list[str] = field(default_factory=list)
    answer_key_errors: list[str] = field(default_factory=list)
    available: bool = True
    unavailable_reason: str | None = None

    @property
    def precision(self) -> float:
        true_positive = sum(metric.true_positive for metric in self.metrics.values())
        false_positive = sum(metric.false_positive for metric in self.metrics.values())
        denominator = true_positive + false_positive
        expected = sum(metric.expected for metric in self.metrics.values())
        return 1.0 if denominator == 0 and expected == 0 else true_positive / denominator

    @property
    def recall(self) -> float:
        true_positive = sum(metric.true_positive for metric in self.metrics.values())
        false_negative = sum(metric.false_negative for metric in self.metrics.values())
        denominator = true_positive + false_negative
        return 1.0 if denominator == 0 else true_positive / denominator

    @property
    def meets_measurement_thresholds(self) -> bool:
        """Whether the fixture score meets its documented, non-gating targets."""

        return (
            self.available
            and not self.answer_key_errors
            and self.precision >= self.thresholds["precision"]
            and self.recall >= self.thresholds["recall"]
            and self.citations.validity_rate >= self.thresholds["citation_validity"]
        )


@dataclass
class EvaluationResult:
    """Serializable result returned by :func:`evaluate` for tests and CI."""

    metrics: dict[str, CheckMetrics]
    citations: CitationValidation
    unexpected_findings: list[str] = field(default_factory=list)
    missing_findings: list[str] = field(default_factory=list)
    clean_agent_violations: list[str] = field(default_factory=list)
    answer_key_errors: list[str] = field(default_factory=list)
    llm_tier: LlmTierResult | None = None

    @property
    def deterministic_passed(self) -> bool:
        return (
            self.citations.valid
            and not self.unexpected_findings
            and not self.missing_findings
            and not self.clean_agent_violations
            and not self.answer_key_errors
            and all(
                metric.precision >= 1.0 and metric.recall >= 1.0 for metric in self.metrics.values()
            )
        )

    @property
    def passed(self) -> bool:
        """The deterministic gate plus the non-negotiable LLM citation safety check.

        LLM precision/recall remains a reported measurement, not a condition
        for the deterministic CI regression gate. Invalid LLM citations would
        violate Steward's universal evidence contract, so they still fail.
        """

        return self.deterministic_passed and (
            self.llm_tier is None or self.llm_tier.citations.valid
        )


def _value(value: Any, field_name: str, default: Any = None) -> Any:
    """Read a field from a Pydantic model, dataclass, or decoded JSON object."""

    if isinstance(value, Mapping):
        return value.get(field_name, default)
    return getattr(value, field_name, default)


def _items(value: Any, field_name: str) -> list[Any]:
    candidate = _value(value, field_name, [])
    if candidate is None:
        return []
    if isinstance(candidate, (list, tuple, set, frozenset)):
        return list(candidate)
    return [candidate]


def _string_set(values: Iterable[Any]) -> set[str]:
    return {str(value) for value in values}


def _read_answer_key(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        answer_key = json.load(handle)
    if not isinstance(answer_key, dict):
        raise EvaluationFailure(f"Answer key must be a JSON object: {path}")
    if not isinstance(answer_key.get("expected_findings"), list):
        raise EvaluationFailure("Answer key must contain an 'expected_findings' list.")
    return answer_key


def _finding_label(finding: Any) -> str:
    return (
        f"{_value(finding, 'check_type', 'unknown')}:{_value(finding, 'agent_id', 'unknown')}"
        f" ({_value(finding, 'id', 'unidentified-finding')})"
    )


def _expected_label(expected: Mapping[str, Any]) -> str:
    key = expected.get("key")
    if key:
        return str(key)
    return f"{expected.get('check_type', 'unknown')}:{expected.get('agent_id', 'unknown')}"


def _evidence_pairs(finding: Any) -> set[tuple[str, str]]:
    return {
        (str(_value(evidence, "entity_type", "")), str(_value(evidence, "entity_id", "")))
        for evidence in _items(finding, "evidence")
    }


def _tool_evidence_ids(finding: Any) -> set[str]:
    return {
        entity_id for entity_type, entity_id in _evidence_pairs(finding) if entity_type == "tool"
    }


def _expected_identity(expected: Mapping[str, Any]) -> tuple[str, str]:
    return str(expected.get("check_type", "")), str(expected.get("agent_id", ""))


def _actual_identity(finding: Any) -> tuple[str, str]:
    return str(_value(finding, "check_type", "")), str(_value(finding, "agent_id", ""))


def _matches_expected(finding: Any, expected: Mapping[str, Any]) -> bool:
    """Match an emitted finding to a golden finding without relying on IDs.

    Finding IDs and internal rule identifiers are implementation details.  A
    match instead needs the same check and subject agent, every expected tool
    cited as evidence, and every entity citation required by the answer key.
    """

    if _actual_identity(finding) != _expected_identity(expected):
        return False
    # The regular answer-key bucket is the deterministic floor. Requiring its
    # source here prevents an LLM-produced finding from silently satisfying a
    # hardcoded-rule regression expectation.
    expected_source = str(expected.get("source", "deterministic"))
    if str(_value(finding, "source", "")) != expected_source:
        return False
    required_tools = _string_set(expected.get("required_tool_ids", []))
    if not required_tools.issubset(_tool_evidence_ids(finding)):
        return False
    required_evidence = {
        (str(item.get("entity_type", "")), str(item.get("entity_id", "")))
        for item in expected.get("required_evidence", [])
        if isinstance(item, Mapping)
    }
    return required_evidence.issubset(_evidence_pairs(finding))


def _inventory_graph(
    fleet: Any, tools: Any
) -> tuple[set[str], set[str], dict[str, set[str]], dict[str, set[str]]]:
    agents = _items(fleet, "agents")
    agent_ids = {str(_value(agent, "id", "")) for agent in agents}
    agent_ids.discard("")

    tool_nodes = _items(tools, "tools")
    tool_ids = {str(_value(tool, "id", "")) for tool in tool_nodes}
    tool_ids.discard("")

    delegation: dict[str, set[str]] = {}
    direct_grants: dict[str, set[str]] = {}
    for agent in agents:
        agent_id = str(_value(agent, "id", ""))
        if agent_id:
            delegation[agent_id] = _string_set(_items(agent, "can_delegate_to"))
            direct_grants[agent_id] = _string_set(_items(agent, "granted_tools"))
    return agent_ids, tool_ids, delegation, direct_grants


def _valid_edge_id(edge_id: str, delegation: Mapping[str, set[str]]) -> bool:
    """Validate the public ``source_agent->target_agent`` edge convention."""

    source, separator, target = edge_id.partition("->")
    return bool(separator and source and target and target in delegation.get(source, set()))


def _reachable_agents(subject_agent_id: str, delegation: Mapping[str, set[str]]) -> set[str]:
    """Return an agent and all of the agents it can invoke through delegation."""

    seen: set[str] = set()
    pending = [subject_agent_id]
    while pending:
        agent_id = pending.pop()
        if agent_id in seen:
            continue
        seen.add(agent_id)
        pending.extend(
            delegate for delegate in delegation.get(agent_id, set()) if delegate not in seen
        )
    return seen


def validate_citations(findings: Sequence[Any], fleet: Any, tools: Any) -> CitationValidation:
    """Assert citations are real *and* relevant to the finding's access path.

    A reference to an unrelated but real tool is not valid evidence.  Tool and
    agent citations must be effective access for the finding's subject, and a
    delegation edge must occur on a path starting at that subject.
    """

    agent_ids, tool_ids, delegation, direct_grants = _inventory_graph(fleet, tools)
    errors: list[str] = []
    evidence_checked = 0

    for finding in findings:
        label = _finding_label(finding)
        finding_agent_id = str(_value(finding, "agent_id", ""))
        if finding_agent_id not in agent_ids:
            errors.append(f"{label} has an unknown subject agent '{finding_agent_id}'.")
            continue
        reachable_agents = _reachable_agents(finding_agent_id, delegation)
        effective_tools = set().union(
            *(direct_grants.get(agent_id, set()) for agent_id in reachable_agents)
        )
        cites_subject_agent = False
        evidence = _items(finding, "evidence")
        if not evidence:
            errors.append(f"{label} has empty evidence.")
            continue
        for item in evidence:
            evidence_checked += 1
            entity_type = str(_value(item, "entity_type", ""))
            entity_id = str(_value(item, "entity_id", ""))
            raw_detail = _value(item, "detail", "")
            detail = raw_detail.strip() if isinstance(raw_detail, str) else ""
            if not entity_id:
                errors.append(f"{label} contains an evidence item with an empty entity_id.")
            if not detail:
                errors.append(f"{label} contains evidence without a detail.")
            if entity_type == "agent":
                if entity_id not in agent_ids:
                    errors.append(f"{label} cites unknown agent '{entity_id}'.")
                elif entity_id not in reachable_agents:
                    errors.append(
                        f"{label} cites agent '{entity_id}', which is not reachable "
                        "from its subject."
                    )
                if entity_id == finding_agent_id:
                    cites_subject_agent = True
            elif entity_type == "tool":
                if entity_id not in tool_ids:
                    errors.append(f"{label} cites unknown tool '{entity_id}'.")
                elif entity_id not in effective_tools:
                    errors.append(
                        f"{label} cites tool '{entity_id}', which is not effective "
                        "access for its subject."
                    )
                elif str(
                    _value(finding, "check_type", "")
                ) == "over_privilege" and entity_id not in direct_grants.get(
                    finding_agent_id, set()
                ):
                    errors.append(
                        f"{label} cites transitive tool '{entity_id}' for an "
                        "over-privilege finding."
                    )
            elif entity_type == "delegation_edge":
                if not _valid_edge_id(entity_id, delegation):
                    errors.append(f"{label} cites nonexistent delegation edge '{entity_id}'.")
                else:
                    source_agent_id = entity_id.split("->", maxsplit=1)[0]
                    if source_agent_id not in reachable_agents:
                        errors.append(
                            f"{label} cites delegation edge '{entity_id}' outside "
                            "its subject's path."
                        )
            else:
                errors.append(f"{label} uses unsupported evidence entity type '{entity_type}'.")
        if not cites_subject_agent:
            errors.append(f"{label} does not cite its subject agent '{finding_agent_id}'.")

    return CitationValidation(
        findings_checked=len(findings),
        evidence_checked=evidence_checked,
        errors=tuple(errors),
    )


def _validate_answer_key(answer_key: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    expected_findings = answer_key.get("expected_findings", [])
    identities: Counter[tuple[str, str]] = Counter()
    observed_counts: Counter[str] = Counter()

    for expected in expected_findings:
        if not isinstance(expected, Mapping):
            errors.append("Answer key includes a non-object expected finding.")
            continue
        check_type, agent_id = _expected_identity(expected)
        if check_type not in CHECK_TYPES:
            errors.append(f"Answer key has unsupported check type for {_expected_label(expected)}.")
        if not agent_id:
            errors.append(f"Answer key has no agent_id for {_expected_label(expected)}.")
        if expected.get("source", "deterministic") != "deterministic":
            errors.append(
                f"Deterministic answer-key finding {_expected_label(expected)} must have source "
                "'deterministic'."
            )
        identities[(check_type, agent_id)] += 1
        observed_counts[check_type] += 1
        if not isinstance(expected.get("required_tool_ids", []), list):
            errors.append(
                f"Answer key required_tool_ids must be a list for {_expected_label(expected)}."
            )
        if not isinstance(expected.get("required_evidence", []), list):
            errors.append(
                f"Answer key required_evidence must be a list for {_expected_label(expected)}."
            )

    for identity, count in identities.items():
        if count > 1:
            errors.append(f"Answer key duplicates expected identity {identity[0]}:{identity[1]}.")

    declared_counts = answer_key.get("expected_counts", {})
    if not isinstance(declared_counts, Mapping):
        errors.append("Answer key expected_counts must be an object.")
    else:
        for check_type in CHECK_TYPES:
            declared = declared_counts.get(check_type)
            if declared != observed_counts[check_type]:
                errors.append(
                    f"Answer key count for {check_type} is {declared!r}; "
                    f"expected_findings contains {observed_counts[check_type]}."
                )
        declared_total = declared_counts.get("total")
        if declared_total != len(expected_findings):
            errors.append(
                f"Answer key total is {declared_total!r}; expected_findings contains "
                f"{len(expected_findings)}."
            )
    return errors


@dataclass(frozen=True)
class FindingComparison:
    """One-to-one matching outcome for a result against a labeled finding set."""

    metrics: dict[str, CheckMetrics]
    missing_findings: list[str]
    unexpected_findings: list[str]


def _compare_findings(
    findings: Sequence[Any],
    expected_findings: Sequence[Mapping[str, Any]],
    *,
    check_types: Sequence[str],
) -> FindingComparison:
    """Match emitted findings to a labeled bucket and calculate per-type metrics."""

    expected_by_type: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    actual_by_type: dict[str, list[Any]] = defaultdict(list)
    for expected in expected_findings:
        expected_by_type[str(expected.get("check_type", ""))].append(expected)
    for finding in findings:
        actual_by_type[str(_value(finding, "check_type", ""))].append(finding)

    matched_actual_ids: set[int] = set()
    matched_expected_ids: set[int] = set()
    missing_findings: list[str] = []
    for expected_index, expected in enumerate(expected_findings):
        match_index: int | None = None
        for actual_index, finding in enumerate(findings):
            if actual_index in matched_actual_ids:
                continue
            if _matches_expected(finding, expected):
                match_index = actual_index
                break
        if match_index is None:
            missing_findings.append(_expected_label(expected))
        else:
            matched_expected_ids.add(expected_index)
            matched_actual_ids.add(match_index)

    unexpected_findings = [
        _finding_label(finding)
        for index, finding in enumerate(findings)
        if index not in matched_actual_ids
    ]
    observed_types = [
        *check_types,
        *(str(expected.get("check_type", "")) for expected in expected_findings),
        *(str(_value(finding, "check_type", "")) for finding in findings),
    ]
    ordered_types = list(dict.fromkeys(observed_types))
    metrics: dict[str, CheckMetrics] = {}
    for check_type in ordered_types:
        expected_count = len(expected_by_type[check_type])
        actual_count = len(actual_by_type[check_type])
        true_positive = sum(
            1
            for expected_index, expected in enumerate(expected_findings)
            if expected_index in matched_expected_ids
            and str(expected.get("check_type", "")) == check_type
        )
        metrics[check_type] = CheckMetrics(
            check_type=check_type,
            expected=expected_count,
            actual=actual_count,
            true_positive=true_positive,
            false_positive=actual_count - true_positive,
            false_negative=expected_count - true_positive,
        )
    return FindingComparison(
        metrics=metrics,
        missing_findings=missing_findings,
        unexpected_findings=unexpected_findings,
    )


def evaluate_result(result: Any, answer_key: Mapping[str, Any]) -> EvaluationResult:
    """Evaluate a completed analysis result against the supplied ground truth."""

    findings = _items(result, "findings")
    fleet = _value(result, "fleet")
    tools = _value(result, "tools")
    if fleet is None or tools is None:
        raise EvaluationFailure("Analysis result must expose fleet, tools, and findings.")

    answer_key_errors = _validate_answer_key(answer_key)
    expected_findings = [
        expected
        for expected in answer_key.get("expected_findings", [])
        if isinstance(expected, Mapping)
    ]
    comparison = _compare_findings(findings, expected_findings, check_types=CHECK_TYPES)
    clean_agents = _string_set(answer_key.get("clean_agent_ids", []))
    clean_agent_violations = [
        _finding_label(finding)
        for finding in findings
        if str(_value(finding, "agent_id", "")) in clean_agents
    ]

    return EvaluationResult(
        metrics=comparison.metrics,
        citations=validate_citations(findings, fleet, tools),
        unexpected_findings=comparison.unexpected_findings,
        missing_findings=comparison.missing_findings,
        clean_agent_violations=clean_agent_violations,
        answer_key_errors=answer_key_errors,
    )


def _llm_tier_thresholds(answer_key: Mapping[str, Any]) -> tuple[dict[str, float], list[str]]:
    defaults = {"precision": 0.5, "recall": 1.0, "citation_validity": 1.0}
    measurement = answer_key.get("llm_tier_measurement", {})
    errors: list[str] = []
    if not isinstance(measurement, Mapping):
        return defaults, ["Answer key llm_tier_measurement must be an object."]
    if measurement.get("gated") is not False:
        errors.append("Answer key llm_tier_measurement.gated must be false.")
    values = measurement.get("thresholds", {})
    if not isinstance(values, Mapping):
        return defaults, [*errors, "Answer key LLM-tier thresholds must be an object."]
    thresholds: dict[str, float] = {}
    for name, default in defaults.items():
        value = values.get(name, default)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1:
            errors.append(f"Answer key LLM-tier threshold {name!r} must be a number from 0 to 1.")
            thresholds[name] = default
        else:
            thresholds[name] = float(value)
    return thresholds, errors


def _validate_llm_tier_answer_key(answer_key: Mapping[str, Any]) -> list[str]:
    """Validate the separate generalization bucket without changing the floor."""

    errors: list[str] = []
    expected_findings = answer_key.get("llm_tier_expected_findings")
    if not isinstance(expected_findings, list):
        return ["Answer key must contain an 'llm_tier_expected_findings' list."]
    deterministic_identities = {
        _expected_identity(expected)
        for expected in answer_key.get("expected_findings", [])
        if isinstance(expected, Mapping)
    }
    identities: Counter[tuple[str, str]] = Counter()
    for expected in expected_findings:
        if not isinstance(expected, Mapping):
            errors.append("Answer key includes a non-object LLM-tier expected finding.")
            continue
        check_type, agent_id = _expected_identity(expected)
        if check_type not in CHECK_TYPES:
            errors.append(f"LLM-tier answer key has unsupported check type for {_expected_label(expected)}.")
        if not agent_id:
            errors.append(f"LLM-tier answer key has no agent_id for {_expected_label(expected)}.")
        if expected.get("source") != LLM_GENERALIZED_SOURCE:
            errors.append(
                f"LLM-tier expected finding {_expected_label(expected)} must have source "
                f"{LLM_GENERALIZED_SOURCE!r}."
            )
        if (check_type, agent_id) in deterministic_identities:
            errors.append(
                f"LLM-tier expected finding {_expected_label(expected)} duplicates the deterministic bucket."
            )
        identities[(check_type, agent_id)] += 1
        if not isinstance(expected.get("required_tool_ids", []), list):
            errors.append(
                f"LLM-tier required_tool_ids must be a list for {_expected_label(expected)}."
            )
        if not isinstance(expected.get("required_evidence", []), list):
            errors.append(
                f"LLM-tier required_evidence must be a list for {_expected_label(expected)}."
            )
    for identity, count in identities.items():
        if count > 1:
            errors.append(
                f"LLM-tier answer key duplicates expected identity {identity[0]}:{identity[1]}."
            )
    _, threshold_errors = _llm_tier_thresholds(answer_key)
    return [*errors, *threshold_errors]


def evaluate_llm_tier(result: Any, answer_key: Mapping[str, Any]) -> LlmTierResult:
    """Score only findings emitted by the LLM-generalization source.

    Deterministic findings are intentionally excluded. The fixture score asks
    whether the optional model integration can discover the novel pair, while
    citation verification remains mandatory for every surfaced LLM finding.
    """

    fleet = _value(result, "fleet")
    tools = _value(result, "tools")
    if fleet is None or tools is None:
        raise EvaluationFailure("Analysis result must expose fleet, tools, and findings.")
    thresholds, _ = _llm_tier_thresholds(answer_key)
    answer_key_errors = _validate_llm_tier_answer_key(answer_key)
    expected_findings = [
        expected
        for expected in answer_key.get("llm_tier_expected_findings", [])
        if isinstance(expected, Mapping)
    ]
    llm_findings = [
        finding
        for finding in _items(result, "findings")
        if str(_value(finding, "source", "")) == LLM_GENERALIZED_SOURCE
    ]
    check_types = tuple(
        dict.fromkeys(
            str(expected.get("check_type", ""))
            for expected in expected_findings
            if str(expected.get("check_type", ""))
        )
    )
    comparison = _compare_findings(llm_findings, expected_findings, check_types=check_types)
    return LlmTierResult(
        metrics=comparison.metrics,
        citations=validate_citations(llm_findings, fleet, tools),
        thresholds=thresholds,
        unexpected_findings=comparison.unexpected_findings,
        missing_findings=comparison.missing_findings,
        answer_key_errors=answer_key_errors,
    )


def _run_public_analysis(fleet_path: Path, tools_path: Path) -> Any:
    """Use the canonical loaders and deterministic analysis function only.

    Importing inside the function keeps ``python -m evals.run --help`` useful
    even when dependencies have not been installed yet. Do not import the
    package-level analyzer here: it is intentionally the optional pipeline and
    may invoke configured Bedrock model tiers.
    """

    from steward.findings import analyze_fleet
    from steward.loaders import load_fleet, load_tools

    fleet = load_fleet(fleet_path)
    tools = load_tools(tools_path)
    return analyze_fleet(fleet, tools)


def _run_offline_llm_analysis(fleet_path: Path, tools_path: Path) -> Any:
    """Exercise the optional pipeline with a deterministic, zero-key fixture."""

    from evals.llm_fixture import OfflineLlmFixture
    from steward.loaders import load_inventory
    from steward.pipeline import analyze_fleet

    fleet, tools = load_inventory(fleet_path, tools_path)
    return analyze_fleet(fleet, tools, llm=OfflineLlmFixture(), enable_llm=True)


def evaluate(
    *,
    fleet_path: Path = DEFAULT_FLEET_PATH,
    tools_path: Path = DEFAULT_TOOLS_PATH,
    answer_key_path: Path = DEFAULT_ANSWER_KEY_PATH,
    include_llm_tier: bool = True,
) -> EvaluationResult:
    """Run the gated floor and, by default, the separate offline LLM measurement."""

    answer_key = _read_answer_key(answer_key_path)
    result = _run_public_analysis(fleet_path, tools_path)
    evaluation = evaluate_result(result, answer_key)
    if not include_llm_tier:
        return evaluation
    try:
        llm_result = _run_offline_llm_analysis(fleet_path, tools_path)
        evaluation.llm_tier = evaluate_llm_tier(llm_result, answer_key)
    except Exception as exc:
        # The fixture should not need any external state. Keep an unexpected
        # integration error distinct from a live model/provider error and do
        # not echo exception text, which could include config fragments.
        thresholds, threshold_errors = _llm_tier_thresholds(answer_key)
        evaluation.llm_tier = LlmTierResult(
            metrics={},
            citations=CitationValidation(findings_checked=0, evidence_checked=0),
            thresholds=thresholds,
            answer_key_errors=threshold_errors,
            available=False,
            unavailable_reason=type(exc).__name__,
        )
    return evaluation


def _format_metrics(metric: CheckMetrics) -> str:
    return (
        f"{metric.check_type:15} precision={metric.precision:.3f} recall={metric.recall:.3f} "
        f"expected={metric.expected} actual={metric.actual} tp={metric.true_positive} "
        f"fp={metric.false_positive} fn={metric.false_negative}"
    )


def print_result(result: EvaluationResult) -> None:
    """Print distinct deterministic-gate and LLM-tier measurement results."""

    print("Steward synthetic-fleet evaluation")
    print("DETERMINISTIC FLOOR (GATED — required 1.000 precision/recall)")
    for check_type in CHECK_TYPES:
        print(_format_metrics(result.metrics[check_type]))
    print(
        "deterministic_citation_validity "
        f"rate={result.citations.validity_rate:.3f} "
        f"findings={result.citations.findings_checked} evidence={result.citations.evidence_checked}"
    )
    print(f"clean_agent_controls {'PASS' if not result.clean_agent_violations else 'FAIL'}")

    for error in result.answer_key_errors:
        print(f"ANSWER_KEY_ERROR: {error}")
    for error in result.citations.errors:
        print(f"CITATION_ERROR: {error}")
    for label in result.missing_findings:
        print(f"MISSING: {label}")
    for label in result.unexpected_findings:
        print(f"UNEXPECTED: {label}")
    for label in result.clean_agent_violations:
        print(f"CLEAN_AGENT_VIOLATION: {label}")

    print(f"DETERMINISTIC GATE: {'PASS' if result.deterministic_passed else 'FAIL'}")

    llm_tier = result.llm_tier
    if llm_tier is not None:
        print("LLM GENERALIZATION (OFFLINE FIXTURE — MEASURED, NON-GATING)")
        if not llm_tier.available:
            print(f"LLM TIER: UNAVAILABLE ({llm_tier.unavailable_reason or 'unknown'})")
        else:
            for metric in llm_tier.metrics.values():
                print(_format_metrics(metric))
            print(
                "llm_tier_score "
                f"precision={llm_tier.precision:.3f} recall={llm_tier.recall:.3f} "
                f"thresholds=precision>={llm_tier.thresholds['precision']:.3f},"
                f"recall>={llm_tier.thresholds['recall']:.3f}"
            )
            print(
                "llm_tier_citation_validity "
                f"rate={llm_tier.citations.validity_rate:.3f} "
                f"findings={llm_tier.citations.findings_checked} "
                f"evidence={llm_tier.citations.evidence_checked} "
                f"threshold>={llm_tier.thresholds['citation_validity']:.3f}"
            )
            for error in llm_tier.answer_key_errors:
                print(f"LLM_ANSWER_KEY_ERROR: {error}")
            for error in llm_tier.citations.errors:
                print(f"LLM_CITATION_ERROR: {error}")
            for label in llm_tier.missing_findings:
                print(f"LLM_MISSING: {label}")
            for label in llm_tier.unexpected_findings:
                print(f"LLM_UNEXPECTED: {label}")
            status = "PASS" if llm_tier.meets_measurement_thresholds else "BELOW_TARGET"
            print(f"LLM TIER MEASUREMENT: {status} (non-gating)")

    print(f"OVERALL SAFETY GATE: {'PASS' if result.passed else 'FAIL'}")


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run Steward's deterministic trust gate and offline LLM-tier measurement."
    )
    parser.add_argument("--fleet", type=Path, default=DEFAULT_FLEET_PATH)
    parser.add_argument("--tools", type=Path, default=DEFAULT_TOOLS_PATH)
    parser.add_argument("--answer-key", type=Path, default=DEFAULT_ANSWER_KEY_PATH)
    parser.add_argument(
        "--deterministic-only",
        action="store_true",
        help="Skip the optional offline LLM-fixture measurement.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        result = evaluate(
            fleet_path=args.fleet,
            tools_path=args.tools,
            answer_key_path=args.answer_key,
            include_llm_tier=not args.deterministic_only,
        )
    except Exception as exc:
        print(f"EVAL_ERROR: {exc}", file=sys.stderr)
        return 1
    print_result(result)
    return 0 if result.passed else 1


if __name__ == "__main__":  # pragma: no cover - exercised through make eval / CI
    raise SystemExit(main())
