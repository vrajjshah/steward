"""Measure the optional LLM generalization tier on a labeled scenario benchmark.

The deterministic gate (``evals.run``) proves the hardcoded floor. This module
answers a different question honestly: *how accurate is the optional model tier
itself?* It runs the real enrichment pipeline against twenty single-purpose
scenario agents with ground-truth labels:

* ``toxic_in_scope`` — sensitive-read + external-egress pairs the v0.1 model
  prompt is designed to propose. These score recall.
* ``benign`` — deliberate near-misses (internal delivery, draft-only senders,
  ticket creation, public sources). A flag here is a false positive.
* ``toxic_out_of_scope`` — genuinely toxic pairs (novel initiate-vs-approve,
  hire-vs-pay, request-vs-grant variants and a destructive pair) that the
  deliberately narrow v0.1 egress-only prompt tells the model NOT to propose.
  They are reported as a documented scope boundary, never counted as headline
  accuracy either way.

The benchmark fleet is deterministically silent (owners set, all grants used,
no delegation), so every emitted finding is model-tier output. Every surfaced
finding must still pass the same graph-citation verifier used in production;
the benchmark separately counts raw model proposals that referenced unknown or
non-effective entities and were therefore blocked by that gate.

Run modes:

    python -m evals.llm_benchmark            # replay + re-verify the committed cached result
    python -m evals.llm_benchmark --live     # real Bedrock run; rewrites the cached result

The live mode needs configured ``MODEL_TERRA``/``MODEL_SOL`` Bedrock IDs, so it
is intentionally not part of ``make eval`` or CI. CI instead re-verifies the
committed cached result's internal consistency and citation validity.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from evals.run import validate_citations

BENCHMARK_DIR = Path(__file__).resolve().parent / "benchmark"
FLEET_PATH = BENCHMARK_DIR / "fleet.json"
TOOLS_PATH = BENCHMARK_DIR / "tools.json"
LABELS_PATH = BENCHMARK_DIR / "labels.json"
RESULTS_PATH = BENCHMARK_DIR / "results.json"

LABEL_VALUES = ("toxic_in_scope", "benign", "toxic_out_of_scope")


class BenchmarkError(AssertionError):
    """Raised when the benchmark inventory, labels, or cache are inconsistent."""


@dataclass(frozen=True)
class Scenario:
    agent_id: str
    label: str
    category: str
    expected_pair: frozenset[str]


def load_scenarios(labels_path: Path = LABELS_PATH) -> list[Scenario]:
    payload = json.loads(labels_path.read_text(encoding="utf-8"))
    raw = payload.get("scenarios")
    if not isinstance(raw, list) or not raw:
        raise BenchmarkError("labels.json must contain a non-empty 'scenarios' list.")
    scenarios: list[Scenario] = []
    for entry in raw:
        if not isinstance(entry, Mapping):
            raise BenchmarkError("Every scenario must be a JSON object.")
        label = str(entry.get("label", ""))
        if label not in LABEL_VALUES:
            raise BenchmarkError(f"Scenario {entry.get('agent_id')!r} has unsupported label {label!r}.")
        pair = entry.get("expected_pair")
        if not isinstance(pair, list) or len(pair) != 2:
            raise BenchmarkError(f"Scenario {entry.get('agent_id')!r} needs a two-tool expected_pair.")
        scenarios.append(
            Scenario(
                agent_id=str(entry.get("agent_id", "")),
                label=label,
                category=str(entry.get("category", "")),
                expected_pair=frozenset(str(tool_id) for tool_id in pair),
            )
        )
    ids = [scenario.agent_id for scenario in scenarios]
    if len(set(ids)) != len(ids):
        raise BenchmarkError("labels.json contains duplicate scenario agent ids.")
    return scenarios


def validate_benchmark_inventory(fleet: Any, scenarios: Sequence[Scenario]) -> None:
    """Every scenario must map to one agent whose grants are exactly its pair."""

    agents = {agent.id: agent for agent in fleet.agents}
    if set(agents) != {scenario.agent_id for scenario in scenarios}:
        raise BenchmarkError("labels.json and fleet.json must cover the same agent ids.")
    for scenario in scenarios:
        agent = agents[scenario.agent_id]
        if set(agent.granted_tools) != set(scenario.expected_pair):
            raise BenchmarkError(
                f"{scenario.agent_id} grants {sorted(agent.granted_tools)} but the label "
                f"expects exactly {sorted(scenario.expected_pair)}."
            )
        if agent.can_delegate_to:
            raise BenchmarkError(f"{scenario.agent_id} must not delegate; the benchmark isolates the model tier.")


@dataclass
class RecordingLLM:
    """Wrap a live BedrockLLM and keep id-level records of raw toxic proposals.

    Only entity identifiers are retained (agent ids and tool ids); free-form
    model prose and request payloads are never persisted, matching Steward's
    metadata-only logging discipline.
    """

    inner: Any
    raw_proposals: list[dict[str, Any]] = field(default_factory=list)

    def model_id(self, tier: str) -> str:
        return self.inner.model_id(tier)

    def call_json(self, **kwargs: Any) -> Any:
        response = self.inner.call_json(**kwargs)
        if kwargs.get("operation") == "toxic_combination_reasoning":
            payload = kwargs.get("payload")
            subject = ""
            if isinstance(payload, Mapping):
                agent = payload.get("agent")
                if isinstance(agent, Mapping):
                    subject = str(agent.get("agent_id", ""))
            if isinstance(response, Mapping) and isinstance(response.get("pairs"), list):
                for pair in response["pairs"]:
                    if not isinstance(pair, Mapping):
                        continue
                    tool_ids = pair.get("tool_ids")
                    self.raw_proposals.append(
                        {
                            "subject_agent_id": subject,
                            "proposed_agent_id": str(pair.get("agent_id", "")),
                            "tool_ids": sorted(
                                str(tool_id) for tool_id in tool_ids if isinstance(tool_id, str)
                            )
                            if isinstance(tool_ids, list)
                            else [],
                        }
                    )
        return response


def _llm_findings(result_findings: Sequence[Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for finding in result_findings:
        dumped = finding.model_dump(mode="json") if hasattr(finding, "model_dump") else dict(finding)
        if dumped.get("source") == "llm_generalized":
            findings.append(dumped)
    return findings


def _cited_tool_pair(finding: Mapping[str, Any]) -> frozenset[str]:
    return frozenset(
        str(item.get("entity_id"))
        for item in finding.get("evidence", [])
        if isinstance(item, Mapping) and item.get("entity_type") == "tool"
    )


def score(
    scenarios: Sequence[Scenario],
    llm_findings: Sequence[Mapping[str, Any]],
    fleet_doc: Mapping[str, Any],
    tools_doc: Mapping[str, Any],
    raw_proposals: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Score surfaced model-tier findings against the ground-truth labels."""

    by_agent: dict[str, list[Mapping[str, Any]]] = {}
    for finding in llm_findings:
        by_agent.setdefault(str(finding.get("agent_id", "")), []).append(finding)

    outcomes: list[dict[str, Any]] = []
    counts = {label: {"total": 0, "flagged": 0} for label in LABEL_VALUES}
    correct_pair_true_positives = 0
    for scenario in scenarios:
        agent_findings = by_agent.get(scenario.agent_id, [])
        flagged = bool(agent_findings)
        cited_pairs = [sorted(_cited_tool_pair(finding)) for finding in agent_findings]
        pair_correct = any(
            frozenset(pair) == scenario.expected_pair for pair in cited_pairs
        )
        counts[scenario.label]["total"] += 1
        if flagged:
            counts[scenario.label]["flagged"] += 1
        if scenario.label == "toxic_in_scope" and pair_correct:
            correct_pair_true_positives += 1
        outcomes.append(
            {
                "agent_id": scenario.agent_id,
                "label": scenario.label,
                "category": scenario.category,
                "expected_pair": sorted(scenario.expected_pair),
                "flagged": flagged,
                "cited_pairs": cited_pairs,
            }
        )

    # Headline metrics cover only the labels the v0.1 prompt is contracted to
    # separate: in-scope toxic (should flag) versus benign (must not flag).
    true_positive = correct_pair_true_positives
    false_positive = counts["benign"]["flagged"]
    false_negative = counts["toxic_in_scope"]["total"] - true_positive
    precision = 1.0 if (true_positive + false_positive) == 0 else true_positive / (true_positive + false_positive)
    recall = 1.0 if counts["toxic_in_scope"]["total"] == 0 else true_positive / counts["toxic_in_scope"]["total"]

    # Hallucination accounting. Surfaced findings must all be graph-valid; the
    # raw-proposal ledger shows what the citation gate had to block.
    hallucinated_surfaced = 0
    for finding in llm_findings:
        validation = validate_citations([finding], fleet_doc, tools_doc)
        if not validation.valid:
            hallucinated_surfaced += 1

    agent_ids = {str(agent.get("id")) for agent in fleet_doc.get("agents", [])}
    tool_ids = {str(tool.get("id")) for tool in tools_doc.get("tools", [])}
    grants = {
        str(agent.get("id")): set(agent.get("granted_tools", []))
        for agent in fleet_doc.get("agents", [])
    }
    surfaced_keys = {
        (str(finding.get("agent_id", "")), _cited_tool_pair(finding)) for finding in llm_findings
    }
    proposal_records: list[dict[str, Any]] = []
    unknown_entity_proposals = 0
    not_effective_proposals = 0
    for proposal in raw_proposals:
        proposed_agent = str(proposal.get("proposed_agent_id", ""))
        proposed_tools = [str(tool_id) for tool_id in proposal.get("tool_ids", [])]
        known = proposed_agent in agent_ids and set(proposed_tools) <= tool_ids
        # The benchmark fleet has no delegation, so effective access is the
        # agent's direct grants.
        effective = known and set(proposed_tools) <= grants.get(proposed_agent, set())
        surfaced = (proposed_agent, frozenset(proposed_tools)) in surfaced_keys
        if not known:
            unknown_entity_proposals += 1
        elif not effective:
            not_effective_proposals += 1
        proposal_records.append(
            {
                **{key: proposal[key] for key in ("subject_agent_id", "proposed_agent_id", "tool_ids")},
                "known_entities": known,
                "effective_for_proposed_agent": effective,
                "surfaced": surfaced,
            }
        )

    return {
        "scenario_outcomes": outcomes,
        "metrics": {
            "in_scope_total": counts["toxic_in_scope"]["total"],
            "in_scope_flagged": counts["toxic_in_scope"]["flagged"],
            "true_positive": true_positive,
            "false_positive": false_positive,
            "false_negative": false_negative,
            "benign_total": counts["benign"]["total"],
            "benign_flagged": counts["benign"]["flagged"],
            "out_of_scope_total": counts["toxic_out_of_scope"]["total"],
            "out_of_scope_flagged": counts["toxic_out_of_scope"]["flagged"],
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "surfaced_findings": len(llm_findings),
            "hallucinated_surfaced_findings": hallucinated_surfaced,
            "hallucinated_citation_rate": 0.0
            if not llm_findings
            else round(hallucinated_surfaced / len(llm_findings), 4),
        },
        "raw_proposals": {
            "total": len(proposal_records),
            "unknown_entity_proposals": unknown_entity_proposals,
            "not_effective_proposals": not_effective_proposals,
            "records": proposal_records,
        },
    }


def _print_report(report: Mapping[str, Any]) -> None:
    metrics = report["metrics"]
    print("Steward LLM-tier accuracy benchmark (non-gating; separate from the deterministic gate)")
    runs = report.get("runs")
    run_note = f" ({runs} run{'s' if runs != 1 else ''})" if runs else ""
    print(f"mode: {report.get('mode', 'unknown')}{run_note}")
    print(
        f"in-scope toxic: flagged {metrics['true_positive']}/{metrics['in_scope_total']} "
        f"(recall={metrics['recall']:.3f})"
    )
    print(
        f"benign near-misses: false positives {metrics['benign_flagged']}/{metrics['benign_total']} "
        f"(precision={metrics['precision']:.3f})"
    )
    print(
        "out-of-scope toxic (documented v0.1 prompt boundary): flagged "
        f"{metrics['out_of_scope_flagged']}/{metrics['out_of_scope_total']}"
    )
    print(
        f"surfaced findings: {metrics['surfaced_findings']}, hallucinated citations: "
        f"{metrics['hallucinated_surfaced_findings']} "
        f"(rate={metrics['hallucinated_citation_rate']:.3f}; requirement 0.000)"
    )
    raw = report["raw_proposals"]
    print(
        f"raw model proposals: {raw['total']} total, {raw['unknown_entity_proposals']} cited unknown "
        f"entities, {raw['not_effective_proposals']} cited non-effective access (all blocked by the "
        "citation gate before output)"
    )
    aggregate = report.get("runs_aggregate")
    if aggregate and aggregate.get("runs", 0) > 1:
        per_metric = aggregate["per_metric"]
        print(f"aggregate over {aggregate['runs']} runs (mean [min, max]):")
        for key in ("recall", "precision", "hallucinated_citation_rate"):
            stats = per_metric.get(key)
            if stats:
                print(
                    f"  {key}: {stats['mean']:.3f} [{stats['min']:.3f}, {stats['max']:.3f}]"
                )
    for outcome in report["scenario_outcomes"]:
        marker = "FLAGGED" if outcome["flagged"] else "clean  "
        print(f"  [{outcome['label']:>18}] {marker} {outcome['agent_id']} ({outcome['category']})")


def aggregate_metrics(runs: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Aggregate per-metric mean/min/max across several benchmark runs.

    A single live run can't distinguish a robust model from a lucky one. When
    the benchmark is run more than once, this reduces the numeric metrics of
    each run to mean/min/max so the provenance carries the *spread*, not one
    sample. Pure and side-effect-free, so it is unit-tested without any model
    call.
    """

    materialized = [dict(run) for run in runs]
    if not materialized:
        return {"runs": 0, "per_metric": {}}
    numeric_keys = [
        key
        for key, value in materialized[0].items()
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    ]
    per_metric: dict[str, dict[str, float]] = {}
    for key in numeric_keys:
        values = [
            float(run[key])
            for run in materialized
            if isinstance(run.get(key), (int, float)) and not isinstance(run.get(key), bool)
        ]
        if not values:
            continue
        per_metric[key] = {
            "mean": round(sum(values) / len(values), 4),
            "min": min(values),
            "max": max(values),
        }
    return {"runs": len(materialized), "per_metric": per_metric}


def run_live(output_path: Path = RESULTS_PATH, *, runs: int = 1) -> int:
    from steward.findings import analyze_fleet as deterministic_analyze_fleet
    from steward.llm import create_llm
    from steward.loaders import load_inventory
    from steward.pipeline import analyze_fleet

    if runs < 1:
        raise BenchmarkError("--runs must be at least 1")

    scenarios = load_scenarios()
    fleet, tools = load_inventory(FLEET_PATH, TOOLS_PATH)
    validate_benchmark_inventory(fleet, scenarios)

    deterministic = deterministic_analyze_fleet(fleet, tools)
    if deterministic.findings:
        raise BenchmarkError(
            "Benchmark fleet must be deterministically silent; got "
            f"{[finding.id for finding in deterministic.findings]}"
        )

    fleet_doc = json.loads(FLEET_PATH.read_text(encoding="utf-8"))
    tools_doc = json.loads(TOOLS_PATH.read_text(encoding="utf-8"))

    per_run_metrics: list[Mapping[str, Any]] = []
    llm = result = llm_findings = report = None
    for index in range(runs):
        if runs > 1:
            print(f"benchmark run {index + 1}/{runs}...")
        llm = RecordingLLM(inner=create_llm())
        result = analyze_fleet(fleet, tools, llm=llm, enable_llm=True)
        llm_findings = _llm_findings(result.findings)
        report = score(scenarios, llm_findings, fleet_doc, tools_doc, llm.raw_proposals)
        per_run_metrics.append(report["metrics"])

    # The last run is the canonical cache (verify recomputes from its findings);
    # the aggregate captures the spread across every run.
    enrichment = result.metadata.get("llm_enrichment", {})
    model_ids = sorted({llm.model_id("terra"), llm.model_id("sol")})
    backend = os.getenv("LLM_BACKEND", "bedrock").strip().lower() or "bedrock"
    model_label = " + ".join(model_ids)
    runs_note = "" if runs == 1 else f", aggregated over {runs} runs"
    report_out = {
        "benchmark_version": "0.1",
        "mode": f"cached live result ({model_label} via {backend}{runs_note})",
        "backend": backend,
        "model_ids": model_ids,
        "disclosure": (
            f"This cached benchmark result was produced by a real live run of Steward's "
            f"enrichment pipeline ({model_label} via the {backend} backend) against the "
            "committed labeled scenario fleet. Replays and CI re-verify this cache; they "
            "never call a model."
        ),
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "enrichment_status": enrichment.get("status"),
        # Always state how many live runs produced this cache, so a reader never
        # has to guess whether the numbers are one sample or an aggregate.
        "runs": runs,
        **report,
        "surfaced_findings": llm_findings,
    }
    if runs > 1:
        report_out["runs_aggregate"] = aggregate_metrics(per_run_metrics)
    # Guard against the id-level redaction corruption the demo-cache regen
    # script exists to avoid. Model prose may legitimately contain a redaction
    # marker (narratives pass through redact_text), so only ids are checked.
    structural_ids = [
        value
        for finding in report_out["surfaced_findings"]
        for value in (
            str(finding.get("id", "")),
            str(finding.get("agent_id", "")),
            *(str(item.get("entity_id", "")) for item in finding.get("evidence", [])),
        )
    ] + [
        value
        for record in report_out["raw_proposals"]["records"]
        for value in (str(record.get("proposed_agent_id", "")), *map(str, record.get("tool_ids", [])))
    ]
    if any("[REDACTED]" in identifier for identifier in structural_ids):
        raise BenchmarkError("Unexpected id-level redaction corruption in benchmark result dump.")
    output_path.write_text(json.dumps(report_out, indent=1) + "\n", encoding="utf-8")
    _print_report(report_out)
    print(f"OK: wrote {output_path}")
    return 0


def verify_cached(results_path: Path = RESULTS_PATH) -> int:
    """Re-verify the committed cached result without any model call."""

    scenarios = load_scenarios()
    cached = json.loads(results_path.read_text(encoding="utf-8"))
    fleet_doc = json.loads(FLEET_PATH.read_text(encoding="utf-8"))
    tools_doc = json.loads(TOOLS_PATH.read_text(encoding="utf-8"))
    recomputed = score(
        scenarios,
        cached.get("surfaced_findings", []),
        fleet_doc,
        tools_doc,
        [
            {key: record.get(key) for key in ("subject_agent_id", "proposed_agent_id", "tool_ids")}
            for record in cached.get("raw_proposals", {}).get("records", [])
        ],
    )
    problems: list[str] = []
    if recomputed["metrics"] != cached.get("metrics"):
        problems.append("cached metrics do not match metrics recomputed from cached findings")
    if recomputed["scenario_outcomes"] != cached.get("scenario_outcomes"):
        problems.append("cached scenario outcomes do not match cached findings")
    if recomputed["metrics"]["hallucinated_surfaced_findings"] != 0:
        problems.append("cached result contains a surfaced finding with invalid citations")
    _print_report({**cached, **recomputed})
    for problem in problems:
        print(f"BENCHMARK_ERROR: {problem}")
    print(f"BENCHMARK CACHE: {'VERIFIED' if not problems else 'INCONSISTENT'}")
    return 0 if not problems else 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--live",
        action="store_true",
        help="Run the real enrichment pipeline on the configured backend and write the result.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=RESULTS_PATH,
        help="Where a --live run writes its result. Point elsewhere for A/B runs so the "
        "committed cache is untouched; verification always reads the committed cache.",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=1,
        help="With --live: run the benchmark this many times and record mean/min/max per "
        "metric in the provenance, so the numbers reflect spread, not a single sample.",
    )
    args = parser.parse_args(argv)
    try:
        return run_live(args.output, runs=args.runs) if args.live else verify_cached()
    except Exception as exc:
        print(f"BENCHMARK_ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover - exercised via make llm-benchmark
    raise SystemExit(main())
