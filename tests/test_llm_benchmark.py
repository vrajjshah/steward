"""CI-safe checks for the labeled LLM-tier accuracy benchmark.

These tests never call Bedrock. They prove the benchmark inventory isolates
the model tier (deterministically silent), the labels and fleet stay in sync,
and the committed cached live result remains internally consistent with zero
hallucinated citations.
"""

from __future__ import annotations

import json

from evals.llm_benchmark import (
    FLEET_PATH,
    LABEL_VALUES,
    RESULTS_PATH,
    TOOLS_PATH,
    load_scenarios,
    score,
    validate_benchmark_inventory,
    verify_cached,
)
from evals.run import validate_citations
from steward.findings import analyze_fleet
from steward.loaders import load_inventory


def test_benchmark_inventory_is_valid_and_labeled_one_to_one() -> None:
    scenarios = load_scenarios()
    fleet, tools = load_inventory(FLEET_PATH, TOOLS_PATH)
    validate_benchmark_inventory(fleet, scenarios)
    assert len(scenarios) == 20
    by_label = {label: [s for s in scenarios if s.label == label] for label in LABEL_VALUES}
    assert len(by_label["toxic_in_scope"]) == 8
    assert len(by_label["benign"]) == 8
    assert len(by_label["toxic_out_of_scope"]) == 4


def test_benchmark_fleet_is_deterministically_silent() -> None:
    """Every benchmark finding must come from the model tier, not the floor."""

    fleet, tools = load_inventory(FLEET_PATH, TOOLS_PATH)
    result = analyze_fleet(fleet, tools)
    assert result.findings == []


def test_cached_live_result_is_consistent_with_zero_hallucinations() -> None:
    assert verify_cached() == 0
    cached = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
    fleet_doc = json.loads(FLEET_PATH.read_text(encoding="utf-8"))
    tools_doc = json.loads(TOOLS_PATH.read_text(encoding="utf-8"))
    surfaced = cached["surfaced_findings"]
    # Every cached surfaced finding must pass the same graph-citation check
    # the production pipeline enforces.
    for finding in surfaced:
        assert validate_citations([finding], fleet_doc, tools_doc).valid
        assert finding["source"] == "llm_generalized"
    assert cached["metrics"]["hallucinated_surfaced_findings"] == 0
    assert cached["metrics"]["hallucinated_citation_rate"] == 0.0


def test_score_counts_a_benign_flag_as_false_positive() -> None:
    """The scoring function itself must not grade on a curve."""

    scenarios = load_scenarios()
    fleet_doc = json.loads(FLEET_PATH.read_text(encoding="utf-8"))
    tools_doc = json.loads(TOOLS_PATH.read_text(encoding="utf-8"))
    fabricated = {
        "source": "llm_generalized",
        "agent_id": "account_digest_bot",
        "check_type": "sod",
        "evidence": [
            {"entity_type": "agent", "entity_id": "account_digest_bot", "detail": "subject"},
            {"entity_type": "tool", "entity_id": "read_customer_accounts", "detail": "granted"},
            {"entity_type": "tool", "entity_id": "send_internal_digest", "detail": "granted"},
        ],
    }
    report = score(scenarios, [fabricated], fleet_doc, tools_doc)
    assert report["metrics"]["false_positive"] == 1
    assert report["metrics"]["true_positive"] == 0
    # The fabricated finding cites real granted tools, so it is not a
    # hallucination — it is a precision failure.
    assert report["metrics"]["hallucinated_surfaced_findings"] == 0
