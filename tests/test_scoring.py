"""Tests for the deterministic composite risk score and ranking."""

from __future__ import annotations

from steward.findings import analyze_fleet
from steward.graph import EffectiveAccessGraph
from steward.loaders import load_inventory
from steward.reporting import build_certification_packet, normalize_findings
from steward.scoring import score_and_rank_findings, score_finding


def _analyzed():
    fleet, tools = load_inventory("data/fleet.json", "data/tools.json")
    return analyze_fleet(fleet, tools)


def test_every_finding_is_scored_with_a_recomputable_breakdown() -> None:
    result = _analyzed()
    assert result.findings
    for finding in result.findings:
        assert finding.risk_score is not None
        assert 0 < finding.risk_score <= 100
        # The breakdown must sum to the (uncapped) score so an auditor can
        # recompute it by hand.
        assert finding.risk_score == min(sum(finding.risk_factors.values()), 100)
        assert set(finding.risk_factors) == {
            "base_severity",
            "blast_radius",
            "data_sensitivity",
            "exploitability",
            "untrusted_exposure",
        }


def test_scoring_is_deterministic_across_runs() -> None:
    first = {f.id: (f.risk_score, f.risk_factors) for f in _analyzed().findings}
    second = {f.id: (f.risk_score, f.risk_factors) for f in _analyzed().findings}
    assert first == second
    assert [f.id for f in _analyzed().findings] == [f.id for f in _analyzed().findings]


def test_direct_grant_scores_higher_than_delegated_reach() -> None:
    """SupportBot holds its exfil pair directly; SummaryBot only reaches
    payment approval through delegation — exploitability must reflect that."""

    result = _analyzed()
    by_id = {finding.id: finding for finding in result.findings}
    support = next(f for f in result.findings if f.agent_id == "support_bot" and f.check_type == "sod")
    summary = next(f for f in result.findings if f.agent_id == "summary_bot")
    assert support.risk_factors["exploitability"] == 10
    assert summary.risk_factors["exploitability"] == 5
    assert by_id  # ranking sanity below
    scores = [f.risk_score or 0 for f in result.findings]
    assert scores == sorted(scores, reverse=True)


def test_rescoring_is_idempotent() -> None:
    fleet, tools = load_inventory("data/fleet.json", "data/tools.json")
    result = analyze_fleet(fleet, tools)
    graph = EffectiveAccessGraph(fleet)
    rescored = score_and_rank_findings(result.findings, fleet, graph)
    assert [(f.id, f.risk_score) for f in rescored] == [
        (f.id, f.risk_score) for f in result.findings
    ]
    one = score_finding(result.findings[0], graph)
    assert one.risk_score == result.findings[0].risk_score


def test_report_and_review_queue_rank_by_score() -> None:
    result = _analyzed()
    public = normalize_findings(result.findings)
    public_scores = [item.get("risk_score") or 0 for item in public]
    assert public_scores == sorted(public_scores, reverse=True)

    packet = build_certification_packet(
        result.fleet, public, effective_access=result.effective_access
    )
    card_scores = [card["top_risk_score"] for card in packet["risk_cards"]]
    assert card_scores == sorted(card_scores, reverse=True)
    # The highest-ranked review card belongs to an agent with findings.
    assert packet["risk_cards"][0]["findings"]
