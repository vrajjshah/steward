"""Focused regression coverage for the separate offline LLM-tier measurement."""

from __future__ import annotations

from evals.llm_fixture import OfflineLlmFixture
from evals.run import evaluate


def test_offline_fixture_recovers_novel_salesbot_pair_without_affecting_floor() -> None:
    result = evaluate()

    assert result.deterministic_passed
    assert result.llm_tier is not None
    assert result.llm_tier.citations.valid
    assert result.llm_tier.meets_measurement_thresholds
    sales_metric = result.llm_tier.metrics["sod"]
    assert sales_metric.expected == 1
    assert sales_metric.actual == 1
    assert sales_metric.precision == 1.0
    assert sales_metric.recall == 1.0


def test_offline_fixture_keeps_prompt_payload_out_of_its_state() -> None:
    fixture = OfflineLlmFixture()
    planted_value = "sk-NOT_A_REAL_SECRET_9J4sP0kLmN7qR2xV"

    response = fixture.call_json(
        operation="toxic_combination_reasoning",
        payload={"api_key": planted_value},
        tier="sol",
        system_instruction="fixture only",
    )

    assert response["pairs"][0]["agent_id"] == "sales_bot"
    assert fixture.operations == ["toxic_combination_reasoning"]
    assert planted_value not in repr(fixture)
