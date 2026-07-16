from __future__ import annotations

from steward.llm import BedrockLLM, CostLatencyLogger, classify_tools, identify_toxic_combinations


class CapturingBedrockClient:
    def __init__(self) -> None:
        self.request = None

    def converse(self, **kwargs):  # type: ignore[no-untyped-def]
        self.request = kwargs
        return {"output": {"message": {"content": [{"text": '{"status":"ok"}'}]}}}


def test_secret_is_absent_from_outbound_prompt_and_cost_log(tmp_path, monkeypatch) -> None:
    planted_secret = "sk-THIS_IS_A_PLANTED_SECRET_9J4sP0kLmN7qR2xV"
    client = CapturingBedrockClient()
    logger = CostLatencyLogger(path=tmp_path / "cost_latency.jsonl")
    llm = BedrockLLM(logger=logger, max_attempts=1)
    llm._client = client
    monkeypatch.setenv("MODEL_TERRA", "example.model-terra")

    result = llm.call_json(
        operation="test_redaction",
        tier="terra",
        system_instruction="Return JSON.",
        payload={
            "mcpServers": {
                "customer-system": {
                    "command": "python",
                    "args": ["--token=" + planted_secret],
                    "env": {"OPENAI_API_KEY": planted_secret, "REGION": "us-east-1"},
                }
            }
        },
    )

    assert result == {"status": "ok"}
    outbound = client.request["messages"][0]["content"][0]["text"]
    assert planted_secret not in outbound
    assert "[REDACTED]" in outbound
    assert planted_secret not in logger.path.read_text(encoding="utf-8")


def test_toxic_combination_payload_is_redacted_before_the_llm_boundary(tmp_path, monkeypatch) -> None:
    """The new model-finding path receives the same secret-safe payload treatment."""

    planted_secret = "Bearer steward-PLANTED_TOKEN_z4K1m7Qp9X"
    client = CapturingBedrockClient()
    logger = CostLatencyLogger(path=tmp_path / "cost_latency.jsonl")
    llm = BedrockLLM(logger=logger, max_attempts=1)
    llm._client = client
    monkeypatch.setenv("MODEL_SOL", "example.model-sol")

    result = identify_toxic_combinations(
        llm,
        {
            "agents": [
                {
                    "agent_id": "sales_bot",
                    "effective_tool_ids": ["read_crm", "send_external_email"],
                    "notes": f"authorization={planted_secret}",
                }
            ],
            "tools": [
                {
                    "tool_id": "read_crm",
                    "name": "CRM reader",
                    "business_capability": f"customer records ({planted_secret})",
                }
            ],
        },
    )

    assert result == {"status": "ok"}
    outbound = client.request["messages"][0]["content"][0]["text"]
    assert planted_secret not in outbound
    assert "[REDACTED]" in outbound
    assert planted_secret not in logger.path.read_text(encoding="utf-8")


def test_batched_tool_classification_payload_is_redacted_before_the_llm_boundary(
    tmp_path, monkeypatch
) -> None:
    """Small classifier batches retain structure but never send a tool-description secret."""

    planted_secret = "sk-CLASSIFICATION_BATCH_SECRET_1a2B3c4D5e6F"
    client = CapturingBedrockClient()
    logger = CostLatencyLogger(path=tmp_path / "cost_latency.jsonl")
    llm = BedrockLLM(logger=logger, max_attempts=1)
    llm._client = client
    monkeypatch.setenv("MODEL_TERRA", "example.gpt-oss-120b")

    result = classify_tools(
        llm,
        [
            {
                "tool_id": f"tool_{index}",
                "name": f"Tool {index}",
                "description": (
                    f"classification note token={planted_secret}" if index == 3 else "safe metadata"
                ),
            }
            for index in range(6)
        ],
        max_tokens=1_800,
    )

    assert result == {"status": "ok"}
    assert client.request["inferenceConfig"]["maxTokens"] == 1_800
    outbound = client.request["messages"][0]["content"][0]["text"]
    assert planted_secret not in outbound
    assert "[REDACTED]" in outbound
    assert '"tool_id":"tool_5"' in outbound
    assert planted_secret not in logger.path.read_text(encoding="utf-8")
