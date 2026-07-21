"""Tests for pluggable model backends: selection, redaction, and compatibility."""

from __future__ import annotations

import json

import pytest

from steward.llm import (
    BedrockLLM,
    LLMUnavailableError,
    OpenAICompatibleLLM,
    create_llm,
)


def test_backend_selection_defaults_to_bedrock(monkeypatch) -> None:
    monkeypatch.delenv("LLM_BACKEND", raising=False)
    assert isinstance(create_llm(), BedrockLLM)


@pytest.mark.parametrize("alias", ["ollama", "openai", "openai-compatible", "local", "OLLAMA"])
def test_backend_aliases_select_the_openai_compatible_client(monkeypatch, alias) -> None:
    monkeypatch.setenv("LLM_BACKEND", alias)
    assert isinstance(create_llm(), OpenAICompatibleLLM)


def test_unknown_backend_is_a_clear_configuration_error(monkeypatch) -> None:
    monkeypatch.setenv("LLM_BACKEND", "carrier-pigeon")
    with pytest.raises(LLMUnavailableError, match="LLM_BACKEND"):
        create_llm()


def test_openai_compatible_defaults_to_local_ollama(monkeypatch) -> None:
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    llm = OpenAICompatibleLLM()
    assert llm._endpoint() == "http://localhost:11434/v1/chat/completions"
    monkeypatch.setenv("LLM_BASE_URL", "https://api.example.com/v1/")
    assert llm._endpoint() == "https://api.example.com/v1/chat/completions"


def test_openai_compatible_redacts_before_the_wire(tmp_path, monkeypatch) -> None:
    """The local backend gets the identical secret-safety boundary as Bedrock."""

    planted_secret = "sk-THIS_IS_A_PLANTED_SECRET_9J4sP0kLmN7qR2xV"
    sent_bodies: list[bytes] = []

    from steward.llm import CostLatencyLogger

    llm = OpenAICompatibleLLM(
        logger=CostLatencyLogger(path=tmp_path / "cost.jsonl"), max_attempts=1
    )
    monkeypatch.setenv("MODEL_TERRA", "llama3.1")

    def fake_send(body: bytes) -> str:
        sent_bodies.append(body)
        return json.dumps({"choices": [{"message": {"content": '{"status":"ok"}'}}]})

    monkeypatch.setattr(llm, "_send", fake_send)
    result = llm.call_json(
        operation="test_redaction",
        tier="terra",
        system_instruction="Return JSON.",
        payload={
            "mcpServers": {
                "customer-system": {
                    "env": {"OPENAI_API_KEY": planted_secret, "REGION": "us-east-1"}
                }
            }
        },
    )

    assert result == {"status": "ok"}
    outbound = sent_bodies[0].decode("utf-8")
    assert planted_secret not in outbound
    assert "[REDACTED]" in outbound
    assert '"model": "llama3.1"' in outbound
    assert planted_secret not in (tmp_path / "cost.jsonl").read_text(encoding="utf-8")


def test_openai_compatible_requires_configured_model(monkeypatch) -> None:
    # A set env var beats load_dotenv(override=False), so the placeholder
    # reliably simulates an unconfigured tier even when a local .env exists.
    monkeypatch.setenv("MODEL_SOL", "replace-with-bedrock-model-id-sol")
    with pytest.raises(LLMUnavailableError, match="MODEL_SOL"):
        OpenAICompatibleLLM().model_id("sol")


def test_bedrock_omits_temperature_for_claude_models(tmp_path, monkeypatch) -> None:
    """Claude on Bedrock (Opus 4.7+) rejects sampling parameters; gpt-oss keeps
    the deterministic temperature=0 request."""

    class CapturingClient:
        def __init__(self) -> None:
            self.request = None

        def converse(self, **kwargs):  # type: ignore[no-untyped-def]
            self.request = kwargs
            return {"output": {"message": {"content": [{"text": '{"status":"ok"}'}]}}}

    from steward.llm import CostLatencyLogger

    for model_id, expects_temperature in (
        ("openai.gpt-oss-120b-1:0", True),
        ("us.anthropic.claude-opus-4-8-v1:0", False),
        ("anthropic.claude-opus-4-8", False),
    ):
        client = CapturingClient()
        llm = BedrockLLM(
            max_attempts=1, logger=CostLatencyLogger(path=tmp_path / "cost.jsonl")
        )
        llm._client = client
        monkeypatch.setenv("MODEL_TERRA", model_id)
        llm.call_json(
            operation="test", tier="terra", system_instruction="Return JSON.", payload={}
        )
        config = client.request["inferenceConfig"]
        assert ("temperature" in config) is expects_temperature, model_id
