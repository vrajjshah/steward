"""The single, redaction-first gateway to Amazon Bedrock.

Steward never sends agent payload data to a model.  This module accepts only
configuration metadata and defensively redacts it again at the boundary before
serializing a request.  Deterministic checks never depend on this module.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from steward.redaction import redact_for_llm

LOGGER = logging.getLogger(__name__)

DEFAULT_SOL = "replace-with-bedrock-model-id-sol"
DEFAULT_TERRA = "replace-with-bedrock-model-id-terra"
DEFAULT_LUNA = "replace-with-bedrock-model-id-luna"


class LLMUnavailableError(RuntimeError):
    """Raised when live enrichment was requested without a configured model."""


def redact_value(value: Any, key: str | None = None) -> Any:
    """Return metadata safe for prompts, logs, and cached outputs.

    The canonical redaction implementation lives in :mod:`steward.redaction`.
    Retaining this small compatibility wrapper makes callers explicit about the
    LLM boundary while ensuring adapters and model calls use identical rules.
    """

    if key is None:
        return redact_for_llm(value)
    return redact_for_llm({key: value}).get(key)


def safe_json_payload(payload: Any) -> str:
    """Serialize a redacted metadata payload for a model request."""

    return json.dumps(
        redact_for_llm(payload), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def _extract_json(text: str) -> Any:
    """Accept strict JSON or a JSON object/array wrapped in markdown fences."""

    candidate = text.strip()
    if candidate.startswith("```"):
        candidate = re.sub(r"^```(?:json)?\s*|\s*```$", "", candidate, flags=re.I | re.S).strip()
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        match = re.search(r"(\{.*\}|\[.*\])", candidate, flags=re.S)
        if not match:
            raise
        return json.loads(match.group(1))


@dataclass
class CostLatencyLogger:
    """Append only operational facts, never prompts, configuration, or secrets."""

    path: Path = field(default_factory=lambda: Path("data/cost_latency.jsonl"))

    def record(
        self,
        *,
        operation: str,
        model_id: str,
        elapsed_ms: int,
        status: Literal["ok", "error"],
        input_chars: int,
        output_chars: int = 0,
    ) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        event = {
            "operation": operation,
            "model_id": model_id,
            "elapsed_ms": elapsed_ms,
            "status": status,
            "input_chars": input_chars,
            "output_chars": output_chars,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")


@dataclass
class BedrockLLM:
    """Small Bedrock Converse client with bounded retries and JSON responses."""

    region_name: str | None = None
    timeout_seconds: int = 30
    max_attempts: int = 3
    logger: CostLatencyLogger = field(default_factory=CostLatencyLogger)
    _client: Any = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        """Load local model configuration without overriding real environment values."""

        try:
            from dotenv import load_dotenv
        except ImportError:  # pragma: no cover - optional convenience dependency
            return
        load_dotenv(override=False)

    def model_id(self, tier: Literal["sol", "terra", "luna"]) -> str:
        defaults = {"sol": DEFAULT_SOL, "terra": DEFAULT_TERRA, "luna": DEFAULT_LUNA}
        value = os.getenv(f"MODEL_{tier.upper()}", defaults[tier]).strip()
        if not value or value == defaults[tier] or value.startswith("replace-with-"):
            raise LLMUnavailableError(
                f"MODEL_{tier.upper()} is not configured. Set it to an enabled Bedrock model ID, "
                "or set STEWARD_DEMO=1."
            )
        return value

    def _bedrock_client(self) -> Any:
        if self._client is None:
            try:
                import boto3
                from botocore.config import Config
            except ImportError as exc:  # pragma: no cover - packaging guard
                raise LLMUnavailableError("boto3 is required for live Bedrock enrichment.") from exc
            self._client = boto3.client(
                "bedrock-runtime",
                region_name=self.region_name or os.getenv("AWS_REGION"),
                config=Config(
                    connect_timeout=self.timeout_seconds, read_timeout=self.timeout_seconds
                ),
            )
        return self._client

    def call_json(
        self,
        *,
        operation: str,
        payload: Any,
        tier: Literal["sol", "terra", "luna"] = "terra",
        system_instruction: str,
        max_tokens: int = 1_500,
    ) -> Any:
        """Make a redacted structured-output request through Converse.

        A valid JSON object or array is required.  Errors are retried with a
        short exponential backoff and surfaced to callers so deterministic
        analysis can still complete without fabricated enrichment.
        """

        model_id = self.model_id(tier)
        serialized = safe_json_payload(payload)
        prompt = (
            "Analyze only the following redacted configuration metadata. Do not infer data values, "
            "credentials, or events. Return valid JSON only.\n\nMETADATA:\n" + serialized
        )
        last_error: Exception | None = None
        for attempt in range(self.max_attempts):
            started = time.monotonic()
            try:
                response = self._bedrock_client().converse(
                    modelId=model_id,
                    system=[{"text": system_instruction}],
                    messages=[{"role": "user", "content": [{"text": prompt}]}],
                    inferenceConfig={"maxTokens": max_tokens, "temperature": 0},
                )
                text = "".join(
                    block.get("text", "")
                    for block in response.get("output", {}).get("message", {}).get("content", [])
                    if isinstance(block, dict)
                )
                parsed = _extract_json(text)
                self.logger.record(
                    operation=operation,
                    model_id=model_id,
                    elapsed_ms=int((time.monotonic() - started) * 1000),
                    status="ok",
                    input_chars=len(serialized),
                    output_chars=len(text),
                )
                return parsed
            except (
                Exception
            ) as exc:  # runtime SDK and model errors are intentionally contained here
                last_error = exc
                self.logger.record(
                    operation=operation,
                    model_id=model_id,
                    elapsed_ms=int((time.monotonic() - started) * 1000),
                    status="error",
                    input_chars=len(serialized),
                )
                if attempt + 1 < self.max_attempts:
                    time.sleep(0.35 * (2**attempt))
        raise RuntimeError(
            f"Bedrock {operation} failed after {self.max_attempts} attempts"
        ) from last_error


TOOL_CLASSIFICATION_SYSTEM = """You are a governance analyst. Classify each tool by its business
capability using only its name and description. Return JSON: {\"capabilities\": [{\"tool_id\": str,
\"business_capability\": str}]}. Return one entry for every supplied tool and do not invent tools.
Make each capability a concrete action plus business object or destination (for example, \"reads CRM
customer account records\" or \"sends messages to external recipients\"), not a vague product label."""

NEEDED_CAPABILITIES_SYSTEM = """You are an identity-governance analyst. Infer the minimum business
capabilities needed for each declared agent purpose. Return JSON: {\"agents\": [{\"agent_id\": str,
\"needed_capabilities\": [str], \"rationale\": str}]}. Do not assume access is needed merely because it
exists in the configuration."""

NEEDED_ACCESS_SYSTEM = """You are an identity-governance analyst. Infer the minimum capabilities
needed for each agent's declared purpose. Use only the declared purpose and the supplied candidate capability
catalog; do not infer need from current grants. Return JSON: {\"agents\": [{\"agent_id\": str,
\"needed_capabilities\": [str], \"needed_tool_ids\": [str], \"rationale\": str}]}. `needed_tool_ids`
must be a subset of the supplied candidate catalog and is review context, not a finding. Do not invent IDs."""

TOXIC_COMBINATIONS_SYSTEM = """You are a segregation-of-duties analyst. Given inferred business
capabilities and the seeded principles (finance initiate-vs-approve, HR hire-vs-pay, IT request-vs-grant),
identify only additional toxic combinations supported by the supplied configuration. The seeded principles
are handled by the deterministic floor; this incremental v0.1 pass must propose only a separately supported
external data-egress pair. Return a pair only when one tool explicitly reads CRM, customer, PII, personnel,
confidential, or other sensitive business records and the other tool explicitly sends, exports, uploads, or
publishes information outside the organization. Do not treat internal updates, deletes, ticket creation,
search, summarization, recommendations, or draft-only email as external delivery, and do not propose those
pairs. Return JSON:
{\"pairs\": [{\"agent_id\": str, \"tool_ids\": [str, str], \"reason\": str}]}. Never name an entity absent
from the metadata."""

NARRATIVE_SYSTEM = """You are writing a concise, auditor-facing business-risk narrative for a
citation-verified agent-governance finding. Explain the practical blast radius and why the cited access matters.
Return JSON: {\"business_risk\": str, \"recommended_action\": str}. Use only cited entities supplied."""

GROUNDED_NARRATIVE_SYSTEM = """You are writing a concise, auditor-facing business-risk narrative
for a citation-verified agent-governance finding. Explain only the practical blast radius supported by the
supplied evidence. Return JSON: {\"business_risk\": str, \"recommended_action\": str,
\"cited_entity_ids\": [str]}. `cited_entity_ids` must be a non-empty subset of the supplied evidence IDs.
Do not name or assume any entity, data value, event, or control that is not supplied."""


def classify_tools(
    llm: BedrockLLM,
    tools: list[dict[str, Any]],
    *,
    max_tokens: int = 1_500,
) -> Any:
    """Classify a bounded tool batch.

    Callers deliberately keep batches small so one malformed or truncated model
    response cannot erase the fleet's entire capability map.  The redaction
    boundary remains :meth:`BedrockLLM.call_json`.
    """

    return llm.call_json(
        operation="tool_classification",
        payload={"tools": tools},
        tier="terra",
        system_instruction=TOOL_CLASSIFICATION_SYSTEM,
        max_tokens=max_tokens,
    )


def infer_needed_capabilities(llm: BedrockLLM, agents: list[dict[str, Any]]) -> Any:
    return llm.call_json(
        operation="needed_capabilities",
        payload={"agents": agents},
        tier="terra",
        system_instruction=NEEDED_CAPABILITIES_SYSTEM,
    )


def infer_needed_access(
    llm: BedrockLLM,
    agents: list[dict[str, Any]],
    capability_catalog: list[dict[str, Any]],
) -> Any:
    """Infer declared need and a constrained candidate-tool mapping."""

    return llm.call_json(
        operation="needed_access_inference",
        payload={"agents": agents, "capability_catalog": capability_catalog},
        tier="terra",
        system_instruction=NEEDED_ACCESS_SYSTEM,
    )


def identify_toxic_combinations(llm: BedrockLLM, payload: dict[str, Any]) -> Any:
    return llm.call_json(
        operation="toxic_combination_reasoning",
        payload=payload,
        tier="sol",
        system_instruction=TOXIC_COMBINATIONS_SYSTEM,
    )


def narrate_finding(llm: BedrockLLM, payload: dict[str, Any]) -> Any:
    return llm.call_json(
        operation="finding_narrative",
        payload=payload,
        tier="sol",
        system_instruction=GROUNDED_NARRATIVE_SYSTEM,
        max_tokens=700,
    )
