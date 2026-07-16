"""Offline, deterministic stand-in for the constrained model enrichment path.

The eval must exercise the same optional pipeline integration a live Bedrock
run uses, without credentials or a network call.  ``OfflineLlmFixture`` is a
small structural substitute for :class:`steward.llm.BedrockLLM`:

* ``model_id(tier) -> str`` tells the pipeline that the requested tier exists.
* ``call_json(operation=..., payload=..., tier=..., ...) -> object`` returns
  the structured JSON response for that operation.

It deliberately retains only operation names (not prompt payloads) so an eval
fixture cannot turn into a configuration/credential log.  The one toxic-pair
proposal is SalesBot's CRM-read plus external-email combination, which lies
outside the deterministic crown-jewel rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class OfflineLlmFixture:
    """Return fixed, metadata-only responses through the BedrockLLM protocol."""

    operations: list[str] = field(default_factory=list)

    def model_id(self, tier: str) -> str:
        """Satisfy the pipeline's availability check without consulting env vars."""

        return f"offline-eval-model-{tier}"

    def call_json(
        self,
        *,
        operation: str,
        payload: Any,
        tier: str = "terra",
        system_instruction: str = "",
        max_tokens: int = 1_500,
    ) -> dict[str, Any]:
        """Return the expected structured response without retaining the prompt.

        ``payload``, ``tier``, ``system_instruction``, and ``max_tokens`` are
        accepted to mirror ``BedrockLLM.call_json``.  They are intentionally
        not persisted or printed; live configuration metadata belongs behind
        the redaction boundary, even in test helpers.
        """

        del payload, tier, system_instruction, max_tokens
        self.operations.append(operation)
        if operation == "tool_classification":
            return {
                "capabilities": [
                    {
                        "tool_id": "read_crm",
                        "business_capability": "reads customer and prospect account context",
                    },
                    {
                        "tool_id": "send_external_email",
                        "business_capability": "sends messages to recipients outside the company",
                    },
                ]
            }
        if operation == "needed_access_inference":
            return {
                "agents": [
                    {
                        "agent_id": "sales_bot",
                        "needed_capabilities": ["read account context for sales outreach"],
                        "needed_tool_ids": ["read_crm"],
                    }
                ]
            }
        if operation == "toxic_combination_reasoning":
            return {
                "pairs": [
                    {
                        "agent_id": "sales_bot",
                        "tool_ids": ["read_crm", "send_external_email"],
                        "reason": (
                            "The agent can read customer relationship context and transmit it to external "
                            "recipients, creating a customer-data egress path without an independent review."
                        ),
                    }
                ]
            }
        if operation == "finding_narrative":
            return {
                "business_risk": "The cited access path can expand the agent's practical blast radius.",
                "recommended_action": (
                    "Separate the cited capabilities behind an independently reviewed workflow."
                ),
                # The pipeline will retain its deterministic prose unless a
                # model response proves grounding. An empty response here
                # intentionally exercises that safe fallback without needing
                # to inspect or retain the finding payload.
                "cited_entity_ids": [],
            }
        return {}
