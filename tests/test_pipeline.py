from __future__ import annotations

import copy
import json
from typing import Any

from steward.findings import citation_errors
from steward.graph import EffectiveAccessGraph
from steward.llm import BedrockLLM, CostLatencyLogger
from steward.loaders import load_inventory
from steward.pipeline import analyze_fleet


class EnrichmentClient:
    """A Bedrock Converse stand-in that returns constrained structured output."""

    def converse(self, **kwargs):  # type: ignore[no-untyped-def]
        system = kwargs["system"][0]["text"]
        if "Classify each tool" in system:
            payload = {
                "capabilities": [
                    {"tool_id": "read_customer_pii", "business_capability": "reads customer PII"},
                    {
                        "tool_id": "send_external_email",
                        "business_capability": "sends external email",
                    },
                    {"tool_id": "approve_payment", "business_capability": "approves payments"},
                ]
            }
        elif "needed_tool_ids" in system:
            payload = {
                "agents": [
                    {
                        "agent_id": "support_bot",
                        "needed_capabilities": ["read customer support case context"],
                        "needed_tool_ids": ["read_customer_pii"],
                    },
                    {
                        "agent_id": "legacy_bot",
                        "needed_capabilities": [],
                        "needed_tool_ids": [],
                    },
                ]
            }
        elif "additional toxic combinations" in system:
            # The first repeats a hard-coded pair; the second invents entities.
            # Neither is allowed to become a new finding.
            payload = {
                "pairs": [
                    {
                        "agent_id": "support_bot",
                        "tool_ids": ["read_customer_pii", "send_external_email"],
                        "reason": "Could expose customer data externally.",
                    },
                    {
                        "agent_id": "invented_agent",
                        "tool_ids": ["invented_tool", "send_external_email"],
                        "reason": "This is not grounded in the graph.",
                    },
                ]
            }
        else:
            payload = {
                "business_risk": "The cited access path can expand the agent's practical blast radius.",
                "recommended_action": "Separate the cited capabilities behind an independently reviewed workflow.",
                "cited_entity_ids": ["support_bot", "read_customer_pii"],
            }
        return {"output": {"message": {"content": [{"text": json.dumps(payload)}]}}}


class GeneralizationFixture:
    """Offline stand-in that exercises the model-proposal boundary, not AWS."""

    def model_id(self, tier: str) -> str:
        return f"fixture-{tier}"

    def call_json(
        self,
        *,
        operation: str,
        payload: dict[str, object] | None = None,
        **_: object,
    ) -> dict[str, object]:
        if operation == "tool_classification":
            return {
                "capabilities": [
                    {
                        "tool_id": "read_crm",
                        "business_capability": "reads customer account records and opportunity notes",
                    },
                    {
                        "tool_id": "send_external_email",
                        "business_capability": "sends messages to recipients outside the company",
                    },
                ]
            }
        if operation == "needed_access_inference":
            return {"agents": []}
        if operation == "toxic_combination_reasoning":
            agent_id = payload["agent"]["agent_id"] if payload else None
            if agent_id == "sales_bot":
                return {
                    "pairs": [
                        {
                            "agent_id": "sales_bot",
                            "tool_ids": ["read_crm", "send_external_email"],
                            "reason": (
                                "Reading customer account context and transmitting it outside the company can "
                                "create an unreviewed customer-data egress path."
                            ),
                        }
                    ]
                }
            if agent_id == "support_bot":
                return {
                    "pairs": [
                        {
                            "agent_id": "support_bot",
                            "tool_ids": ["read_customer_pii", "send_external_email"],
                            "reason": "Duplicate of the existing deterministic path.",
                        }
                    ]
                }
            return {
                "pairs": [
                    # Unknown graph entities must never become a finding.
                    {
                        "agent_id": "not_a_real_agent",
                        "tool_ids": ["read_crm", "not_a_real_tool"],
                        "reason": "Ungrounded proposal.",
                    },
                ]
            }
        return {}


class PayloadRecordingLLM:
    """Offline model double that records only the pipeline payloads it receives."""

    def __init__(self, planted_secret: str) -> None:
        self.planted_secret = planted_secret
        self.calls: list[dict[str, Any]] = []

    def model_id(self, tier: str) -> str:
        return f"recording-fixture-{tier}"

    def call_json(
        self,
        *,
        operation: str,
        payload: dict[str, Any],
        **_: object,
    ) -> dict[str, object]:
        self.calls.append({"operation": operation, "payload": copy.deepcopy(payload)})
        if operation == "tool_classification":
            capabilities = []
            for tool in payload["tools"]:
                tool_id = tool["tool_id"]
                capability = f"performs {tool_id.replace('_', ' ')}"
                # Model output is untrusted too: this exercises the boundary
                # between classification and the later toxic-pair payload.
                if tool_id == "read_crm":
                    capability = f"reads customer records ({self.planted_secret})"
                capabilities.append({"tool_id": tool_id, "business_capability": capability})
            return {"capabilities": capabilities}
        if operation == "needed_access_inference":
            return {"agents": []}
        if operation == "toxic_combination_reasoning":
            agent_id = payload["agent"]["agent_id"]
            if agent_id == "sales_bot":
                return {
                    "pairs": [
                        {
                            "agent_id": "sales_bot",
                            "tool_ids": ["read_crm", "send_external_email"],
                            "reason": "The two cited capabilities can create external customer-data egress.",
                        }
                    ]
                }
            if agent_id == "access_bot":
                # A model response can be malicious or simply confused.  It
                # must not be able to submit a SalesBot finding from an
                # AccessBot-scoped reasoning request.
                return {
                    "pairs": [
                        {
                            "agent_id": "sales_bot",
                            "tool_ids": ["read_crm", "send_external_email"],
                            "reason": "Deliberately out-of-scope proposal.",
                        }
                    ]
                }
            return {"pairs": []}
        return {}


class PartialEnrichmentFixture:
    """Exercises explicit fallback and per-agent incompleteness metadata."""

    def model_id(self, tier: str) -> str:
        return f"partial-fixture-{tier}"

    def call_json(
        self,
        *,
        operation: str,
        payload: dict[str, Any],
        **_: object,
    ) -> dict[str, object]:
        if operation == "tool_classification":
            return {
                "capabilities": [
                    {
                        "tool_id": tool["tool_id"],
                        "business_capability": f"uses {tool['tool_id']}",
                    }
                    for tool in payload["tools"]
                    if tool["tool_id"] != "delete_records"
                ]
            }
        if operation == "needed_access_inference":
            return {"agents": []}
        if operation == "toxic_combination_reasoning":
            if payload["agent"]["agent_id"] == "sales_bot":
                raise RuntimeError("fixture toxic response failure")
            return {"pairs": []}
        return {}


def _fleet_and_tools_with_planted_secret(secret: str):
    fleet, tools = load_inventory("data/fleet.json", "data/tools.json")
    agents = [
        agent.model_copy(update={"description": f"{agent.description} token={secret}"})
        if agent.id == "sales_bot"
        else agent
        for agent in fleet.agents
    ]
    secret_tools = [
        tool.model_copy(update={"description": f"{tool.description} token={secret}"})
        if tool.id == "read_crm"
        else tool
        for tool in tools.tools
    ]
    return fleet.model_copy(update={"agents": agents}), tools.model_copy(update={"tools": secret_tools})


def test_optional_enrichment_preserves_citation_verified_findings(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MODEL_TERRA", "example.model-terra")
    monkeypatch.setenv("MODEL_SOL", "example.model-sol")
    fleet, tools = load_inventory("data/fleet.json", "data/tools.json")
    llm = BedrockLLM(logger=CostLatencyLogger(path=tmp_path / "cost_latency.jsonl"), max_attempts=1)
    llm._client = EnrichmentClient()

    result = analyze_fleet(fleet, tools, llm=llm, enable_llm=True)

    assert len(result.findings) == 9
    assert result.tool_capabilities["read_customer_pii"] == "reads customer PII"
    assert result.needed_capabilities["support_bot"] == ["read customer support case context"]
    assert result.granted_vs_needed_gaps["support_bot"] == ["send_external_email"]
    assert result.granted_vs_needed_gaps["legacy_bot"] == ["read_archive"]
    support = next(finding for finding in result.findings if finding.agent_id == "support_bot")
    assert (
        support.business_risk
        == "The cited access path can expand the agent's practical blast radius."
    )
    assert all(not citation_errors(finding, fleet, tools=tools) for finding in result.findings)


def test_llm_generalization_constructs_and_verifies_a_novel_finding() -> None:
    fleet, tools = load_inventory("data/fleet.json", "data/tools.json")

    deterministic = analyze_fleet(fleet, tools, enable_llm=False)
    assert all(finding.agent_id != "sales_bot" for finding in deterministic.findings)
    assert all(finding.source == "deterministic" for finding in deterministic.findings)

    enriched = analyze_fleet(fleet, tools, llm=GeneralizationFixture(), enable_llm=True)
    generated = [finding for finding in enriched.findings if finding.source == "llm_generalized"]

    assert len(generated) == 1
    finding = generated[0]
    assert finding.agent_id == "sales_bot"
    assert {evidence.entity_id for evidence in finding.evidence if evidence.entity_type == "tool"} == {
        "read_crm",
        "send_external_email",
    }
    assert not citation_errors(finding, fleet, tools=tools)
    assert len(
        [
            finding
            for finding in enriched.findings
            if finding.agent_id == "support_bot" and finding.check_type == "sod"
        ]
    ) == 1


def test_batched_classification_and_per_agent_toxic_paths_stay_redacted() -> None:
    planted_secret = "sk-PLANTED_BATCH_SECRET_9J4sP0kLmN7qR2xV"
    fleet, tools = _fleet_and_tools_with_planted_secret(planted_secret)
    llm = PayloadRecordingLLM(planted_secret)

    result = analyze_fleet(fleet, tools, llm=llm, enable_llm=True)

    classification_payloads = [
        call["payload"] for call in llm.calls if call["operation"] == "tool_classification"
    ]
    assert classification_payloads
    assert all(set(payload) == {"tools"} for payload in classification_payloads)
    assert all(len(payload["tools"]) <= 6 for payload in classification_payloads)

    graph = EffectiveAccessGraph(fleet)
    toxic_payloads = [
        call["payload"]
        for call in llm.calls
        if call["operation"] == "toxic_combination_reasoning"
    ]
    assert toxic_payloads
    assert any(payload["agent"]["agent_id"] == "sales_bot" for payload in toxic_payloads)
    for payload in toxic_payloads:
        assert set(payload) == {"seeded_sod_principles", "agent", "tools"}
        assert set(payload["agent"]) == {
            "agent_id",
            "effective_tool_ids",
            "delegation_paths",
        }
        agent_id = payload["agent"]["agent_id"]
        effective_tools = set(payload["agent"]["effective_tool_ids"])
        assert effective_tools == graph.effective_tools(agent_id)
        assert {tool["tool_id"] for tool in payload["tools"]}.issubset(effective_tools)

    boundary_payloads = [*classification_payloads, *toxic_payloads]
    assert all(planted_secret not in json.dumps(payload, sort_keys=True) for payload in boundary_payloads)

    generated = [finding for finding in result.findings if finding.source == "llm_generalized"]
    assert len(generated) == 1
    finding = generated[0]
    assert finding.agent_id == "sales_bot"
    assert finding.check_type == "sod"
    assert {
        evidence.entity_id for evidence in finding.evidence if evidence.entity_type == "tool"
    } == {"read_crm", "send_external_email"}
    assert not citation_errors(finding, fleet, tools=tools)


def test_partial_enrichment_is_explicit_and_keeps_full_capability_coverage() -> None:
    fleet, tools = load_inventory("data/fleet.json", "data/tools.json")

    result = analyze_fleet(fleet, tools, llm=PartialEnrichmentFixture(), enable_llm=True)
    enrichment = result.metadata["llm_enrichment"]
    classification = enrichment["operations"]["tool_classification"]
    toxic = enrichment["operations"]["toxic_combination_reasoning"]

    assert set(result.tool_capabilities) == tools.tool_ids
    assert result.tool_capabilities["delete_records"].startswith("Unclassified capability")
    assert enrichment["status"] == "partial"
    assert classification["status"] == "partial"
    assert classification["classified_tools"] == len(tools.tools) - 1
    assert classification["total_tools"] == len(tools.tools)
    assert classification["unclassified_tool_ids"] == ["delete_records"]
    assert classification["individual_retry_tool_ids"] == ["delete_records"]
    assert toxic["status"] == "partial"
    assert toxic["agents_incomplete"] == ["sales_bot"]
