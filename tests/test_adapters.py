from __future__ import annotations

from typing import Any

from steward.adapters import import_mcp_config, load_mcp_config
from steward.findings import citation_errors
from steward.models import Fleet, ToolCatalog
from steward.pipeline import analyze_fleet


class SampleMcpGeneralizationFixture:
    """Offline GPT response for the semantically named, out-of-catalog MCP bundles."""

    def model_id(self, tier: str) -> str:
        return f"fixture-{tier}"

    def call_json(self, *, operation: str, **_: Any) -> dict[str, Any]:
        if operation == "tool_classification":
            return {
                "capabilities": [
                    {
                        "tool_id": "mcp_customer_records_reader",
                        "business_capability": "reads customer relationship records",
                    },
                    {
                        "tool_id": "mcp_external_outreach_delivery",
                        "business_capability": "delivers outreach to external recipients",
                    },
                ]
            }
        if operation == "toxic_combination_reasoning":
            return {
                "pairs": [
                    {
                        "agent_id": "mcp_workspace_agent",
                        "tool_ids": [
                            "mcp_customer_records_reader",
                            "mcp_external_outreach_delivery",
                        ],
                        "reason": (
                            "The same workspace can read customer records and send them to external recipients, "
                            "creating a customer-data egress path."
                        ),
                    }
                ]
            }
        return {"agents": []}


def test_mcp_import_keeps_server_structure_and_drops_environment_values() -> None:
    imported = import_mcp_config(
        {
            "mcpServers": {
                "customer-data": {
                    "command": "npx",
                    "args": ["-y", "customer-server", "--token=sk-DO_NOT_LEAK_9Af3Qw7Xz"],
                    "env": {"API_TOKEN": "sk-DO_NOT_LEAK_9Af3Qw7Xz"},
                }
            }
        }
    )

    assert imported.fleet["agents"][0]["granted_tools"] == ["mcp_customer_data"]
    exported = imported.public_dict()
    assert "sk-DO_NOT_LEAK_9Af3Qw7Xz" not in str(exported)
    assert "customer-data" in imported.tools["tools"][0]["name"]


def test_example_mcp_generalizes_an_unseen_server_bundle_pair() -> None:
    imported = load_mcp_config("examples/mcp.json")
    fleet = Fleet.model_validate(imported.fleet)
    tools = ToolCatalog.model_validate(imported.tools)

    result = analyze_fleet(
        fleet,
        tools,
        llm=SampleMcpGeneralizationFixture(),
        enable_llm=True,
    )

    generated = [finding for finding in result.findings if finding.source == "llm_generalized"]
    assert len(generated) == 1
    finding = generated[0]
    assert finding.agent_id == "mcp_workspace_agent"
    assert {
        evidence.entity_id for evidence in finding.evidence if evidence.entity_type == "tool"
    } == {"mcp_customer_records_reader", "mcp_external_outreach_delivery"}
    assert not citation_errors(finding, fleet, tools=tools)
