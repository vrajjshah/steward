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


def test_known_servers_expand_to_documented_capabilities() -> None:
    """A real-shaped claude_desktop_config.json yields finer, honest tool nodes."""

    imported = load_mcp_config("examples/claude_desktop_config.json")
    tool_ids = {tool["id"] for tool in imported.tools["tools"]}

    assert {
        "mcp_filesystem_read_files",
        "mcp_filesystem_write_files",
        "mcp_filesystem_list_directories",
        "mcp_github_read_repositories",
        "mcp_github_write_issues_and_prs",
        "mcp_github_push_repository_content",
        "mcp_slack_read_messages",
        "mcp_slack_post_messages",
        "mcp_postgres_query_database_read_only",
        "mcp_web_fetch_fetch_web_content",
        # The unrecognized custom server stays a conservative bundle.
        "mcp_internal_billing",
    } == tool_ids

    # The host holds every imported capability, telemetry stays unavailable,
    # and no credential placeholder survives the import.
    host = imported.fleet["agents"][0]
    assert set(host["granted_tools"]) == tool_ids
    assert host["usage_log_available"] is False
    assert "REPLACE_WITH_YOUR_TOKEN" not in str(imported.public_dict())

    # Every documented-capability node carries its provenance disclaimer.
    for tool in imported.tools["tools"]:
        if tool["id"] != "mcp_internal_billing":
            assert "not from runtime tool discovery" in tool["description"]
    notes = " ".join(imported.notes)
    assert "documented capability sets" in notes
    assert "server-bundle" in notes

    # The import stays a valid, analyzable Steward graph.
    fleet = Fleet.model_validate(imported.fleet)
    tools = ToolCatalog.model_validate(imported.tools)
    result = analyze_fleet(fleet, tools, enable_llm=False)
    assert all(not citation_errors(f, fleet, tools=tools) for f in result.findings)


def test_known_server_matching_ignores_display_names() -> None:
    """A server merely *named* github must not inherit GitHub's capability map."""

    imported = import_mcp_config(
        {
            "mcpServers": {
                "github": {"command": "node", "args": ["/opt/custom/definitely-not-github.js"]}
            }
        }
    )
    assert [tool["id"] for tool in imported.tools["tools"]] == ["mcp_github"]


def test_known_server_matching_tolerates_version_suffixes() -> None:
    imported = import_mcp_config(
        {
            "mcpServers": {
                "pinned-search": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-brave-search@1.2.3"],
                }
            }
        }
    )
    assert [tool["id"] for tool in imported.tools["tools"]] == ["mcp_pinned_search_web_search"]


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
