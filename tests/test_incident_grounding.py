"""Regression coverage for deterministic, source-linked MCP threat context."""

from __future__ import annotations

from fastapi.testclient import TestClient

from steward.app import create_app
from steward.findings import analyze_fleet
from steward.loaders import load_inventory
from steward.pipeline import analyze_fleet as enriched_analyze_fleet
from steward.reporting import build_fleet_audit_report, render_markdown_report
from steward.web_service import StewardService


def _finding_by_agent(result, agent_id: str):  # type: ignore[no-untyped-def]
    return next(finding for finding in result.findings if finding.agent_id == agent_id)


def test_fixture_findings_get_conservative_real_world_context() -> None:
    fleet, tools = load_inventory("data/fleet.json", "data/tools.json")
    result = analyze_fleet(fleet, tools)

    support = _finding_by_agent(result, "support_bot")
    assert [reference.id for reference in support.owasp_mcp] == ["MCP03:2025", "MCP04:2025"]
    assert [incident.title for incident in support.real_world_incident] == [
        "Supabase MCP stored prompt-injection scenario",
        "Malicious postmark-mcp package backdoor (v1.0.16)",
    ]
    assert all("not evidence" in incident.relevance.lower() for incident in support.real_world_incident)

    summary = _finding_by_agent(result, "summary_bot")
    assert [reference.id for reference in summary.owasp_mcp] == ["MCP02:2025"]
    assert [incident.title for incident in summary.real_world_incident] == [
        "Invariant Labs GitHub MCP toxic agent flow"
    ]

    # The mapping must remain narrow: other valid findings are not falsely
    # labeled as analogues merely because they are severe.
    invoice = _finding_by_agent(result, "invoice_bot")
    assert invoice.owasp_mcp == []
    assert invoice.real_world_incident == []


def test_llm_generalized_sales_pair_gets_the_same_context_after_enrichment() -> None:
    """The final pipeline boundary annotates findings added after deterministic checks."""

    fleet, tools = load_inventory("data/fleet.json", "data/tools.json")

    class FixtureLLM:
        def model_id(self, tier: str) -> str:
            return f"fixture-{tier}"

        def call_json(self, *, operation: str, payload: dict, **kwargs: object) -> dict:  # type: ignore[type-arg]
            if operation == "tool_classification":
                return {
                    "capabilities": [
                        {
                            "tool_id": tool["tool_id"],
                            "business_capability": tool["tool_id"].replace("_", " "),
                        }
                        for tool in payload["tools"]
                    ]
                }
            if operation == "needed_access_inference":
                return {"agents": []}
            if operation == "toxic_combination_reasoning" and payload["agent"]["agent_id"] == "sales_bot":
                return {
                    "pairs": [
                        {
                            "agent_id": "sales_bot",
                            "tool_ids": ["read_crm", "send_external_email"],
                            "reason": "A cited customer-data egress path.",
                        }
                    ]
                }
            return {"pairs": []}

    result = enriched_analyze_fleet(fleet, tools, llm=FixtureLLM(), enable_llm=True)
    sales = _finding_by_agent(result, "sales_bot")
    assert sales.source == "llm_generalized"
    assert [reference.id for reference in sales.owasp_mcp] == ["MCP03:2025", "MCP04:2025"]
    assert len(sales.real_world_incident) == 2


def test_report_and_zero_key_cache_surface_context_without_treating_it_as_evidence() -> None:
    fleet, tools = load_inventory("data/fleet.json", "data/tools.json")
    result = analyze_fleet(fleet, tools)
    report = build_fleet_audit_report(
        fleet,
        result.findings,
        tools=tools,
        effective_access=result.effective_access,
    )
    support = next(finding for finding in report["findings"] if finding["agent_id"] == "support_bot")
    assert {reference["id"] for reference in support["owasp_mcp"]} == {"MCP03:2025", "MCP04:2025"}
    assert report["mcp_threat_context"][0]["owasp_mcp"]["id"] == "MCP01:2025"

    markdown = render_markdown_report(report)
    assert "## Grounded MCP threat context" in markdown
    assert "CVE-2026-32211" in markdown
    assert "not graph evidence" in markdown

    # The committed cache predates these optional fields; the app's existing
    # citation-verification boundary deterministically adds context for the
    # same real graph entities at zero-key dashboard time.
    demo = StewardService(demo_mode=True).current()
    sales = next(finding for finding in demo["findings"] if finding["agent_id"] == "sales_bot")
    assert {reference["id"] for reference in sales["owasp_mcp"]} == {"MCP03:2025", "MCP04:2025"}
    assert all(finding["evidence"] for finding in demo["findings"])

    client = TestClient(create_app(StewardService(demo_mode=True)))
    dashboard = client.get("/")
    risk_card = client.get("/risk-cards/support_bot")
    report_page = client.get("/report")
    assert "Grounded MCP context" in dashboard.text
    assert "MCP03:2025" in dashboard.text
    assert "postmark-mcp package backdoor" in risk_card.text
    assert "CVE-2026-32211" in report_page.text
