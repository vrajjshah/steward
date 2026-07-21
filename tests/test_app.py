import json

import pytest
from fastapi.testclient import TestClient

from steward.app import create_app
from steward.findings import analyze_fleet
from steward.loaders import load_fleet, load_tools
from steward.reporting import normalize_findings
from steward.web_service import StewardService


@pytest.fixture(autouse=True)
def _keep_app_surface_tests_offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """The FastAPI/report tests must never spend a real Bedrock request.

    The app's live mode is intentionally capable of optional enrichment. These
    presentation tests exercise the safe deterministic fallback instead, even
    when a developer shell happens to have live model IDs configured.
    """

    for tier in ("SOL", "TERRA", "LUNA"):
        monkeypatch.setenv(f"MODEL_{tier}", f"replace-with-test-{tier.lower()}-model-id")


def test_api_exposes_only_verified_finding_and_report_surfaces() -> None:
    client = TestClient(create_app(StewardService(demo_mode=False)))

    analysis = client.post("/api/analyze")
    assert analysis.status_code == 200
    payload = analysis.json()
    assert payload["report"]["scope"]["tools"] > 0
    assert len(payload["findings"]) == 9
    assert all(finding["evidence"] for finding in payload["findings"])
    assert {finding["source"] for finding in payload["findings"]} == {"deterministic"}

    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert "Critical data-exfiltration path" in dashboard.text
    assert "read_customer_pii" in dashboard.text
    assert "send_external_email" in dashboard.text
    assert "Deterministic check" in dashboard.text

    markdown = client.get("/api/report.md")
    assert markdown.status_code == 200
    assert "# Steward fleet audit report" in markdown.text
    assert "**Finding source:** Deterministic check" in markdown.text

    packet_export = client.get("/api/certification-packet.json")
    assert packet_export.status_code == 200
    assert "attachment" in packet_export.headers["content-disposition"]


def test_reviewer_action_updates_certification_packet_for_current_session() -> None:
    client = TestClient(create_app(StewardService(demo_mode=False)))
    response = client.post(
        "/api/risk-cards/support_bot/review",
        json={"status": "flag", "note": "Confirm controlled external egress."},
    )
    assert response.status_code == 200
    assert response.json()["review"]["status"] == "flag"

    packet = client.get("/api/certification-packet").json()
    card = next(card for card in packet["risk_cards"] if card["agent"]["id"] == "support_bot")
    assert card["review"]["status"] == "flag"
    assert card["review"]["note"] == "Confirm controlled external egress."


def test_api_loads_an_mcp_config_through_the_same_analysis_graph(tmp_path) -> None:
    config_path = tmp_path / "mcp.json"
    config_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "internal-search": {
                        "command": "npx",
                        "args": ["-y", "internal-search-mcp"],
                        "env": {"API_TOKEN": "fake-secret-never-enters-the-graph"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    client = TestClient(create_app(StewardService(demo_mode=False)))

    loaded = client.post(
        "/api/fleet/load", json={"fleet_path": str(config_path), "source_type": "mcp"}
    )
    assert loaded.status_code == 200
    assert loaded.json()["source"] == "mcp"
    assert "fake-secret-never-enters-the-graph" not in loaded.text

    analysis = client.post("/api/analyze")
    assert analysis.status_code == 200
    assert analysis.json()["fleet"]["agents"][0]["id"] == "mcp_workspace_agent"


def test_demo_mode_analyzes_a_loaded_real_config_instead_of_replaying_synthetic_cache(tmp_path) -> None:
    config_path = tmp_path / "mcp.json"
    config_path.write_text(
        json.dumps({"mcpServers": {"internal-search": {"command": "npx"}}}), encoding="utf-8"
    )
    client = TestClient(create_app(StewardService(demo_mode=True)))

    loaded = client.post(
        "/api/fleet/load", json={"fleet_path": str(config_path), "source_type": "mcp"}
    )
    assert loaded.status_code == 200
    analysis = client.post("/api/analyze")

    assert analysis.status_code == 200
    payload = analysis.json()
    assert payload["source"] == "mcp"
    assert payload["findings"]
    assert all(finding["agent_id"] == "mcp_workspace_agent" for finding in payload["findings"])


def test_zero_key_demo_reads_a_committed_analysis_shape(tmp_path) -> None:
    fleet = load_fleet("data/fleet.json")
    tools = load_tools("data/tools.json")
    cache_path = tmp_path / "demo_results.json"
    cache_path.write_text(
        json.dumps(analyze_fleet(fleet, tools).model_dump(mode="json")), encoding="utf-8"
    )
    client = TestClient(create_app(StewardService(demo_mode=True, demo_path=cache_path)))

    response = client.get("/api/report")
    assert response.status_code == 200
    assert response.json()["certification_packet"]["summary"]["findings"] == 9
    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert "Then: AI-generalized path" not in dashboard.text


def test_committed_demo_cache_keeps_deterministic_and_llm_generalized_sources() -> None:
    """The zero-key demo must visibly preserve both evidence-verified tiers."""

    client = TestClient(create_app(StewardService(demo_mode=True)))
    findings = client.get("/api/findings").json()["findings"]
    findings_by_agent = {finding["agent_id"]: finding for finding in findings}

    support = findings_by_agent["support_bot"]
    sales = findings_by_agent["sales_bot"]

    assert support["source"] == "deterministic"
    assert support["source_label"] == "Deterministic check"
    assert sales["source"] == "llm_generalized"
    assert sales["source_label"] == "LLM-generalized"
    assert sales["evidence"]

    analysis = client.post("/api/analyze")
    assert analysis.status_code == 200
    enrichment = analysis.json()["llm_enrichment"]
    assert enrichment["state"] == "partial"
    assert enrichment["label"] == "Enrichment partial"
    assert enrichment["mode"] == "cached live OpenAI gpt-oss-120b Bedrock result"
    assert {operation["key"] for operation in enrichment["operations"]} == {
        "tool_classification",
        "needed_access",
        "toxic_combination_reasoning",
        "finding_narratives",
    }

    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert "Then: AI-generalized path" in dashboard.text
    assert sales["title"] in dashboard.text
    assert f'/risk-cards/{sales["agent_id"]}' in dashboard.text
    assert "Enrichment partial" in dashboard.text
    assert "GPT-5.6 proposed this capability pair" not in dashboard.text
    assert "external" in sales["business_risk"].lower()

    markdown = client.get("/api/report.md")
    assert markdown.status_code == 200
    assert "## Optional model enrichment" in markdown.text
    assert "Enrichment partial" in markdown.text


def test_partial_enrichment_is_explicit_in_api_report_and_dashboard(tmp_path) -> None:
    fleet = load_fleet("data/fleet.json")
    tools = load_tools("data/tools.json")
    cached = analyze_fleet(fleet, tools).model_dump(mode="json")
    cached["metadata"] = {
        "llm_enrichment": {
            "enabled": True,
            "status": "partial",
            "completion": {
                "classified_tools": 32,
                "total_tools": 34,
                "unclassified_tool_ids": ["delete_records", "export_data"],
                "agents_incomplete": ["sales_bot"],
            },
            "operations": {
                "tool_classification": {
                    "status": "ok",
                    "classified_tools": 32,
                    "total_tools": 34,
                    "unclassified_tool_ids": ["delete_records", "export_data"],
                    "failed_batch_tool_ids": [["delete_records", "export_data"]],
                    "individual_retry_tool_ids": ["delete_records", "export_data"],
                },
                "toxic_combination_reasoning": {
                    "status": "partial",
                    "agents_analyzed": 20,
                    "agents_total": 21,
                    "agents_incomplete": ["sales_bot"],
                    "on_demand_tool_retry_ids": ["export_data"],
                },
            },
        }
    }
    cache_path = tmp_path / "partial-enrichment.json"
    cache_path.write_text(json.dumps(cached), encoding="utf-8")
    client = TestClient(create_app(StewardService(demo_mode=True, demo_path=cache_path)))

    enrichment = client.post("/api/analyze").json()["llm_enrichment"]
    assert enrichment["state"] == "partial"
    assert enrichment["label"] == "Enrichment partial"
    assert enrichment["recorded_status"] == "partial"
    assert enrichment["completion"]["incomplete_agents"] == ["sales_bot"]
    operations = {operation["key"]: operation for operation in enrichment["operations"]}
    assert operations["tool_classification"]["incomplete"] is True
    assert "32/34 tools classified" in operations["tool_classification"]["coverage"]
    assert operations["tool_classification"]["individual_retry_tools"] == [
        "delete_records",
        "export_data",
    ]
    assert operations["toxic_combination_reasoning"]["incomplete_agents"] == ["sales_bot"]
    assert operations["toxic_combination_reasoning"]["on_demand_retry_tools"] == ["export_data"]

    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert "Enrichment partial" in dashboard.text
    assert "Incomplete: sales_bot" in dashboard.text
    assert "Recovered batch retry: delete_records, export_data" in dashboard.text

    markdown = client.get("/api/report.md")
    assert markdown.status_code == 200
    assert "Enrichment partial" in markdown.text
    assert "32/34 tools classified" in markdown.text


def test_demo_cache_suppresses_a_finding_with_invalid_citation(tmp_path) -> None:
    fleet = load_fleet("data/fleet.json")
    tools = load_tools("data/tools.json")
    cached = analyze_fleet(fleet, tools).model_dump(mode="json")
    cached["findings"][0]["evidence"][1]["entity_id"] = "not_a_real_tool"
    cache_path = tmp_path / "demo_results.json"
    cache_path.write_text(json.dumps(cached), encoding="utf-8")

    client = TestClient(create_app(StewardService(demo_mode=True, demo_path=cache_path)))
    response = client.get("/api/findings")
    assert response.status_code == 200
    assert response.json()["count"] == 8


def test_finding_source_is_serialized_for_deterministic_and_llm_generalized_findings() -> None:
    base = {
        "id": "sod:test:sample",
        "agent_id": "test_agent",
        "check_type": "sod",
        "severity": "high",
        "title": "Sample finding",
        "business_risk": "A sample risk.",
        "evidence": [
            {"entity_type": "agent", "entity_id": "test_agent", "detail": "Subject agent."}
        ],
        "recommended_action": "Separate the access.",
        "control_mapping": "Identity governance — separation of duties",
    }
    findings_by_source = {
        finding["source"]: finding
        for finding in normalize_findings(
            [base, {**base, "id": "sod:test:generalized", "source": "llm_generalized"}]
        )
    }
    deterministic = findings_by_source["deterministic"]
    generalized = findings_by_source["llm_generalized"]

    assert deterministic["source"] == "deterministic"
    assert deterministic["source_label"] == "Deterministic check"
    assert generalized["source"] == "llm_generalized"
    assert generalized["source_label"] == "LLM-generalized"


def test_demo_cache_preserves_an_llm_generalized_source_label_without_a_model_call(tmp_path) -> None:
    fleet = load_fleet("data/fleet.json")
    tools = load_tools("data/tools.json")
    cached = analyze_fleet(fleet, tools).model_dump(mode="json")
    cached["findings"][0]["source"] = "llm_generalized"
    cache_path = tmp_path / "demo_results.json"
    cache_path.write_text(json.dumps(cached), encoding="utf-8")

    client = TestClient(create_app(StewardService(demo_mode=True, demo_path=cache_path)))
    findings = client.get("/api/findings").json()["findings"]
    generalized = next(finding for finding in findings if finding["id"] == cached["findings"][0]["id"])

    assert generalized["source"] == "llm_generalized"
    assert generalized["source_label"] == "LLM-generalized"
    assert "The configured model proposed" in generalized["source_description"]
