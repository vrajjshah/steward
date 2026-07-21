"""Tests for the named lethal-trifecta check (zero-noise on the shipped fleet)."""

from __future__ import annotations

from steward.findings import analyze_fleet, citation_errors, find_lethal_trifecta
from steward.loaders import load_inventory
from steward.models import Fleet, ToolCatalog


def test_shipped_synthetic_fleet_has_no_trifecta_agent() -> None:
    """The check is deliberately zero-noise today: no demo agent spans all
    three legs, and the deterministic gate proves it stays that way."""

    fleet, tools = load_inventory("data/fleet.json", "data/tools.json")
    result = analyze_fleet(fleet, tools)
    assert not [f for f in result.findings if f.rule_id == "lethal_trifecta"]


def _trifecta_fixture() -> tuple[Fleet, ToolCatalog]:
    tools = ToolCatalog.model_validate(
        {
            "tools": [
                {"id": "read_crm", "name": "Read CRM", "description": "Reads CRM records."},
                {"id": "web_search", "name": "Web search", "description": "Searches the public web."},
                {"id": "export_data", "name": "Export data", "description": "Exports data sets."},
                {"id": "read_calendar", "name": "Read calendar", "description": "Reads calendars."},
            ]
        }
    )
    fleet = Fleet.model_validate(
        {
            "agents": [
                {
                    "id": "research_outreach_bot",
                    "name": "ResearchOutreachBot",
                    "owner": "Fixture Owner",
                    "description": "Researches accounts on the public web and prepares export packages.",
                    "granted_tools": ["read_crm", "web_search", "export_data"],
                    "can_delegate_to": [],
                    "usage_log": ["read_crm", "web_search", "export_data"],
                },
                {
                    "id": "two_leg_bot",
                    "name": "TwoLegBot",
                    "owner": "Fixture Owner",
                    "description": "Reads CRM and searches the web, but has no egress channel.",
                    "granted_tools": ["read_crm", "web_search", "read_calendar"],
                    "can_delegate_to": [],
                    "usage_log": ["read_crm", "web_search", "read_calendar"],
                },
            ]
        }
    )
    return fleet, tools


def test_crafted_trifecta_agent_is_flagged_with_verified_citations() -> None:
    fleet, tools = _trifecta_fixture()
    result = analyze_fleet(fleet, tools)
    trifecta = [f for f in result.findings if f.rule_id == "lethal_trifecta"]
    assert len(trifecta) == 1
    finding = trifecta[0]
    assert finding.agent_id == "research_outreach_bot"
    assert finding.check_type == "sod"
    assert finding.severity == "critical"
    assert finding.source == "deterministic"
    # All three legs are cited as graph evidence and pass the verifier.
    cited_tools = {e.entity_id for e in finding.evidence if e.entity_type == "tool"}
    assert cited_tools == {"read_crm", "web_search", "export_data"}
    assert not citation_errors(finding, fleet, tools=tools)
    # The named pattern carries its source link and control context.
    assert any("lethal-trifecta" in i.url for i in finding.real_world_incident)
    control_ids = {r.control_id for r in finding.control_frameworks}
    assert {"AC-6", "AC-5", "LLM01"} <= control_ids
    # An agent holding only two legs is not flagged.
    assert not [f for f in result.findings if f.agent_id == "two_leg_bot"]


def test_trifecta_completes_through_delegation() -> None:
    """A leg reached only via delegation still completes the trifecta —
    effective access is the whole point."""

    fleet, tools = _trifecta_fixture()
    document = fleet.model_dump(mode="json")
    # Take export_data away from the two-leg agent's own grants and let it
    # reach the third leg through delegation instead.
    document["agents"][1]["can_delegate_to"] = ["research_outreach_bot"]
    fleet = Fleet.model_validate(document)
    findings = find_lethal_trifecta(fleet)
    assert {f.agent_id for f in findings} == {"research_outreach_bot", "two_leg_bot"}
    delegated = next(f for f in findings if f.agent_id == "two_leg_bot")
    assert any(e.entity_type == "delegation_edge" for e in delegated.evidence)
