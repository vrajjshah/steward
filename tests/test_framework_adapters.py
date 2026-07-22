"""Tests for the LangGraph / CrewAI / OpenAI Agents export readers (R6)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from steward.adapters import (
    AdapterError,
    import_crewai_export,
    import_langgraph_export,
    import_openai_agents_export,
    load_framework_export,
)
from steward.findings import analyze_fleet
from steward.models import Fleet, ToolCatalog

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRAMEWORKS = PROJECT_ROOT / "examples" / "frameworks"


def _load(name: str) -> dict:
    return json.loads((FRAMEWORKS / name).read_text(encoding="utf-8"))


def _agent(graph, agent_id: str) -> dict:
    return next(a for a in graph.fleet["agents"] if a["id"] == agent_id)


def test_langgraph_maps_edges_to_delegation() -> None:
    graph = import_langgraph_export(_load("langgraph_export.json"))
    assert graph.source_kind == "langgraph"
    assert _agent(graph, "supervisor")["can_delegate_to"] == ["researcher", "writer"]
    # Leaf nodes have no outgoing edges.
    assert _agent(graph, "writer")["can_delegate_to"] == []


def test_crewai_allow_delegation_maps_to_peers() -> None:
    graph = import_crewai_export(_load("crewai_export.json"))
    assert graph.source_kind == "crewai"
    # allow_delegation: true → may delegate to every coworker.
    assert set(_agent(graph, "manager")["can_delegate_to"]) == {"ap_clerk", "approver"}
    # allow_delegation: false and no explicit list → no delegation.
    assert _agent(graph, "ap_clerk")["can_delegate_to"] == []


def test_openai_agents_handoffs_map_to_delegation() -> None:
    graph = import_openai_agents_export(_load("openai_agents_export.json"))
    assert graph.source_kind == "openai_agents"
    assert _agent(graph, "triage")["can_delegate_to"] == ["billing", "tech"]


def test_env_and_credential_fields_are_dropped() -> None:
    graph = import_crewai_export(_load("crewai_export.json"))
    # Tool objects keep only id/name/description — the api_key never survives.
    for tool in graph.tools["tools"]:
        assert set(tool) <= {"id", "name", "description"}
    dumped = json.dumps(graph.public_dict())
    assert "sk-live-EXAMPLE-SHOULD-NOT-LEAK" not in dumped
    assert "api_key" not in dumped


def test_imports_mark_usage_unavailable() -> None:
    # A static export has no telemetry, so usage must be unavailable — otherwise
    # every imported grant would look like unused standing access.
    for name, reader in (
        ("langgraph_export.json", import_langgraph_export),
        ("crewai_export.json", import_crewai_export),
        ("openai_agents_export.json", import_openai_agents_export),
    ):
        graph = reader(_load(name))
        for agent in graph.fleet["agents"]:
            assert agent["usage_log_available"] is False


@pytest.mark.parametrize(
    "name,reader,expected_agent",
    [
        ("langgraph_export.json", import_langgraph_export, "supervisor"),
        ("crewai_export.json", import_crewai_export, "manager"),
        ("openai_agents_export.json", import_openai_agents_export, "triage"),
    ],
)
def test_imported_exports_analyze_end_to_end(name, reader, expected_agent) -> None:
    graph = reader(_load(name))
    fleet = Fleet.model_validate(graph.fleet)
    tools = ToolCatalog.model_validate(graph.tools)
    result = analyze_fleet(fleet, tools)
    # Each example is crafted so a delegated toxic combination surfaces on the
    # delegating agent — proving the imported delegation feeds the graph.
    assert any(f.agent_id == expected_agent for f in result.findings)
    # No false over-privilege: usage is unavailable, so that check stays silent.
    assert not any(f.check_type == "over_privilege" for f in result.findings)


def test_shape_validation_errors() -> None:
    with pytest.raises(AdapterError, match="'nodes' list"):
        import_langgraph_export({"edges": []})
    with pytest.raises(AdapterError, match="'edges' must be a list"):
        import_langgraph_export({"nodes": [], "edges": {}})
    with pytest.raises(AdapterError, match="'id' or 'name'"):
        import_langgraph_export({"nodes": [{"tools": []}]})
    with pytest.raises(AdapterError, match="'agents' list"):
        import_crewai_export({"tools": []})
    with pytest.raises(AdapterError, match="'agents' list"):
        import_openai_agents_export({})


def test_dispatcher_and_unknown_framework() -> None:
    graph = load_framework_export(FRAMEWORKS / "langgraph_export.json", "langgraph")
    assert graph.source_kind == "langgraph"
    with pytest.raises(AdapterError, match="Unknown framework"):
        load_framework_export(FRAMEWORKS / "langgraph_export.json", "autogen")
