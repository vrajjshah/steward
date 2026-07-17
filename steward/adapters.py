"""Adapters that turn real agent configuration into Steward's portable graph input.

The v0.1 real-world adapter targets Claude Desktop/Cursor-style ``mcp.json``.
Those files describe *servers*, not the individual tools discovered at runtime,
so Steward intentionally represents each configured server as one conservative
tool bundle.  It never claims a server exposes operations that were not in the
configuration.  A richer exported fleet can use the native JSON format.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from steward.llm import redact_value


class AdapterError(ValueError):
    """Raised when an external configuration cannot be represented safely."""


def _slug(value: str) -> str:
    result = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    return result or "unnamed"


def _as_mapping(value: Any, *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AdapterError(f"{label} must be a JSON object.")
    return value


def load_json(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    try:
        parsed = json.loads(source.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AdapterError(f"Configuration file not found: {source}") from exc
    except json.JSONDecodeError as exc:
        raise AdapterError(f"Invalid JSON in {source}: {exc.msg}") from exc
    return dict(_as_mapping(parsed, label="Configuration root"))


@dataclass(frozen=True)
class ImportedGraph:
    """Safe native-format fleet/tool documents produced by an adapter."""

    fleet: dict[str, Any]
    tools: dict[str, Any]
    source_kind: str
    notes: tuple[str, ...] = ()

    def public_dict(self) -> dict[str, Any]:
        return {
            "fleet": self.fleet,
            "tools": self.tools,
            "source_kind": self.source_kind,
            "notes": list(self.notes),
        }


def _mcp_server_tool(
    server_name: str, server_config: Mapping[str, Any], used_ids: set[str]
) -> dict[str, str]:
    """Create a conservative tool-bundle node from a declared MCP server."""

    base_id = f"mcp_{_slug(server_name)}"
    tool_id = base_id
    suffix = 2
    while tool_id in used_ids:
        tool_id = f"{base_id}_{suffix}"
        suffix += 1
    used_ids.add(tool_id)

    safe_name = str(redact_value(server_name))
    transport = "remote" if "url" in server_config else "local"
    return {
        "id": tool_id,
        "name": f"MCP server: {safe_name}",
        "description": (
            f"{transport.title()} MCP server configured as '{safe_name}'. "
            "This is a server-level capability bundle imported from mcp.json; "
            "credentials, environment values, command arguments, and payload data "
            "were not retained."
        ),
    }


def import_mcp_config(config: Mapping[str, Any], *, source_name: str = "mcp.json") -> ImportedGraph:
    """Convert a Claude Desktop/Cursor MCP config to the native graph format.

    ``mcpServers`` is the portable shape shared by Claude Desktop and Cursor.
    An MCP config does not identify a named application agent, so its host is
    faithfully represented as an unowned ``MCPWorkspaceAgent``; this may emit
    an ownership finding until a reviewer supplies an owner in a native fleet.
    """

    root = _as_mapping(config, label="MCP config")
    servers = root.get("mcpServers", root.get("mcp_servers", {}))
    servers = _as_mapping(servers, label="mcpServers")
    if not servers:
        raise AdapterError("No MCP servers found. Expected a non-empty 'mcpServers' object.")

    tools: list[dict[str, str]] = []
    used_ids: set[str] = set()
    for raw_name, raw_server in servers.items():
        server_name = str(raw_name)
        server = _as_mapping(raw_server, label=f"MCP server '{server_name}'")
        tool = _mcp_server_tool(server_name, server, used_ids)
        tools.append(tool)

    host_id = "mcp_workspace_agent"
    safe_source_name = str(redact_value(Path(source_name).name))
    host = {
        "id": host_id,
        "name": "MCPWorkspaceAgent",
        "owner": None,
        "description": (
            f"Execution host inferred from imported {safe_source_name} configuration."
        ),
        "granted_tools": [tool["id"] for tool in tools],
        "can_delegate_to": [],
        "usage_log": [],
        "usage_log_available": False,
    }
    notes = (
        "Imported at MCP-server granularity: mcp.json does not expose the tools discovered "
        "at runtime.",
        "All environment-variable values and credential-like strings were redacted before "
        "this graph was created.",
        "Assign an owner and replace server bundles with discovered tool metadata for a "
        "more precise review.",
    )
    return ImportedGraph(
        fleet={
            "schema_version": "0.1",
            "fleet_name": f"Imported MCP configuration: {safe_source_name}",
            "agents": [host],
        },
        tools={"schema_version": "0.1", "tools": tools},
        source_kind="mcp",
        notes=notes,
    )


def load_mcp_config(path: str | Path) -> ImportedGraph:
    """Read and safely import an MCP config from disk."""

    return import_mcp_config(load_json(path), source_name=str(path))


def parse_mcp_config(path: str | Path) -> ImportedGraph:
    """Compatibility entry point used by the application service."""

    return load_mcp_config(path)


def import_native_export(
    config: Mapping[str, Any], *, source_name: str = "agents.json"
) -> ImportedGraph:
    """Accept a native exported Steward-shaped fleet without ever retaining secrets.

    This also offers a low-friction path for an OpenAI Agents SDK project: emit
    its agent metadata as ``agents`` and its callable metadata as ``tools``.
    The SDK's runtime instructions, credentials, or payload traces are out of
    scope and are intentionally discarded/redacted by the caller boundary.
    """

    root = _as_mapping(redact_value(dict(config)), label="Native export")
    agents = root.get("agents")
    tools = root.get("tools")
    if not isinstance(agents, list) or not isinstance(tools, list):
        raise AdapterError("Native export needs top-level 'agents' and 'tools' lists.")
    normalized_agents: list[Any] = []
    for agent in agents:
        if not isinstance(agent, Mapping):
            normalized_agents.append(agent)
            continue
        normalized = dict(agent)
        # An SDK metadata export often has no runtime telemetry. Preserve that
        # distinction rather than converting omitted usage into a false unused
        # entitlement finding.
        if "usage_log" not in normalized:
            normalized["usage_log_available"] = False
        normalized_agents.append(normalized)
    fleet = {
        "schema_version": "0.1",
        "fleet_name": str(
            root.get(
                "fleet_name",
                f"Imported agent export: {redact_value(Path(source_name).name)}",
            )
        ),
        "agents": normalized_agents,
    }
    return ImportedGraph(
        fleet=fleet,
        tools={"schema_version": "0.1", "tools": tools},
        source_kind="native_export",
        notes=("Imported metadata was redacted before conversion.",),
    )
