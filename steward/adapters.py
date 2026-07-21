"""Adapters that turn real agent configuration into Steward's portable graph input.

The v0.1 real-world adapter targets Claude Desktop/Cursor-style ``mcp.json``.
Those files describe *servers*, not the individual tools discovered at runtime.
For a small registry of widely used servers recognized by their exact package
identifier, Steward imports the package's *documented* capability set at a
finer granularity; every other server is represented as one conservative
server-level tool bundle.  Neither path claims runtime tool discovery, and no
credential or environment value survives the import.  A richer exported fleet
can use the native JSON format.
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


@dataclass(frozen=True)
class KnownCapability:
    """One documented capability of a recognized MCP server package."""

    suffix: str
    name: str
    description: str


@dataclass(frozen=True)
class KnownServer:
    """A widely used MCP server whose documented toolset Steward can map.

    ``package_tokens`` are the exact package identifiers that may appear in a
    config's ``command``/``args`` (npm package, PyPI entry point, or container
    image).  Matching is deliberately exact-token: a server merely *named*
    "github" is not assumed to be the GitHub server.
    """

    label: str
    package_tokens: tuple[str, ...]
    capabilities: tuple[KnownCapability, ...]


_PROVENANCE = (
    " Derived from the recognized package name in the imported configuration and that "
    "package's documented toolset — not from runtime tool discovery; the running version, "
    "flags, or an allowlist may expose a different set."
)

KNOWN_MCP_SERVERS: tuple[KnownServer, ...] = (
    KnownServer(
        label="Filesystem MCP server",
        package_tokens=("@modelcontextprotocol/server-filesystem",),
        capabilities=(
            KnownCapability(
                suffix="read_files",
                name="Read files",
                description="Reads file contents within the configured allowed directories.",
            ),
            KnownCapability(
                suffix="write_files",
                name="Write and move files",
                description="Creates, edits, and moves files within the configured allowed directories.",
            ),
            KnownCapability(
                suffix="list_directories",
                name="List and search directories",
                description="Lists and searches directory trees within the configured allowed directories.",
            ),
        ),
    ),
    KnownServer(
        label="GitHub MCP server",
        package_tokens=(
            "@modelcontextprotocol/server-github",
            "ghcr.io/github/github-mcp-server",
        ),
        capabilities=(
            KnownCapability(
                suffix="read_repositories",
                name="Read repositories",
                description="Reads repository code, issues, and pull requests accessible to the configured token.",
            ),
            KnownCapability(
                suffix="write_issues_and_prs",
                name="Create and update issues/PRs",
                description="Creates and updates issues, pull requests, and comments in accessible repositories.",
            ),
            KnownCapability(
                suffix="push_repository_content",
                name="Push repository content",
                description="Creates branches and pushes file changes to accessible repositories.",
            ),
        ),
    ),
    KnownServer(
        label="Slack MCP server",
        package_tokens=("@modelcontextprotocol/server-slack",),
        capabilities=(
            KnownCapability(
                suffix="read_messages",
                name="Read workspace messages",
                description="Reads channel history, threads, and user profiles in the connected workspace.",
            ),
            KnownCapability(
                suffix="post_messages",
                name="Post workspace messages",
                description="Posts messages and replies to channels in the connected workspace.",
            ),
        ),
    ),
    KnownServer(
        label="PostgreSQL MCP server",
        package_tokens=("@modelcontextprotocol/server-postgres",),
        capabilities=(
            KnownCapability(
                suffix="query_database_read_only",
                name="Run read-only SQL",
                description="Runs documented read-only SQL queries and schema inspection against the configured database.",
            ),
        ),
    ),
    KnownServer(
        label="SQLite MCP server",
        package_tokens=("@modelcontextprotocol/server-sqlite", "mcp-server-sqlite"),
        capabilities=(
            KnownCapability(
                suffix="read_write_database",
                name="Run SQL including writes",
                description="Runs SQL queries, including writes, against the configured local SQLite database.",
            ),
        ),
    ),
    KnownServer(
        label="Fetch MCP server",
        package_tokens=("mcp-server-fetch", "@modelcontextprotocol/server-fetch"),
        capabilities=(
            KnownCapability(
                suffix="fetch_web_content",
                name="Fetch arbitrary URLs",
                description=(
                    "Sends requests to and retrieves content from arbitrary external URLs; "
                    "an outbound request channel as well as a read channel."
                ),
            ),
        ),
    ),
    KnownServer(
        label="Brave Search MCP server",
        package_tokens=("@modelcontextprotocol/server-brave-search",),
        capabilities=(
            KnownCapability(
                suffix="web_search",
                name="Search the public web",
                description="Searches the public web through the Brave Search API.",
            ),
        ),
    ),
    KnownServer(
        label="Google Drive MCP server",
        package_tokens=("@modelcontextprotocol/server-gdrive",),
        capabilities=(
            KnownCapability(
                suffix="read_drive_files",
                name="Read Drive files",
                description="Searches and reads files in the connected Google Drive account.",
            ),
        ),
    ),
    KnownServer(
        label="Memory MCP server",
        package_tokens=("@modelcontextprotocol/server-memory",),
        capabilities=(
            KnownCapability(
                suffix="read_write_memory",
                name="Read/write local memory graph",
                description="Reads and writes a local knowledge-graph memory file.",
            ),
        ),
    ),
    KnownServer(
        label="Puppeteer MCP server",
        package_tokens=("@modelcontextprotocol/server-puppeteer",),
        capabilities=(
            KnownCapability(
                suffix="browser_automation",
                name="Drive a live browser",
                description=(
                    "Navigates and interacts with live web pages in a real browser, including "
                    "clicking and filling forms; capable of submitting data to external sites."
                ),
            ),
        ),
    ),
    KnownServer(
        label="Sentry MCP server",
        package_tokens=("@modelcontextprotocol/server-sentry", "mcp-server-sentry"),
        capabilities=(
            KnownCapability(
                suffix="read_error_reports",
                name="Read error reports",
                description="Reads issues and stack traces from the connected Sentry organization.",
            ),
        ),
    ),
)


def _match_known_server(server_config: Mapping[str, Any]) -> KnownServer | None:
    """Recognize a server by exact package identifier in command/args.

    A version or image-tag suffix (``pkg@1.2.3``, ``image:tag``) still matches
    its package prefix.  The server's display name is deliberately ignored.
    """

    tokens: list[str] = []
    command = server_config.get("command")
    if isinstance(command, str):
        tokens.append(command.strip().lower())
    args = server_config.get("args")
    if isinstance(args, list):
        tokens.extend(str(arg).strip().lower() for arg in args)
    for known in KNOWN_MCP_SERVERS:
        for package in known.package_tokens:
            if any(
                token == package or token.startswith((f"{package}@", f"{package}:"))
                for token in tokens
            ):
                return known
    return None


def _known_server_tools(
    server_name: str, known: KnownServer, used_ids: set[str]
) -> list[dict[str, str]]:
    """Emit one documented-capability tool per mapped capability."""

    safe_name = str(redact_value(server_name))
    tools: list[dict[str, str]] = []
    for capability in known.capabilities:
        base_id = f"mcp_{_slug(server_name)}_{capability.suffix}"
        tool_id = base_id
        suffix = 2
        while tool_id in used_ids:
            tool_id = f"{base_id}_{suffix}"
            suffix += 1
        used_ids.add(tool_id)
        tools.append(
            {
                "id": tool_id,
                "name": f"{known.label} ('{safe_name}'): {capability.name}",
                "description": capability.description + _PROVENANCE,
            }
        )
    return tools


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
    recognized: list[str] = []
    bundled: list[str] = []
    for raw_name, raw_server in servers.items():
        server_name = str(raw_name)
        server = _as_mapping(raw_server, label=f"MCP server '{server_name}'")
        known = _match_known_server(server)
        if known is None:
            tools.append(_mcp_server_tool(server_name, server, used_ids))
            bundled.append(str(redact_value(server_name)))
        else:
            tools.extend(_known_server_tools(server_name, known, used_ids))
            recognized.append(f"{redact_value(server_name)} ({known.label})")

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
    notes_list = [
        "All environment-variable values and credential-like strings were redacted before "
        "this graph was created.",
    ]
    if recognized:
        notes_list.append(
            f"Recognized {len(recognized)} server(s) by exact package identifier and imported "
            f"their documented capability sets: {', '.join(sorted(recognized))}. This reflects "
            "each package's documented toolset, not runtime tool discovery; the running "
            "version, flags, or an allowlist may expose a different set."
        )
    if bundled:
        notes_list.append(
            f"Imported {len(bundled)} unrecognized server(s) at conservative server-bundle "
            f"granularity ({', '.join(sorted(bundled))}): mcp.json does not expose the tools "
            "discovered at runtime."
        )
    notes_list.append(
        "Assign an owner and replace imported entries with discovered tool metadata for a "
        "more precise review."
    )
    notes = tuple(notes_list)
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
