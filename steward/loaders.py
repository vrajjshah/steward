"""Load and validate Steward's small JSON inventory files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Fleet, ToolCatalog


class InventoryValidationError(ValueError):
    """Raised when fleet references cannot be resolved against the catalog."""


def _read_json(path: str | Path) -> Any:
    source = Path(path)
    try:
        return json.loads(source.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise
    except json.JSONDecodeError as exc:
        raise InventoryValidationError(f"invalid JSON in {source}: {exc.msg}") from exc


def load_fleet(path: str | Path) -> Fleet:
    """Load a fleet from either ``[{agent...}]`` or ``{"agents": [...]}``."""

    data = _read_json(path)
    if isinstance(data, list):
        data = {"agents": data}
    if not isinstance(data, dict):
        raise InventoryValidationError(
            "fleet JSON must be a list or an object with an 'agents' list"
        )
    try:
        return Fleet.model_validate(data)
    except Exception as exc:  # Pydantic's error type is an implementation detail here.
        raise InventoryValidationError(f"invalid fleet in {path}: {exc}") from exc


def load_tools(path: str | Path) -> ToolCatalog:
    """Load tools from either ``[{tool...}]`` or ``{"tools": [...]}``."""

    data = _read_json(path)
    if isinstance(data, list):
        data = {"tools": data}
    if not isinstance(data, dict):
        raise InventoryValidationError("tools JSON must be a list or an object with a 'tools' list")
    try:
        return ToolCatalog.model_validate(data)
    except Exception as exc:  # Pydantic's error type is an implementation detail here.
        raise InventoryValidationError(f"invalid tool catalog in {path}: {exc}") from exc


def validate_inventory(fleet: Fleet, tools: ToolCatalog) -> None:
    """Ensure every grant, usage event, and delegation reference is real.

    This is intentionally separate from parsing: callers can still inspect a
    malformed real-world inventory and report useful errors rather than failing
    while reading a file.
    """

    errors: list[str] = []
    agent_ids = fleet.agent_ids
    tool_ids = tools.tool_ids

    for agent in fleet.agents:
        unknown_delegates = sorted(set(agent.can_delegate_to) - agent_ids)
        if unknown_delegates:
            errors.append(
                f"agent {agent.id!r} delegates to unknown agents: {', '.join(unknown_delegates)}"
            )

        unknown_grants = sorted(set(agent.granted_tools) - tool_ids)
        if unknown_grants:
            errors.append(
                f"agent {agent.id!r} has unknown granted tools: {', '.join(unknown_grants)}"
            )

        unknown_usage = sorted(set(agent.usage_log) - tool_ids)
        if unknown_usage:
            errors.append(
                f"agent {agent.id!r} has unknown usage-log tools: {', '.join(unknown_usage)}"
            )

    if errors:
        raise InventoryValidationError("; ".join(errors))


def load_inventory(fleet_path: str | Path, tools_path: str | Path) -> tuple[Fleet, ToolCatalog]:
    """Load the two canonical files and validate their cross-references."""

    fleet = load_fleet(fleet_path)
    tools = load_tools(tools_path)
    validate_inventory(fleet, tools)
    return fleet, tools
