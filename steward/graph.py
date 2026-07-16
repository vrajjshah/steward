"""Effective-access graph construction and deterministic delegation traversal."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass

import networkx as nx

from .models import Fleet


class GraphValidationError(ValueError):
    """Raised when a fleet cannot form a well-defined delegation graph."""


def delegation_edge_id(source_agent_id: str, target_agent_id: str) -> str:
    """Return the stable external identifier used in citation evidence."""

    return f"{source_agent_id}->{target_agent_id}"


@dataclass(frozen=True)
class AccessProvenance:
    """How one agent obtains a tool in its effective access set."""

    tool_id: str
    grantor_agent_id: str
    path: tuple[str, ...]
    is_direct: bool

    @property
    def delegation_edge_ids(self) -> tuple[str, ...]:
        return tuple(
            delegation_edge_id(source, target)
            for source, target in zip(self.path, self.path[1:], strict=False)
        )


class EffectiveAccessGraph:
    """An in-memory graph of direct grants and transitive delegation.

    Delegating to another agent means the delegator can invoke that agent's
    available tools. Therefore an agent's effective access is its direct grants
    plus every direct grant held by a reachable delegate, including delegates of
    delegates. Cycles are safe and do not duplicate access.
    """

    def __init__(self, fleet: Fleet) -> None:
        self.fleet = fleet
        self._agents = {agent.id: agent for agent in fleet.agents}
        self._validate_delegation_references()

        # Delegation-only graph used for effective access calculations.
        self.delegation_graph = nx.DiGraph()
        self.delegation_graph.add_nodes_from(sorted(self._agents))
        for agent in fleet.agents:
            for delegate in sorted(agent.can_delegate_to):
                self.delegation_graph.add_edge(agent.id, delegate)

        # Full graph is useful to visualizers and makes the graph entity model
        # explicit: agent, tool, owner, and delegation edges all exist here.
        self.graph = nx.DiGraph()
        for agent in fleet.agents:
            agent_node = self.agent_node_id(agent.id)
            self.graph.add_node(
                agent_node, entity_type="agent", entity_id=agent.id, label=agent.name
            )
            if agent.owner:
                owner_node = self.owner_node_id(agent.owner)
                self.graph.add_node(
                    owner_node, entity_type="owner", entity_id=agent.owner, label=agent.owner
                )
                self.graph.add_edge(owner_node, agent_node, relation="owns")
            for tool_id in sorted(set(agent.granted_tools) | set(agent.usage_log)):
                tool_node = self.tool_node_id(tool_id)
                self.graph.add_node(tool_node, entity_type="tool", entity_id=tool_id, label=tool_id)
            for tool_id in sorted(agent.granted_tools):
                self.graph.add_edge(agent_node, self.tool_node_id(tool_id), relation="granted")
            for delegate in sorted(agent.can_delegate_to):
                self.graph.add_edge(
                    agent_node,
                    self.agent_node_id(delegate),
                    relation="delegates_to",
                    entity_id=delegation_edge_id(agent.id, delegate),
                )

        self._provenance_cache: dict[str, dict[str, AccessProvenance]] = {}

    @staticmethod
    def agent_node_id(agent_id: str) -> str:
        return f"agent:{agent_id}"

    @staticmethod
    def tool_node_id(tool_id: str) -> str:
        return f"tool:{tool_id}"

    @staticmethod
    def owner_node_id(owner: str) -> str:
        return f"owner:{owner}"

    def _validate_delegation_references(self) -> None:
        errors: list[str] = []
        agent_ids = set(self._agents)
        for agent in self.fleet.agents:
            unknown = sorted(set(agent.can_delegate_to) - agent_ids)
            if unknown:
                errors.append(f"{agent.id} delegates to unknown agents: {', '.join(unknown)}")
        if errors:
            raise GraphValidationError("; ".join(errors))

    @property
    def agent_ids(self) -> set[str]:
        return set(self._agents)

    @property
    def tool_ids(self) -> set[str]:
        tool_ids: set[str] = set()
        for agent in self.fleet.agents:
            tool_ids.update(agent.granted_tools)
            tool_ids.update(agent.usage_log)
        return tool_ids

    @property
    def delegation_edge_ids(self) -> set[str]:
        return {
            delegation_edge_id(source, target) for source, target in self.delegation_graph.edges
        }

    def has_delegation_edge(self, edge_id: str) -> bool:
        return edge_id in self.delegation_edge_ids

    def direct_tools(self, agent_id: str) -> set[str]:
        """Return an agent's direct grants only."""

        return set(self._get_agent(agent_id).granted_tools)

    def reachable_agent_ids(self, agent_id: str, *, include_self: bool = True) -> set[str]:
        """Return all delegates reachable from an agent, safely handling cycles."""

        self._get_agent(agent_id)
        reachable = set(nx.descendants(self.delegation_graph, agent_id))
        if include_self:
            reachable.add(agent_id)
        return reachable

    def delegation_path(self, source_agent_id: str, target_agent_id: str) -> list[str] | None:
        """Return a deterministic shortest delegation path, or ``None``.

        NetworkX's shortest-path tie breaking follows insertion order. A small
        lexicographic BFS keeps report citations stable when a config's JSON
        ordering changes.
        """

        self._get_agent(source_agent_id)
        self._get_agent(target_agent_id)
        if source_agent_id == target_agent_id:
            return [source_agent_id]

        queue: deque[list[str]] = deque([[source_agent_id]])
        visited = {source_agent_id}
        while queue:
            path = queue.popleft()
            current = path[-1]
            for neighbor in sorted(self.delegation_graph.successors(current)):
                if neighbor in visited:
                    continue
                next_path = [*path, neighbor]
                if neighbor == target_agent_id:
                    return next_path
                visited.add(neighbor)
                queue.append(next_path)
        return None

    def provenance_for(self, agent_id: str, tool_id: str) -> AccessProvenance | None:
        """Return the best evidence path for a single effective grant."""

        return self._all_provenance(agent_id).get(tool_id)

    def effective_tools(self, agent_id: str) -> set[str]:
        """Return direct plus transitively delegated tools for an agent."""

        return set(self._all_provenance(agent_id))

    def is_transitively_held(self, agent_id: str, tool_id: str) -> bool:
        """True only when the tool is effective but is not a direct grant."""

        provenance = self.provenance_for(agent_id, tool_id)
        return provenance is not None and not provenance.is_direct

    def effective_access_map(self) -> dict[str, list[str]]:
        return {
            agent_id: sorted(self.effective_tools(agent_id)) for agent_id in sorted(self.agent_ids)
        }

    def direct_access_map(self) -> dict[str, list[str]]:
        return {
            agent_id: sorted(self.direct_tools(agent_id)) for agent_id in sorted(self.agent_ids)
        }

    def delegation_paths_map(self) -> dict[str, dict[str, list[str]]]:
        """Map each effective tool to a direct-grant owner path for rendering."""

        return {
            agent_id: {
                tool_id: list(provenance.path)
                for tool_id, provenance in sorted(self._all_provenance(agent_id).items())
            }
            for agent_id in sorted(self.agent_ids)
        }

    def _all_provenance(self, agent_id: str) -> dict[str, AccessProvenance]:
        self._get_agent(agent_id)
        if agent_id in self._provenance_cache:
            return self._provenance_cache[agent_id]

        candidates_by_tool: dict[str, list[AccessProvenance]] = {}
        for grantor_id in sorted(self.reachable_agent_ids(agent_id)):
            path = self.delegation_path(agent_id, grantor_id)
            # A reachable set and path lookup should agree; retaining the guard
            # protects against accidental future graph mutations.
            if path is None:
                continue
            for tool_id in sorted(self.direct_tools(grantor_id)):
                candidates_by_tool.setdefault(tool_id, []).append(
                    AccessProvenance(
                        tool_id=tool_id,
                        grantor_agent_id=grantor_id,
                        path=tuple(path),
                        is_direct=grantor_id == agent_id,
                    )
                )

        selected: dict[str, AccessProvenance] = {}
        for tool_id, candidates in candidates_by_tool.items():
            # Prefer a direct entitlement, then the shortest / lexicographically
            # stable delegation trail. This supplies one concise citation even
            # when an agent can reach equivalent grants through multiple paths.
            selected[tool_id] = min(
                candidates,
                key=lambda candidate: (
                    not candidate.is_direct,
                    len(candidate.path),
                    candidate.path,
                    candidate.grantor_agent_id,
                ),
            )
        self._provenance_cache[agent_id] = selected
        return selected

    def _get_agent(self, agent_id: str):
        try:
            return self._agents[agent_id]
        except KeyError as exc:
            raise KeyError(f"unknown agent: {agent_id}") from exc


def paths_to_edges(path: Iterable[str]) -> list[str]:
    """Convert an agent-id path into stable delegation-edge evidence IDs."""

    path_values = list(path)
    return [
        delegation_edge_id(source, target)
        for source, target in zip(path_values, path_values[1:], strict=False)
    ]
