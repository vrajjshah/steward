"""Peer-group outlier analytics (R5).

A deterministic heuristic that surfaces agents whose *effective* access profile
looks nothing like anyone else's — a cheap way to spot a likely over-grant or a
misconfigured identity that the rule-based checks won't catch. It compares every
pair of agents by Jaccard similarity of their effective tool sets, groups agents
that are more than a threshold similar, and flags any agent that ends up in a
group of one while still holding meaningful access.

This is emphatically **not** a `Finding`: it can't satisfy the graph-citation
contract (an unusual access profile is a statistical signal, not a specific
policy violation), so — exactly like the Granted-vs-Needed reconciliation — it
is reported as a clearly labeled analytics section. Steward's four-member
``check_type`` set stays closed.

Honesty: on a small fleet, "unlike its peers" is indicative, not statistical —
a legitimately unique role reads the same as a mistake. All thresholds live in
one place below and are surfaced in the output so a reviewer can recalibrate.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from pydantic import BaseModel, Field

from .capability_classes import DEFAULT_CAPABILITY_CLASSES, CapabilityClasses

# All tuning in one place (documented, and echoed into the output).
DEFAULT_SIMILARITY_THRESHOLD = 0.3  # max Jaccard to any peer at/below which an agent is isolated
DEFAULT_MIN_TOOLS = 3  # ignore agents too small to matter as an over-grant
DEFAULT_MIN_PEERS = 4  # below this many agents, peer comparison is meaningless


class PeerOutlier(BaseModel):
    """One agent whose effective access is unlike any peer's."""

    agent_id: str
    effective_tool_count: int
    high_impact_count: int
    max_similarity: float
    nearest_peer: str | None
    reason: str


class PeerAnalysis(BaseModel):
    """The analytics section: outliers plus the parameters that produced them."""

    method: str = (
        "Jaccard similarity of effective access sets; an agent isolated from every "
        "peer (max similarity at or below the threshold) while holding enough access "
        "is flagged. Heuristic, not a policy finding."
    )
    similarity_threshold: float
    min_tools: int
    agents_considered: int
    applicable: bool
    note: str
    outliers: list[PeerOutlier] = Field(default_factory=list)


def jaccard(left: set[str], right: set[str]) -> float:
    """Jaccard similarity of two sets; 0.0 when both are empty."""

    union = left | right
    if not union:
        return 0.0
    return len(left & right) / len(union)


def analyze_peer_groups(
    effective_access: Mapping[str, Iterable[str]],
    capability_classes: CapabilityClasses = DEFAULT_CAPABILITY_CLASSES,
    *,
    similarity_threshold: float = DEFAULT_SIMILARITY_THRESHOLD,
    min_tools: int = DEFAULT_MIN_TOOLS,
    min_peers: int = DEFAULT_MIN_PEERS,
) -> PeerAnalysis:
    """Flag agents whose effective access overlaps little with any peer."""

    access = {agent_id: set(tools) for agent_id, tools in effective_access.items()}
    agent_ids = sorted(access)

    if len(agent_ids) < min_peers:
        return PeerAnalysis(
            similarity_threshold=similarity_threshold,
            min_tools=min_tools,
            agents_considered=len(agent_ids),
            applicable=False,
            note=(
                f"Fleet has {len(agent_ids)} agents; peer analytics needs at least "
                f"{min_peers} to be meaningful. Skipped."
            ),
        )

    outliers: list[PeerOutlier] = []
    for agent_id in agent_ids:
        tools = access[agent_id]
        if len(tools) < min_tools:
            continue
        # Highest similarity to any *other* agent, with a deterministic nearest peer.
        best_similarity = 0.0
        nearest_peer: str | None = None
        for peer_id in agent_ids:
            if peer_id == agent_id:
                continue
            similarity = jaccard(tools, access[peer_id])
            if similarity > best_similarity or (
                similarity == best_similarity and (nearest_peer is None or peer_id < nearest_peer)
            ):
                best_similarity = similarity
                nearest_peer = peer_id
        if best_similarity > similarity_threshold:
            continue
        high_impact = sorted(tools & capability_classes.high_impact)
        outliers.append(
            PeerOutlier(
                agent_id=agent_id,
                effective_tool_count=len(tools),
                high_impact_count=len(high_impact),
                max_similarity=round(best_similarity, 3),
                nearest_peer=nearest_peer,
                reason=(
                    f"Holds {len(tools)} effective tools"
                    + (f" ({len(high_impact)} high-impact: {', '.join(high_impact)})" if high_impact else "")
                    + f", but overlaps at most {best_similarity:.0%} with any peer"
                    + (f" (closest: {nearest_peer})" if nearest_peer else "")
                    + " — an access profile unlike the rest of the fleet, worth a look for over-grant."
                ),
            )
        )

    outliers.sort(key=lambda item: (item.max_similarity, -item.effective_tool_count, item.agent_id))
    note = (
        f"{len(outliers)} agent(s) hold access unlike any peer. Indicative on a small "
        "fleet, not statistical: a legitimately unique role looks the same as a mistake."
        if outliers
        else "No agent is isolated from its peers at the current threshold."
    )
    return PeerAnalysis(
        similarity_threshold=similarity_threshold,
        min_tools=min_tools,
        agents_considered=len(agent_ids),
        applicable=True,
        note=note,
        outliers=outliers,
    )
