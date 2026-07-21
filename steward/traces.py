"""Runtime-trace ingestion for the "Used" pillar of Granted vs. Used vs. Needed.

Steward's inventory says what an agent *may* do; an execution trace says what
it *did*. This module ingests a deliberately minimal JSONL trace format — one
event per line with ``timestamp``, ``agent_id``, ``tool_id``, and an optional
``status`` — and reconciles observed use against the analyzed access graph.
The shape maps directly from OpenTelemetry GenAI spans (``gen_ai.agent.id``,
``gen_ai.tool.name``) or any agent framework's invocation log.

The metadata-only discipline applies here too: tool-call arguments, results,
prompts, and any other payload-bearing fields are ignored at parse time and
never retained. An event is identity metadata (who invoked which tool, when),
nothing more.

Reconciliation yields three runtime signals per agent:

* **granted but never used** — standing direct grants absent from the trace
  window (the classic revocation candidate; feeds the same ``Granted − Used``
  view as the over-privilege check);
* **used but not granted** — an invocation of a tool that is *not* in the
  agent's effective access. This cannot be expressed as a Steward finding at
  all — the citation verifier rejects evidence outside effective access by
  design — so it surfaces as a reconciliation drift signal instead: either the
  inventory is stale or the runtime is not enforcing the inventory. Both need
  a human.
* **used but not needed** — observed use of a tool the optional model tier
  concluded the declared purpose does not require. Inference-assisted, so it
  is review context, not a drift fact.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import Field

from steward.models import AnalysisResult, Fleet, StewardModel, ToolCatalog

# The only fields an event may carry. Anything else (arguments, payloads,
# prompts, results) is dropped on the floor at parse time.
_ALLOWED_FIELDS = frozenset({"timestamp", "agent_id", "tool_id", "status"})


class ToolUsage(StewardModel):
    """Aggregated observations of one agent invoking one tool."""

    tool_id: str
    invocations: int = 0
    error_invocations: int = 0
    first_seen: str = ""
    last_seen: str = ""


class TraceLog(StewardModel):
    """Parsed, aggregated trace file. Only identity metadata is retained."""

    source_name: str = "traces.jsonl"
    events_total: int = 0
    events_malformed: int = 0
    # agent_id -> tool_id -> aggregated usage
    usage: dict[str, dict[str, ToolUsage]] = Field(default_factory=dict)

    def agents_observed(self) -> set[str]:
        return set(self.usage)

    def used_tool_ids(self, agent_id: str) -> set[str]:
        return set(self.usage.get(agent_id, {}))


class AgentReconciliation(StewardModel):
    """Granted vs. Used vs. Needed for one agent over one trace window."""

    agent_id: str
    observed_in_trace: bool = False
    used_tools: list[str] = Field(default_factory=list)
    granted_never_used: list[str] = Field(default_factory=list)
    used_not_granted: list[str] = Field(default_factory=list)
    used_not_needed: list[str] = Field(default_factory=list)
    needed_inference_available: bool = False


class TraceReconciliation(StewardModel):
    """Fleet-wide reconciliation result plus events nothing could match."""

    source_name: str
    events_total: int
    events_malformed: int
    agents: list[AgentReconciliation] = Field(default_factory=list)
    # Events naming an agent id absent from the fleet inventory: either a
    # retired identity still running, or a trace from a different fleet.
    unrecognized_agent_ids: list[str] = Field(default_factory=list)
    # Tool ids observed for a known agent but absent from the tool catalog.
    # They stay visible here because usage_log validation cannot hold them.
    unrecognized_tool_ids: dict[str, list[str]] = Field(default_factory=dict)

    @property
    def drift_detected(self) -> bool:
        return bool(
            self.unrecognized_agent_ids
            or any(agent.used_not_granted for agent in self.agents)
        )


def load_traces(path: str | Path) -> TraceLog:
    """Parse a JSONL trace file, tolerating and counting malformed lines.

    A well-formed event needs non-empty string ``agent_id`` and ``tool_id``
    plus a ``timestamp`` string; ISO-8601 timestamps sort lexicographically so
    they are kept as strings. Fields outside the allowed set are discarded.
    """

    source = Path(path)
    log = TraceLog(source_name=source.name)
    usage: dict[str, dict[str, ToolUsage]] = {}
    for line in source.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        log.events_total += 1
        try:
            event = json.loads(stripped)
        except json.JSONDecodeError:
            log.events_malformed += 1
            continue
        if not isinstance(event, dict):
            log.events_malformed += 1
            continue
        agent_id = event.get("agent_id")
        tool_id = event.get("tool_id")
        timestamp = event.get("timestamp")
        if not (
            isinstance(agent_id, str)
            and agent_id.strip()
            and isinstance(tool_id, str)
            and tool_id.strip()
            and isinstance(timestamp, str)
            and timestamp.strip()
        ):
            log.events_malformed += 1
            continue
        agent_id, tool_id, timestamp = agent_id.strip(), tool_id.strip(), timestamp.strip()
        record = usage.setdefault(agent_id, {}).setdefault(tool_id, ToolUsage(tool_id=tool_id))
        record.invocations += 1
        if str(event.get("status", "ok")).strip().lower() == "error":
            record.error_invocations += 1
        if not record.first_seen or timestamp < record.first_seen:
            record.first_seen = timestamp
        if not record.last_seen or timestamp > record.last_seen:
            record.last_seen = timestamp
    log.usage = usage
    return log


def apply_usage(fleet: Fleet, log: TraceLog, tools: ToolCatalog) -> Fleet:
    """Return a fleet copy whose usage logs reflect the observed trace window.

    Only agents that appear in the trace get ``usage_log_available = True``:
    an agent with zero events may simply be outside the telemetry's coverage,
    and absence of evidence must not become an unused-grant finding. The usage
    log keeps every observed tool the catalog knows — grant membership is not
    required, because hiding a non-granted invocation would hide drift — while
    fully unknown tool ids cannot pass inventory validation and surface via
    :func:`reconcile` instead.
    """

    known_tools = tools.tool_ids
    catalog_agents: list[dict[str, object]] = []
    for agent in fleet.agents:
        if agent.id not in log.usage:
            catalog_agents.append(agent.model_dump(mode="json"))
            continue
        updated = agent.model_dump(mode="json")
        updated["usage_log"] = sorted(log.used_tool_ids(agent.id) & known_tools)
        updated["usage_log_available"] = True
        catalog_agents.append(updated)
    return Fleet.model_validate(
        {
            "schema_version": fleet.schema_version,
            "fleet_name": fleet.fleet_name,
            "agents": catalog_agents,
        }
    )


def reconcile(result: AnalysisResult, log: TraceLog) -> TraceReconciliation:
    """Compare observed use against analyzed Granted / effective / Needed."""

    known_agents = result.fleet.agent_ids
    known_tools = result.tools.tool_ids
    reconciliation = TraceReconciliation(
        source_name=log.source_name,
        events_total=log.events_total,
        events_malformed=log.events_malformed,
        unrecognized_agent_ids=sorted(log.agents_observed() - known_agents),
    )
    for agent in sorted(result.fleet.agents, key=lambda item: item.id):
        observed = log.used_tool_ids(agent.id)
        recognized = {tool_id for tool_id in observed if tool_id in known_tools}
        unrecognized = sorted(observed - recognized)
        if unrecognized:
            reconciliation.unrecognized_tool_ids[agent.id] = unrecognized
        effective = set(result.effective_access.get(agent.id, []))
        needed_gap = result.granted_vs_needed_gaps.get(agent.id)
        entry = AgentReconciliation(
            agent_id=agent.id,
            observed_in_trace=agent.id in log.usage,
            used_tools=sorted(recognized),
            granted_never_used=(
                sorted(set(agent.granted_tools) - recognized)
                if agent.id in log.usage
                else []
            ),
            used_not_granted=sorted(recognized - effective),
            used_not_needed=(
                sorted(recognized & set(needed_gap)) if needed_gap is not None else []
            ),
            needed_inference_available=needed_gap is not None,
        )
        reconciliation.agents.append(entry)
    return reconciliation
