"""Optional outbound drift notification — stdlib urllib, metadata only.

When ``steward analyze --traces`` detects runtime drift (access used outside an
agent's effective grants, or an unknown identity in the trace), a ``--notify-url``
can receive a small JSON summary so a monitoring pipeline can react. The payload
is **metadata only** — agent ids, tool ids, and counts — never tool-call
arguments, results, or prompts, and it is passed through the same redaction as
every other Steward output boundary. There is no third-party dependency: the
POST uses the standard library.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import UTC, datetime
from typing import Any

from steward.llm import redact_value

DRIFT_SCHEMA = "steward-drift/0.1"


class NotifyError(RuntimeError):
    """Raised when a drift notification cannot be delivered."""


def build_drift_payload(reconciliation: Any, *, fleet_agent_count: int) -> dict[str, Any]:
    """Assemble a redacted, metadata-only drift summary from a reconciliation."""

    observed = [agent for agent in reconciliation.agents if agent.observed_in_trace]
    payload = {
        "event": "steward.drift_detected",
        "schema": DRIFT_SCHEMA,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "source": reconciliation.source_name,
        "fleet_agents": fleet_agent_count,
        "agents_observed": len(observed),
        "events_total": reconciliation.events_total,
        "events_malformed": reconciliation.events_malformed,
        "drift": {
            "used_not_granted": {
                agent.agent_id: list(agent.used_not_granted)
                for agent in reconciliation.agents
                if agent.used_not_granted
            },
            "unrecognized_agents": sorted(reconciliation.unrecognized_agent_ids),
            "unrecognized_tools": {
                agent_id: sorted(tool_ids)
                for agent_id, tool_ids in sorted(reconciliation.unrecognized_tool_ids.items())
            },
        },
    }
    # Defense in depth: run the whole summary through the redaction boundary so a
    # credential-shaped id can never leave the host, even though ids are metadata.
    redacted = redact_value(payload)
    return redacted if isinstance(redacted, dict) else payload


def post_drift_notification(url: str, payload: dict[str, Any], *, timeout: float = 10.0) -> int:
    """POST the drift payload as JSON and return the HTTP status code."""

    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310 - user-supplied monitoring URL
        url,
        data=data,
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "steward-drift/0.1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return int(getattr(response, "status", 0) or 0)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise NotifyError(f"drift notification to {url} failed: {exc}") from exc
