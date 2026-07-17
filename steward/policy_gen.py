"""Deterministic least-privilege policy generation for Steward findings.

This module deliberately operates only on an :class:`~steward.models.AnalysisResult`.
It does not call a model, inspect tool payloads, or alter the analyzer's output.
The generated policy is intentionally small: default deny, an allow-list based
on observed/declared need, and an explicit deny that breaks every cited toxic
combination.  It is designed for the bundled demonstration gate, not as an
enterprise authorization system.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from steward.models import AnalysisResult, Finding
from steward.redaction import redact_text

POLICY_VERSION = "steward-policy/v1"

# The policy generator must make a deterministic remediation choice when both
# grants have been observed in use.  Prefer blocking an outward/consequential
# action rather than a read or request capability.  Unknown tools fall back to
# a stable lexical choice, so the output is replayable.
_DENY_PREFERENCE: dict[str, int] = {
    "send_external_email": 0,
    "export_data": 0,
    "delete_records": 0,
    "approve_payment": 1,
    "run_payroll": 1,
    "grant_access": 1,
    "create_vendor": 2,
    "add_employee": 2,
    "request_access": 2,
}


class AgentPolicy(BaseModel):
    """A default-deny tool allow-list for one known agent identity."""

    model_config = ConfigDict(extra="forbid")

    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)
    remediation: dict[str, str] = Field(default_factory=dict)

    @field_validator("allow", "deny")
    @classmethod
    def _unique_tools(cls, values: list[str]) -> list[str]:
        cleaned = sorted({item.strip() for item in values if isinstance(item, str) and item.strip()})
        if len(cleaned) != len(values):
            raise ValueError("policy tool ids must be unique, non-empty strings")
        return cleaned

    @model_validator(mode="after")
    def _denies_override_allows(self) -> AgentPolicy:
        overlap = set(self.allow) & set(self.deny)
        if overlap:
            raise ValueError(f"allow and deny overlap: {', '.join(sorted(overlap))}")
        unknown_remediation = set(self.remediation) - set(self.deny)
        if unknown_remediation:
            raise ValueError(
                "remediation must only describe denied tools: "
                f"{', '.join(sorted(unknown_remediation))}"
            )
        return self


class StewardPolicy(BaseModel):
    """The portable policy document accepted by :mod:`steward.enforce`."""

    model_config = ConfigDict(extra="forbid")

    policy_version: str = POLICY_VERSION
    generated_at: datetime
    default: Literal["deny"] = "deny"
    agents: dict[str, AgentPolicy] = Field(default_factory=dict)

    @field_validator("policy_version")
    @classmethod
    def _known_version(cls, value: str) -> str:
        if value != POLICY_VERSION:
            raise ValueError(f"unsupported Steward policy version: {value}")
        return value


class PolicyDecision(BaseModel):
    """A pure policy evaluation result for a single MCP ``tools/call``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_id: str
    tool_id: str
    allowed: bool
    reason: str
    policy_version: str


def _cited_toxic_tools(finding: Finding) -> list[str]:
    """Return the pair of cited tool IDs for a valid toxic-combination finding."""

    if finding.check_type != "sod":
        return []
    tool_ids = sorted(
        {
            evidence.entity_id
            for evidence in finding.evidence
            if evidence.entity_type == "tool"
        }
    )
    # v0.1 toxic-combination findings are pairs.  Do not turn an unexpected
    # malformed/non-pair finding into an unreviewable broad deny.
    return tool_ids if len(tool_ids) == 2 else []


def _choose_tool_to_deny(tool_ids: list[str]) -> str:
    """Choose the least-privilege break point for one cited toxic pair."""

    return min(tool_ids, key=lambda tool_id: (_DENY_PREFERENCE.get(tool_id, 50), tool_id))


def _deterministic_needed_tools(result: AnalysisResult, agent_id: str) -> set[str]:
    """Derive a conservative allow-list without an optional model inference.

    If an enriched result carries a concrete Granted-vs-Needed gap, it is the
    strongest available signal.  Otherwise, an available usage log is the
    deterministic evidence of an agent's operational need.  Agents without
    telemetry receive no allow-list entries and remain default-denied.
    """

    agent = result.fleet.agent_by_id(agent_id)
    direct_grants = set(agent.granted_tools)
    effective_tools = set(result.effective_access.get(agent_id, agent.granted_tools))
    if agent_id in result.granted_vs_needed_gaps:
        inferred_needed = effective_tools - set(result.granted_vs_needed_gaps[agent_id])
        return direct_grants & inferred_needed
    if agent.usage_log_available:
        return direct_grants & set(agent.usage_log)
    return set()


def generate_policy(result: AnalysisResult, *, generated_at: datetime | None = None) -> StewardPolicy:
    """Generate a replayable, default-deny policy from existing analysis facts.

    Every fleet identity gets a stanza so unknown tools and unrecognized agents
    are denied by default.  Each SoD finding contributes an explicit deny for
    one of its graph-cited tool IDs.  This keeps remediation traceable to a
    real finding while allowing the policy to remain useful in zero-key mode.
    """

    toxic_denies: dict[str, dict[str, list[str]]] = {}
    for finding in sorted(result.findings, key=lambda item: item.id):
        tool_ids = _cited_toxic_tools(finding)
        if not tool_ids:
            continue
        tool_id = _choose_tool_to_deny(tool_ids)
        toxic_denies.setdefault(finding.agent_id, {}).setdefault(tool_id, []).append(finding.id)

    agents: dict[str, AgentPolicy] = {}
    for agent in sorted(result.fleet.agents, key=lambda item: item.id):
        deny_reasons = toxic_denies.get(agent.id, {})
        denied = set(deny_reasons)
        allow = _deterministic_needed_tools(result, agent.id) - denied
        remediation = {
            tool_id: redact_text(
                "Denied by Steward to break cited toxic combination finding(s): "
                + ", ".join(sorted(finding_ids))
                + "."
            )
            for tool_id, finding_ids in sorted(deny_reasons.items())
        }
        agents[agent.id] = AgentPolicy(
            allow=sorted(allow),
            deny=sorted(denied),
            remediation=remediation,
        )

    return StewardPolicy(
        generated_at=generated_at or datetime.now(UTC),
        agents=agents,
    )


def evaluate_policy(policy: StewardPolicy, agent_id: str, tool_id: str) -> PolicyDecision:
    """Evaluate one tool invocation against a default-deny Steward policy."""

    agent_policy = policy.agents.get(agent_id)
    if agent_policy is None:
        return PolicyDecision(
            agent_id=agent_id,
            tool_id=tool_id,
            allowed=False,
            reason="Unknown agent; Steward policies are default-deny.",
            policy_version=policy.policy_version,
        )
    if tool_id in agent_policy.deny:
        return PolicyDecision(
            agent_id=agent_id,
            tool_id=tool_id,
            allowed=False,
            reason=agent_policy.remediation.get(
                tool_id, "Tool is explicitly denied by the Steward policy."
            ),
            policy_version=policy.policy_version,
        )
    if tool_id in agent_policy.allow:
        return PolicyDecision(
            agent_id=agent_id,
            tool_id=tool_id,
            allowed=True,
            reason="Tool is on this agent's Steward least-privilege allow-list.",
            policy_version=policy.policy_version,
        )
    return PolicyDecision(
        agent_id=agent_id,
        tool_id=tool_id,
        allowed=False,
        reason="Tool is not on this agent's Steward least-privilege allow-list.",
        policy_version=policy.policy_version,
    )


def write_policy(policy: StewardPolicy, path: str | Path) -> Path:
    """Write a human-readable YAML policy, suitable for offline review."""

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = policy.model_dump(mode="json")
    target.write_text(yaml.safe_dump(payload, sort_keys=True), encoding="utf-8")
    return target


def load_policy(path: str | Path) -> StewardPolicy:
    """Load and validate a policy emitted by :func:`write_policy`."""

    source = Path(path)
    raw: Any = yaml.safe_load(source.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"policy document {source} must contain a mapping")
    return StewardPolicy.model_validate(raw)
