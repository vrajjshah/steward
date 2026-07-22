"""Recurring access-certification campaigns (R4).

A campaign is a scoped review session: pick a set of agents (explicitly, or by a
severity / risk-score filter, or all of them), record an approve / revoke / flag
decision with a note for each, and close it. Every lifecycle event — start,
decision, close — appends a signed event to the existing Ed25519 audit ledger,
so the record of *who certified what, when* is tamper-evident. Campaign state
lives in ``campaigns.json`` beside the ledger and survives process restarts.

Honest scope: this is a single-reviewer local workflow with a tamper-evident
evidence trail — not multi-approver enterprise routing, delegation of reviews,
or SoD on the reviewers themselves. It gives a small team a real recurring
recertification loop, not an IGA platform's campaign engine.
"""

from __future__ import annotations

import re
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from .ledger import AuditLedger
from .models import AnalysisResult

DecisionType = Literal["approve", "revoke", "flag"]
CampaignStatus = Literal["open", "complete", "overdue", "closed"]
ScopeKind = Literal["agents", "min_severity", "min_risk_score", "all"]
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_CAMPAIGN_POLICY_VERSION = "steward-campaign/v0.1"


class CampaignError(ValueError):
    """Raised for an invalid campaign operation (bad scope, closed campaign, …)."""


class CampaignScope(BaseModel):
    """How a campaign selects the agents it certifies."""

    kind: ScopeKind
    agent_ids: list[str] = Field(default_factory=list)
    min_severity: str | None = None
    min_risk_score: int | None = None

    def describe(self) -> str:
        if self.kind == "all":
            return "all agents"
        if self.kind == "agents":
            return f"agents: {', '.join(self.agent_ids)}"
        if self.kind == "min_severity":
            return f"findings at or above severity {self.min_severity}"
        return f"findings with risk score >= {self.min_risk_score}"


class Decision(BaseModel):
    """One reviewer decision recorded against an agent in a campaign."""

    agent_id: str
    decision: DecisionType
    note: str = ""
    decided_at: datetime


class Campaign(BaseModel):
    """A scoped recertification session and its recorded decisions."""

    id: str
    name: str
    scope: CampaignScope
    agent_ids: list[str]
    created_at: datetime
    due_at: date | None = None
    closed_at: datetime | None = None
    close_reason: str | None = None
    forced_close: bool = False
    decisions: dict[str, Decision] = Field(default_factory=dict)

    def is_complete(self) -> bool:
        return all(agent_id in self.decisions for agent_id in self.agent_ids)

    def completion_pct(self) -> int:
        if not self.agent_ids:
            return 100
        decided = sum(1 for agent_id in self.agent_ids if agent_id in self.decisions)
        return round(100 * decided / len(self.agent_ids))

    def pending_agent_ids(self) -> list[str]:
        return [agent_id for agent_id in self.agent_ids if agent_id not in self.decisions]

    def status(self, *, now: datetime | None = None) -> CampaignStatus:
        if self.closed_at is not None:
            return "closed"
        if self.is_complete():
            return "complete"
        now = now or datetime.now(UTC)
        if self.due_at is not None and now.date() > self.due_at:
            return "overdue"
        return "open"


class CampaignStore(BaseModel):
    """The persisted set of campaigns for a state directory."""

    version: str = "0.1"
    campaigns: dict[str, Campaign] = Field(default_factory=dict)


# --- persistence ----------------------------------------------------------


def _campaigns_path(state_dir: Path | str) -> Path:
    return Path(state_dir) / "campaigns.json"


def load_store(state_dir: Path | str) -> CampaignStore:
    """Load the campaign store, or an empty one if none exists yet."""

    path = _campaigns_path(state_dir)
    if not path.exists():
        return CampaignStore()
    return CampaignStore.model_validate_json(path.read_text(encoding="utf-8"))


def save_store(state_dir: Path | str, store: CampaignStore) -> None:
    """Persist the campaign store beside the ledger."""

    path = _campaigns_path(state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(store.model_dump_json(indent=2) + "\n", encoding="utf-8")


# --- scope ----------------------------------------------------------------


def resolve_scope(scope: CampaignScope, result: AnalysisResult) -> list[str]:
    """Return the sorted agent ids a scope selects against an analysis result."""

    fleet_ids = {agent.id for agent in result.fleet.agents}
    if scope.kind == "all":
        return sorted(fleet_ids)
    if scope.kind == "agents":
        if not scope.agent_ids:
            raise CampaignError("an 'agents' scope needs at least one agent id")
        unknown = sorted(set(scope.agent_ids) - fleet_ids)
        if unknown:
            raise CampaignError(f"unknown agents in scope: {', '.join(unknown)}")
        return sorted(set(scope.agent_ids))
    if scope.kind == "min_severity":
        threshold = SEVERITY_ORDER.get((scope.min_severity or "").strip().lower())
        if threshold is None:
            raise CampaignError("min_severity must be one of critical|high|medium|low")
        selected = {
            finding.agent_id
            for finding in result.findings
            if SEVERITY_ORDER.get(finding.severity, 0) >= threshold
        }
        return sorted(selected & fleet_ids)
    # min_risk_score
    threshold = scope.min_risk_score if scope.min_risk_score is not None else 0
    selected = {
        finding.agent_id
        for finding in result.findings
        if (finding.risk_score or 0) >= threshold
    }
    return sorted(selected & fleet_ids)


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
    return slug or "campaign"


def _unique_id(store: CampaignStore, base: str) -> str:
    if base not in store.campaigns:
        return base
    index = 2
    while f"{base}-{index}" in store.campaigns:
        index += 1
    return f"{base}-{index}"


def _require_campaign(store: CampaignStore, campaign_id: str) -> Campaign:
    campaign = store.campaigns.get(campaign_id)
    if campaign is None:
        raise CampaignError(f"no campaign with id {campaign_id!r}")
    return campaign


# --- lifecycle (each op appends a signed ledger event) --------------------


def start_campaign(
    store: CampaignStore,
    ledger: AuditLedger,
    *,
    name: str,
    scope: CampaignScope,
    result: AnalysisResult,
    due_at: date | None = None,
    now: datetime | None = None,
) -> Campaign:
    """Open a campaign over the scoped agents and sign the event."""

    if not name.strip():
        raise CampaignError("a campaign needs a non-empty name")
    now = now or datetime.now(UTC)
    agent_ids = resolve_scope(scope, result)
    campaign_id = _unique_id(store, _slugify(name))
    campaign = Campaign(
        id=campaign_id,
        name=name.strip(),
        scope=scope,
        agent_ids=agent_ids,
        created_at=now,
        due_at=due_at,
    )
    # Append first: a tampered ledger raises here, before the store is mutated.
    ledger.append_certification(
        {
            "event": "campaign_started",
            "campaign_id": campaign_id,
            "name": campaign.name,
            "scope": scope.describe(),
            "agent_ids": agent_ids,
            "due_at": due_at.isoformat() if due_at else None,
        },
        policy_version=_CAMPAIGN_POLICY_VERSION,
    )
    store.campaigns[campaign_id] = campaign
    return campaign


def record_decision(
    store: CampaignStore,
    ledger: AuditLedger,
    *,
    campaign_id: str,
    agent_id: str,
    decision: str,
    note: str = "",
    now: datetime | None = None,
) -> Campaign:
    """Record an approve/revoke/flag decision for one agent and sign it."""

    campaign = _require_campaign(store, campaign_id)
    if campaign.closed_at is not None:
        raise CampaignError(f"campaign {campaign_id!r} is closed")
    if agent_id not in campaign.agent_ids:
        raise CampaignError(f"agent {agent_id!r} is not in this campaign's scope")
    if decision not in ("approve", "revoke", "flag"):
        raise CampaignError("decision must be one of approve|revoke|flag")
    now = now or datetime.now(UTC)
    ledger.append_certification(
        {
            "event": "campaign_decision",
            "campaign_id": campaign_id,
            "agent_id": agent_id,
            "decision": decision,
            "note": note,
        },
        policy_version=_CAMPAIGN_POLICY_VERSION,
    )
    campaign.decisions[agent_id] = Decision(
        agent_id=agent_id, decision=decision, note=note, decided_at=now
    )
    return campaign


def close_campaign(
    store: CampaignStore,
    ledger: AuditLedger,
    *,
    campaign_id: str,
    force: bool = False,
    reason: str | None = None,
    now: datetime | None = None,
) -> Campaign:
    """Close a campaign; an incomplete one requires force and a recorded reason."""

    campaign = _require_campaign(store, campaign_id)
    if campaign.closed_at is not None:
        raise CampaignError(f"campaign {campaign_id!r} is already closed")
    incomplete = not campaign.is_complete()
    if incomplete and not force:
        pending = campaign.pending_agent_ids()
        raise CampaignError(
            f"campaign {campaign_id!r} has {len(pending)} undecided agent(s); "
            "pass --force with --reason to close it early"
        )
    if incomplete and force and not (reason and reason.strip()):
        raise CampaignError("closing an incomplete campaign requires a --reason")
    now = now or datetime.now(UTC)
    forced_close = incomplete and force
    ledger.append_certification(
        {
            "event": "campaign_closed",
            "campaign_id": campaign_id,
            "forced": forced_close,
            "reason": reason,
            "completion_pct": campaign.completion_pct(),
            "decisions": {
                agent_id: decision.decision for agent_id, decision in campaign.decisions.items()
            },
        },
        policy_version=_CAMPAIGN_POLICY_VERSION,
    )
    campaign.closed_at = now
    campaign.close_reason = reason.strip() if reason else None
    campaign.forced_close = forced_close
    return campaign


# --- summaries and rendering ----------------------------------------------


def campaign_report_summary(store: CampaignStore, *, now: datetime | None = None) -> dict:
    """A report/exec-summary rollup: counts by status plus a per-campaign line."""

    now = now or datetime.now(UTC)
    campaigns = sorted(store.campaigns.values(), key=lambda c: c.created_at)
    statuses = [campaign.status(now=now) for campaign in campaigns]
    return {
        "total": len(campaigns),
        "open": statuses.count("open"),
        "complete": statuses.count("complete"),
        "overdue": statuses.count("overdue"),
        "closed": statuses.count("closed"),
        "campaigns": [
            {
                "id": campaign.id,
                "name": campaign.name,
                "status": status,
                "completion_pct": campaign.completion_pct(),
                "agents": len(campaign.agent_ids),
                "decided": len(campaign.decisions),
                "due_at": campaign.due_at.isoformat() if campaign.due_at else None,
            }
            for campaign, status in zip(campaigns, statuses, strict=True)
        ],
    }


def render_campaign_status(store: CampaignStore, *, now: datetime | None = None) -> str:
    """Human-readable rollup of every campaign for the CLI."""

    summary = campaign_report_summary(store, now=now)
    if not summary["total"]:
        return "No certification campaigns. Start one with `steward campaign start`."
    lines = [
        f"Certification campaigns: {summary['total']} total "
        f"({summary['open']} open, {summary['complete']} complete, "
        f"{summary['overdue']} overdue, {summary['closed']} closed)."
    ]
    for row in summary["campaigns"]:
        due = f", due {row['due_at']}" if row["due_at"] else ""
        lines.append(
            f"- {row['id']} [{row['status'].upper()}] {row['name']}: "
            f"{row['decided']}/{row['agents']} decided ({row['completion_pct']}%){due}"
        )
    return "\n".join(lines)


def render_campaign_detail(campaign: Campaign, *, now: datetime | None = None) -> str:
    """Human-readable detail for one campaign for the CLI."""

    lines = [
        f"Campaign {campaign.id} [{campaign.status(now=now).upper()}]: {campaign.name}",
        f"Scope: {campaign.scope.describe()} ({len(campaign.agent_ids)} agents, "
        f"{campaign.completion_pct()}% decided).",
    ]
    if campaign.due_at:
        lines.append(f"Due: {campaign.due_at.isoformat()}")
    if campaign.closed_at:
        note = f" (forced: {campaign.close_reason})" if campaign.forced_close else ""
        lines.append(f"Closed: {campaign.closed_at.isoformat()}{note}")
    for agent_id in campaign.agent_ids:
        decision = campaign.decisions.get(agent_id)
        if decision is None:
            lines.append(f"- {agent_id}: (undecided)")
        else:
            note = f" — {decision.note}" if decision.note else ""
            lines.append(f"- {agent_id}: {decision.decision.upper()}{note}")
    return "\n".join(lines)
