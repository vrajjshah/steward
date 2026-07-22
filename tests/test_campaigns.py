"""Tests for recurring certification campaigns (R4)."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

import pytest
from typer.testing import CliRunner

from steward.campaigns import (
    Campaign,
    CampaignError,
    CampaignScope,
    Decision,
    campaign_report_summary,
    close_campaign,
    load_store,
    record_decision,
    resolve_scope,
    save_store,
    start_campaign,
)
from steward.cli import app
from steward.findings import analyze_fleet
from steward.ledger import AuditLedger
from steward.models import Fleet, ToolCatalog
from steward.reporting import build_fleet_audit_report, render_markdown_report

runner = CliRunner()


def _tools() -> ToolCatalog:
    return ToolCatalog.model_validate(
        {
            "tools": [
                {"id": "create_vendor", "name": "Create vendor"},
                {"id": "approve_payment", "name": "Approve payment"},
                {"id": "read_calendar", "name": "Read calendar"},
            ]
        }
    )


def _result():
    fleet = Fleet.model_validate(
        {
            "agents": [
                {
                    "id": "crit_bot",
                    "name": "CritBot",
                    "owner": "Finance",
                    "granted_tools": ["create_vendor", "approve_payment"],
                    "usage_log": ["create_vendor", "approve_payment"],
                },
                {
                    "id": "clean_bot",
                    "name": "CleanBot",
                    "owner": "Ops",
                    "granted_tools": ["read_calendar"],
                    "usage_log": ["read_calendar"],
                },
            ]
        }
    )
    return analyze_fleet(fleet, _tools())


def _ledger(tmp_path) -> AuditLedger:
    ledger = AuditLedger(tmp_path)
    ledger.initialize()
    return ledger


def test_scope_resolution() -> None:
    result = _result()
    assert resolve_scope(CampaignScope(kind="all"), result) == ["clean_bot", "crit_bot"]
    assert resolve_scope(
        CampaignScope(kind="min_severity", min_severity="critical"), result
    ) == ["crit_bot"]
    assert resolve_scope(
        CampaignScope(kind="min_risk_score", min_risk_score=1), result
    ) == ["crit_bot"]
    assert resolve_scope(
        CampaignScope(kind="agents", agent_ids=["clean_bot"]), result
    ) == ["clean_bot"]
    with pytest.raises(CampaignError, match="unknown agents"):
        resolve_scope(CampaignScope(kind="agents", agent_ids=["ghost"]), result)


def test_full_lifecycle_and_chain_verifies(tmp_path) -> None:
    ledger = _ledger(tmp_path)
    store = load_store(tmp_path)
    campaign = start_campaign(
        store,
        ledger,
        name="Q3 Recert",
        scope=CampaignScope(kind="all"),
        result=_result(),
    )
    assert campaign.id == "q3-recert"
    assert set(campaign.agent_ids) == {"crit_bot", "clean_bot"}

    for agent_id in campaign.agent_ids:
        record_decision(
            store, ledger, campaign_id=campaign.id, agent_id=agent_id, decision="approve"
        )
    assert campaign.is_complete()
    assert campaign.completion_pct() == 100

    # A complete campaign closes without force.
    close_campaign(store, ledger, campaign_id=campaign.id)
    assert campaign.status() == "closed"

    # Start + 2 decisions + close = 4 signed events, and the chain still verifies.
    verification = ledger.verify()
    assert verification.valid
    assert verification.entry_count == 4


def test_overdue_derivation() -> None:
    past = date.today() - timedelta(days=1)
    future = date.today() + timedelta(days=7)
    base = dict(
        id="c",
        name="C",
        scope=CampaignScope(kind="all"),
        agent_ids=["a", "b"],
        created_at=datetime.now(UTC),
    )
    overdue = Campaign(**base, due_at=past)
    assert overdue.status() == "overdue"
    not_yet = Campaign(**base, due_at=future)
    assert not_yet.status() == "open"
    # A complete campaign is never overdue, even past its due date.
    complete = Campaign(**base, due_at=past)
    for agent_id in ("a", "b"):
        complete.decisions[agent_id] = Decision(
            agent_id=agent_id, decision="approve", decided_at=datetime.now(UTC)
        )
    assert complete.status() == "complete"


def test_close_incomplete_requires_force_and_reason(tmp_path) -> None:
    ledger = _ledger(tmp_path)
    store = load_store(tmp_path)
    campaign = start_campaign(
        store, ledger, name="Partial", scope=CampaignScope(kind="all"), result=_result()
    )
    record_decision(
        store, ledger, campaign_id=campaign.id, agent_id="crit_bot", decision="revoke"
    )
    with pytest.raises(CampaignError, match="undecided"):
        close_campaign(store, ledger, campaign_id=campaign.id)
    with pytest.raises(CampaignError, match="requires a --reason"):
        close_campaign(store, ledger, campaign_id=campaign.id, force=True)
    close_campaign(
        store, ledger, campaign_id=campaign.id, force=True, reason="window ended"
    )
    assert campaign.forced_close is True
    assert campaign.close_reason == "window ended"


def test_decide_rejects_out_of_scope_and_bad_decision(tmp_path) -> None:
    ledger = _ledger(tmp_path)
    store = load_store(tmp_path)
    campaign = start_campaign(
        store,
        ledger,
        name="Scoped",
        scope=CampaignScope(kind="agents", agent_ids=["crit_bot"]),
        result=_result(),
    )
    with pytest.raises(CampaignError, match="not in this campaign"):
        record_decision(
            store, ledger, campaign_id=campaign.id, agent_id="clean_bot", decision="approve"
        )
    with pytest.raises(CampaignError, match="approve|revoke|flag"):
        record_decision(
            store, ledger, campaign_id=campaign.id, agent_id="crit_bot", decision="maybe"
        )


def test_state_survives_restart(tmp_path) -> None:
    ledger = _ledger(tmp_path)
    store = load_store(tmp_path)
    campaign = start_campaign(
        store, ledger, name="Persisted", scope=CampaignScope(kind="all"), result=_result()
    )
    record_decision(
        store,
        ledger,
        campaign_id=campaign.id,
        agent_id="crit_bot",
        decision="flag",
        note="needs finance sign-off",
    )
    save_store(tmp_path, store)

    # A fresh process reloads the same state from disk.
    reloaded = load_store(tmp_path)
    restored = reloaded.campaigns[campaign.id]
    assert restored.decisions["crit_bot"].decision == "flag"
    assert restored.decisions["crit_bot"].note == "needs finance sign-off"
    assert set(restored.agent_ids) == {"crit_bot", "clean_bot"}


def test_report_includes_campaign_summary(tmp_path) -> None:
    ledger = _ledger(tmp_path)
    store = load_store(tmp_path)
    result = _result()
    start_campaign(store, ledger, name="Q3", scope=CampaignScope(kind="all"), result=result)
    summary = campaign_report_summary(store)
    assert summary["total"] == 1
    assert summary["open"] == 1

    report = build_fleet_audit_report(result.fleet, result.findings, campaigns=summary)
    assert report["executive_summary"]["certification_campaigns"]["open"] == 1
    assert report["certification_campaigns"]["total"] == 1
    rendered = render_markdown_report(report)
    assert "## Certification campaigns" in rendered
    assert "Q3" in rendered


def test_report_without_campaigns_is_unchanged() -> None:
    result = _result()
    report = build_fleet_audit_report(result.fleet, result.findings)
    assert report["certification_campaigns"] is None
    assert "certification_campaigns" not in report["executive_summary"]


def test_cli_campaign_status_empty(tmp_path, cli_text) -> None:
    result = runner.invoke(app, ["campaign", "status", "--state-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "No certification campaigns" in cli_text(result)


def test_cli_campaign_start_requires_initialized_ledger(tmp_path, cli_text) -> None:
    result = runner.invoke(
        app,
        ["campaign", "start", "--name", "X", "--scope-all", "--state-dir", str(tmp_path)],
    )
    assert result.exit_code != 0
    # cli_text normalizes the panel that CI wraps this long (tmp-path) message into.
    assert "steward init" in cli_text(result)
