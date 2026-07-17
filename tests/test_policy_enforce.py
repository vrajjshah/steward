from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from fastapi.testclient import TestClient

from steward.enforce import JSONRPC_POLICY_DENIED, MCPToolCallGate, create_enforcement_app
from steward.findings import analyze_fleet
from steward.ledger import AuditLedger
from steward.loaders import load_inventory
from steward.policy_gen import generate_policy, load_policy, write_policy
from steward.redteam import EXFIL_AGENT_ID, exfiltration_attack_request, run_exfiltration_scenario


class RecordingLedger:
    """The ledger seam used by policy-gate tests without key material."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def __call__(
        self, event_type: str, payload: Mapping[str, Any], *, policy_version: str | None
    ) -> None:
        self.events.append(
            {
                "event_type": event_type,
                "payload": dict(payload),
                "policy_version": policy_version,
            }
        )


def _deterministic_policy():
    fleet, tools = load_inventory("data/fleet.json", "data/tools.json")
    result = analyze_fleet(fleet, tools)
    return generate_policy(result, generated_at=datetime(2026, 7, 18, tzinfo=UTC))


def test_policy_generation_is_default_deny_and_breaks_supportbot_exfiltration(tmp_path) -> None:
    policy = _deterministic_policy()

    support = policy.agents["support_bot"]
    assert policy.default == "deny"
    assert support.allow == ["read_customer_pii"]
    assert support.deny == ["send_external_email"]
    assert "sod:support_bot:sensitive_data_external_egress" in support.remediation[
        "send_external_email"
    ]
    # The unused direct grants are also closed in a zero-key run through the
    # deterministic usage-log fallback.
    assert policy.agents["report_bot"].allow == ["read_db"]
    assert {"delete_records", "export_data"}.isdisjoint(policy.agents["report_bot"].allow)

    path = write_policy(policy, tmp_path / "policy.yaml")
    serialized = path.read_text(encoding="utf-8")
    assert "default: deny" in serialized
    assert load_policy(path) == policy


def test_policy_generation_prefers_concrete_granted_vs_needed_gaps_over_usage() -> None:
    fleet, tools = load_inventory("data/fleet.json", "data/tools.json")
    result = analyze_fleet(fleet, tools).model_copy(
        update={"granted_vs_needed_gaps": {"sales_assist_bot": ["draft_customer_email"]}}
    )

    policy = generate_policy(result, generated_at=datetime(2026, 7, 18, tzinfo=UTC))

    # Both grants appear in the historical usage log, but the concrete
    # Granted-vs-Needed signal is more specific and therefore wins.
    assert policy.agents["sales_assist_bot"].allow == ["read_crm"]


def test_policy_gate_denies_exfiltration_and_never_records_argument_values() -> None:
    policy = _deterministic_policy()
    ledger = RecordingLedger()
    upstream_calls: list[Mapping[str, Any]] = []

    def upstream(request: Mapping[str, Any]) -> dict[str, Any]:
        upstream_calls.append(request)
        return {"jsonrpc": "2.0", "id": request.get("id"), "result": {"status": "sent"}}

    gate = MCPToolCallGate(policy, upstream, ledger_append=ledger)
    planted_secret = "sk-ENFORCEMENT_LEDGER_SECRET_9kLm8Pq2X"
    attack = exfiltration_attack_request()
    attack["params"]["arguments"]["body"] = f"token={planted_secret}"
    response = gate.handle(EXFIL_AGENT_ID, attack)

    assert response["error"]["code"] == JSONRPC_POLICY_DENIED
    assert upstream_calls == []
    assert ledger.events[-1]["event_type"] == "enforcement"
    payload = ledger.events[-1]["payload"]
    assert payload["decision"] == "deny"
    assert payload["arguments_sha256"] == hashlib.sha256(
        json.dumps(attack["params"]["arguments"], sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    persisted = json.dumps(ledger.events)
    assert planted_secret not in persisted
    assert payload["arguments_metadata"] == {
        "type": "object",
        "keys": ["body", "subject", "to"],
    }


def test_fastapi_gate_forwards_allow_and_default_denies_unknown_tool() -> None:
    policy = _deterministic_policy()
    ledger = RecordingLedger()
    upstream_calls: list[Mapping[str, Any]] = []

    def upstream(request: Mapping[str, Any]) -> dict[str, Any]:
        upstream_calls.append(request)
        return {"jsonrpc": "2.0", "id": request.get("id"), "result": {"forwarded": True}}

    client = TestClient(create_enforcement_app(policy, upstream, ledger_append=ledger))
    allowed = client.post(
        "/mcp/support_bot",
        json={
            "jsonrpc": "2.0",
            "id": "allow-1",
            "method": "tools/call",
            "params": {"name": "read_customer_pii", "arguments": {"case_id": "CASE-001"}},
        },
    )
    denied = client.post(
        "/mcp/support_bot",
        json={
            "jsonrpc": "2.0",
            "id": "deny-1",
            "method": "tools/call",
            "params": {"name": "unlisted_tool", "arguments": {}},
        },
    )

    assert allowed.status_code == 200
    assert allowed.json()["result"] == {"forwarded": True}
    assert denied.status_code == 200
    assert denied.json()["error"]["code"] == JSONRPC_POLICY_DENIED
    assert len(upstream_calls) == 1
    assert [event["payload"]["decision"] for event in ledger.events] == ["allow", "deny"]


def test_guarded_redteam_scenario_produces_a_ledger_deny_event() -> None:
    ledger = RecordingLedger()
    result = run_exfiltration_scenario(_deterministic_policy(), ledger_append=ledger)

    assert result.unguarded_succeeded
    assert result.guarded_blocked
    # The direct upstream invocation succeeds once; the denied guarded request
    # is never forwarded.
    assert result.upstream_calls == 1
    assert ledger.events[-1]["event_type"] == "enforcement"
    assert ledger.events[-1]["payload"]["decision"] == "deny"
    assert ledger.events[-1]["payload"]["tool_id"] == "send_external_email"


def test_guarded_redteam_deny_reaches_the_real_signed_ledger(tmp_path) -> None:
    """The gate's injected seam is compatible with the actual audit store."""

    ledger = AuditLedger(tmp_path / ".steward")
    ledger.initialize()

    result = run_exfiltration_scenario(_deterministic_policy(), ledger_append=ledger.append)

    assert result.unguarded_succeeded
    assert result.guarded_blocked
    verified = ledger.verify()
    assert verified.valid
    assert verified.entry_count == 1
    persisted = json.loads(ledger.export_jsonl())
    assert persisted["event_type"] == "enforcement"
    assert persisted["payload"]["decision"] == "deny"
    assert persisted["payload"]["tool_id"] == "send_external_email"
    assert len(persisted["payload"]["arguments_sha256"]) == 64
    assert persisted["payload"]["arguments_metadata"] == {
        "type": "object",
        "keys": ["body", "subject", "to"],
    }
