"""Security properties for Steward's signed, append-only audit ledger."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from steward.ledger import AuditLedger, LedgerError, redact_ledger_payload


def _ledger(tmp_path) -> AuditLedger:  # type: ignore[no-untyped-def]
    ledger = AuditLedger(tmp_path / ".steward")
    paths = ledger.initialize()
    assert paths.private_key_path.exists()
    assert paths.public_key_path.exists()
    return ledger


def test_append_verify_and_export_are_signed_and_chained(tmp_path) -> None:
    ledger = _ledger(tmp_path)
    first = ledger.append_finding(
        {"finding_id": "supportbot-exfil", "agent_id": "support_bot"},
        policy_version="0.1",
    )
    second = ledger.append_certification(
        {"agent_id": "support_bot", "decision": "revoke"}, policy_version="policy-2026-01"
    )
    third = ledger.append_enforcement(
        {"agent_id": "support_bot", "tool_id": "send_external_email", "decision": "deny"}
    )

    verified = ledger.verify()
    assert verified.valid
    assert verified.entry_count == 3
    assert verified.head_hash
    assert first.prev_hash is None
    assert second.prev_hash
    assert third.prev_hash

    lines = ledger.export_jsonl().splitlines()
    assert len(lines) == 3
    entries = [json.loads(line) for line in lines]
    assert entries[0]["event_type"] == "finding"
    assert entries[1]["prev_hash"] == second.prev_hash
    assert entries[2]["prev_hash"] == third.prev_hash
    assert "signature" in entries[0]


def test_ledger_payload_hashes_arguments_and_redacts_secret_metadata(tmp_path) -> None:
    ledger = _ledger(tmp_path)
    planted_secret = "sk-LEDGER-PLANTED-SECRET_1a2B3c4D5e6F"
    pii_email = "customer.alice@example.test"
    ledger.append_enforcement(
        {
            "agent_id": "support_bot",
            "arguments": {"to": pii_email, "api_key": planted_secret, "subject": "Account issue"},
            "metadata": {
                "env": {"POSTMARK_TOKEN": planted_secret},
                "tool_id": "send_external_email",
            },
        }
    )

    persisted = ledger.export_jsonl()
    assert planted_secret not in persisted
    assert pii_email not in persisted
    record = json.loads(persisted)
    assert record["payload"]["arguments"]["redacted"] is True
    assert len(record["payload"]["arguments"]["sha256"]) == 64
    assert record["payload"]["metadata"]["env"]["POSTMARK_TOKEN"] == "[REDACTED]"


def test_redact_ledger_payload_commits_common_pii_fields() -> None:
    payload = redact_ledger_payload(
        {"recipient": "alice@example.test", "safe_metadata": {"agent_id": "support_bot"}}
    )

    assert payload["recipient"]["redacted"] is True
    assert "alice@example.test" not in json.dumps(payload)
    assert payload["safe_metadata"]["agent_id"] == "support_bot"


def test_ledger_retains_an_explicit_valid_argument_hash() -> None:
    arguments_hash = "a" * 64
    payload = redact_ledger_payload(
        {
            "arguments_sha256": arguments_hash,
            "arguments_metadata": {"keys": ["recipient"], "items": 1},
        }
    )

    assert payload["arguments_sha256"] == arguments_hash
    assert payload["arguments_metadata"] == {"keys": ["recipient"], "items": 1}


def test_ledger_commits_email_variants_and_redacts_camel_case_secret_fields() -> None:
    planted_email = "alice@example.test"
    planted_secret = "plain-text-client-secret"
    payload = redact_ledger_payload(
        {"customerEmail": planted_email, "clientSecret": planted_secret}
    )

    serialized = json.dumps(payload)
    assert planted_email not in serialized
    assert planted_secret not in serialized
    assert payload["customerEmail"]["redacted"] is True
    assert payload["clientSecret"] == "[REDACTED]"


def test_init_replaces_a_published_stale_key_only_when_the_ledger_is_empty(tmp_path) -> None:
    ledger = _ledger(tmp_path)
    original_public_key = ledger.export_public_key()
    ledger.paths.private_key_path.unlink()

    # This mirrors a fresh clone: a published public key is present, but no
    # local signing key or audit history exists yet.
    ledger.initialize()
    assert ledger.paths.private_key_path.exists()
    assert ledger.export_public_key() != original_public_key

    ledger.append_finding({"finding_id": "already-signed"})
    ledger.paths.private_key_path.unlink()
    with pytest.raises(LedgerError, match="non-empty ledger"):
        ledger.initialize()


def test_public_key_alone_can_verify_a_signed_ledger_offline(tmp_path) -> None:
    ledger = _ledger(tmp_path)
    ledger.append_finding({"finding_id": "offline-verification"})
    ledger.paths.private_key_path.unlink()

    verified = ledger.verify()
    assert verified.valid
    assert verified.entry_count == 1


def test_verify_reports_the_first_tampered_sequence_and_append_refuses(tmp_path) -> None:
    ledger = _ledger(tmp_path)
    ledger.append_finding({"finding_id": "first"})
    ledger.append_certification({"decision": "flag"})

    contents = bytearray(ledger.paths.ledger_path.read_bytes())
    offset = contents.index(b"first")
    contents[offset] = ord("F")
    ledger.paths.ledger_path.write_bytes(contents)

    verified = ledger.verify()
    assert not verified.valid
    assert verified.broken_index == 1
    assert verified.reason
    with pytest.raises(LedgerError, match="tampered ledger at entry 1"):
        ledger.append_enforcement({"decision": "deny"})


@settings(max_examples=12, deadline=None)
@given(
    payloads=st.lists(
        st.dictionaries(
            keys=st.sampled_from(["finding_id", "agent_id", "tool_id", "decision"]),
            values=st.text(max_size=32),
            min_size=1,
            max_size=4,
        ),
        min_size=1,
        max_size=5,
    )
)
def test_every_single_byte_mutation_is_detected_at_its_entry(payloads) -> None:  # type: ignore[no-untyped-def]
    """The core tamper-evidence claim: every single-byte change is caught."""

    with TemporaryDirectory() as temporary_directory:
        ledger = _ledger(Path(temporary_directory))
        for index, payload in enumerate(payloads):
            event_type = ("finding", "certification", "enforcement")[index % 3]
            ledger.append(event_type, payload)
        assert ledger.verify().valid

        original = ledger.paths.ledger_path.read_bytes()
        for position, original_byte in enumerate(original):
            expected_index = original[:position].count(b"\n") + 1
            tampered = bytearray(original)
            tampered[position] = (original_byte + 1) % 256
            ledger.paths.ledger_path.write_bytes(tampered)

            verified = ledger.verify()
            assert not verified.valid
            assert verified.broken_index == expected_index

        ledger.paths.ledger_path.write_bytes(original)
