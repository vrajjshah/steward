"""Integration coverage for the optional signed-ledger flow around Steward surfaces."""

from __future__ import annotations

from typer.testing import CliRunner

from steward.cli import app
from steward.ledger import AuditLedger
from steward.web_service import StewardService


def test_dashboard_findings_and_certification_decision_are_signed_without_note_contents(
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    ledger = AuditLedger(tmp_path / ".steward")
    ledger.initialize()
    service = StewardService(demo_mode=True, ledger=ledger)

    analysis = service.analyze()
    assert analysis["findings"]
    assert ledger.verify().entry_count == len(analysis["findings"])

    planted_secret = "sk-CERTIFICATION-NOTE-SECRET_7h8J9kLm"
    service.record_review("support_bot", "revoke", f"reason: token={planted_secret}")

    verified = ledger.verify()
    assert verified.valid
    assert verified.entry_count == len(analysis["findings"]) + 1
    persisted = ledger.export_jsonl()
    assert planted_secret not in persisted
    assert '"event_type":"certification"' in persisted
    assert '"note":{"redacted":true' in persisted


def test_zero_key_cli_detect_close_prove_loop(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The public commands work with crypto only—no Bedrock/API key is involved."""

    runner = CliRunner()
    state_dir = tmp_path / ".steward"
    policy_path = tmp_path / "policy.yaml"

    initialized = runner.invoke(app, ["init", "--state-dir", str(state_dir)])
    assert initialized.exit_code == 0, initialized.output

    analyzed = runner.invoke(
        app,
        ["analyze", "--no-llm", "--state-dir", str(state_dir)],
    )
    assert analyzed.exit_code == 0, analyzed.output
    assert "Critical data-exfiltration path" in analyzed.output

    generated = runner.invoke(
        app,
        [
            "policy",
            "generate",
            "--output",
            str(policy_path),
        ],
    )
    assert generated.exit_code == 0, generated.output
    assert policy_path.is_file()

    redteam = runner.invoke(
        app,
        ["redteam", "exfil", "--policy", str(policy_path), "--state-dir", str(state_dir)],
    )
    assert redteam.exit_code == 0, redteam.output
    assert "UNGUARDED: SUCCEEDED" in redteam.output
    assert "GUARDED: BLOCKED" in redteam.output

    verified = runner.invoke(app, ["audit", "verify", "--state-dir", str(state_dir)])
    assert verified.exit_code == 0, verified.output
    assert "chain valid" in verified.output
