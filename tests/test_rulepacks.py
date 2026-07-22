"""Tests for custom SoD rule packs and additive detection (R3)."""

from __future__ import annotations

from pathlib import Path

import pytest

from steward.capability_classes import DEFAULT_CAPABILITY_CLASSES
from steward.findings import BUILTIN_RULE_IDS, analyze_fleet
from steward.graph import EffectiveAccessGraph
from steward.loaders import load_inventory
from steward.models import Evidence, Finding, Fleet, ToolCatalog
from steward.rulepacks import (
    RulePackError,
    inert_rule_ids,
    load_rule_pack,
    load_rule_packs,
    merge_rule_packs,
)
from steward.scoring import score_finding

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE_PACK = PROJECT_ROOT / "examples" / "rules" / "finance_sod_pack.yaml"


def _erp_tools() -> ToolCatalog:
    return ToolCatalog.model_validate(
        {
            "tools": [
                {"id": name, "name": name}
                for name in (
                    "post_journal_entry",
                    "approve_journal_entry",
                    "read_bank_statements",
                    "ingest_vendor_invoice_email",
                    "export_financial_report",
                    "release_payment_run",
                )
            ]
        }
    )


def _erp_fleet() -> Fleet:
    return Fleet.model_validate(
        {
            "agents": [
                {
                    "id": "ledger_bot",
                    "name": "LedgerBot",
                    "owner": "Controller",
                    "granted_tools": ["post_journal_entry", "approve_journal_entry"],
                    "usage_log": ["post_journal_entry", "approve_journal_entry"],
                },
                {
                    "id": "treasury_bot",
                    "name": "TreasuryBot",
                    "owner": "Treasury",
                    "granted_tools": [
                        "read_bank_statements",
                        "ingest_vendor_invoice_email",
                        "export_financial_report",
                    ],
                    "usage_log": [
                        "read_bank_statements",
                        "ingest_vendor_invoice_email",
                        "export_financial_report",
                    ],
                },
            ]
        }
    )


def test_example_pack_loads() -> None:
    pack = load_rule_pack(EXAMPLE_PACK)
    assert pack.sod_rules
    assert pack.delegated_rules
    assert "release_payment_run" in pack.capability_classes.high_impact


def test_pack_toxic_rule_fires_as_deterministic_finding() -> None:
    pack = load_rule_pack(EXAMPLE_PACK)
    result = analyze_fleet(_erp_fleet(), _erp_tools(), rule_pack=pack)
    sod = next(
        f
        for f in result.findings
        if f.agent_id == "ledger_bot" and f.rule_id == "erp_post_and_approve_journal"
    )
    assert sod.source == "deterministic"
    assert sod.check_type == "sod"
    # Check-type-based control-framework annotation applies to pack findings.
    assert sod.control_frameworks


def test_capability_extension_completes_trifecta() -> None:
    # treasury_bot's three legs are all pack-declared tool ids; without the
    # pack's capability_classes extension the trifecta cannot be detected.
    pack = load_rule_pack(EXAMPLE_PACK)
    with_pack = analyze_fleet(_erp_fleet(), _erp_tools(), rule_pack=pack)
    assert any(
        f.agent_id == "treasury_bot" and f.rule_id == "lethal_trifecta"
        for f in with_pack.findings
    )
    without_pack = analyze_fleet(_erp_fleet(), _erp_tools())
    assert not without_pack.findings


def test_capability_extension_raises_blast_radius_score() -> None:
    fleet = Fleet.model_validate(
        {
            "agents": [
                {
                    "id": "p",
                    "name": "P",
                    "owner": "Finance",
                    "granted_tools": ["release_payment_run"],
                    "usage_log": ["release_payment_run"],
                }
            ]
        }
    )
    graph = EffectiveAccessGraph(fleet)
    finding = Finding(
        id="x",
        agent_id="p",
        check_type="sod",
        severity="high",
        title="t",
        business_risk="b",
        evidence=[
            Evidence(entity_type="agent", entity_id="p", detail="subject"),
            Evidence(entity_type="tool", entity_id="release_payment_run", detail="direct grant"),
        ],
        recommended_action="r",
        control_mapping="c",
    )
    base = score_finding(finding, graph).risk_score
    extended = DEFAULT_CAPABILITY_CLASSES.extended(high_impact=["release_payment_run"])
    boosted = score_finding(finding, graph, extended).risk_score
    assert boosted > base


def test_defaults_byte_identical_with_inert_pack() -> None:
    # The eval gate never loads packs. Prove analysis without a pack — and with
    # a pack whose tools are absent from the catalog — produces identical output.
    fleet, tools = load_inventory(
        PROJECT_ROOT / "data" / "fleet.json", PROJECT_ROOT / "data" / "tools.json"
    )
    baseline = analyze_fleet(fleet, tools)
    inert_pack = load_rule_pack(EXAMPLE_PACK)  # finance tools absent from demo catalog
    assert inert_rule_ids(inert_pack, tools)  # confirm every rule is inert here
    with_inert = analyze_fleet(fleet, tools, rule_pack=inert_pack)
    assert [f.model_dump(mode="json") for f in baseline.findings] == [
        f.model_dump(mode="json") for f in with_inert.findings
    ]
    # Pin the known-good shipped result so a future refactor can't drift it.
    assert len(baseline.findings) == 9


def test_merge_rejects_duplicate_rule_ids_across_packs() -> None:
    pack = load_rule_pack(EXAMPLE_PACK)
    with pytest.raises(RulePackError, match="duplicate rule_id"):
        merge_rule_packs([pack, pack])


def test_load_rule_packs_merges_additively() -> None:
    merged = load_rule_packs([EXAMPLE_PACK])
    assert merged.sod_rules
    assert "release_payment_run" in merged.capability_classes.high_impact


def _write(tmp_path, text: str) -> Path:
    path = tmp_path / "pack.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_malformed_packs_fail_loudly(tmp_path) -> None:
    good_fields = (
        "severity: critical\n    title: t\n    business_risk: b\n"
        "    recommended_action: r\n    control_mapping: c\n"
    )
    cases = [
        ("empty", ""),
        ("not a mapping", "- just\n- a\n- list\n"),
        ("unknown top key", "widgets: []\n"),
        (
            "too few tools",
            f"toxic_combinations:\n  - rule_id: r1\n    tool_ids: [only_one]\n    {good_fields}",
        ),
        (
            "bad severity",
            "toxic_combinations:\n  - rule_id: r1\n    tool_ids: [a, b]\n"
            "    severity: spicy\n    title: t\n    business_risk: b\n"
            "    recommended_action: r\n    control_mapping: c\n",
        ),
        (
            "missing field",
            "toxic_combinations:\n  - rule_id: r1\n    tool_ids: [a, b]\n    severity: high\n",
        ),
        (
            "builtin collision",
            f"toxic_combinations:\n  - rule_id: missing_owner\n    tool_ids: [a, b]\n    {good_fields}",
        ),
        (
            "unknown capability class",
            "capability_classes:\n  nonsense: [a]\n",
        ),
    ]
    for label, text in cases:
        with pytest.raises(RulePackError):
            load_rule_pack(_write(tmp_path, text))
        assert label  # keeps the label meaningful in a failure trace


def test_builtin_rule_ids_are_reserved() -> None:
    assert "lethal_trifecta" in BUILTIN_RULE_IDS
    assert "finance_create_vendor_approve_payment" in BUILTIN_RULE_IDS
