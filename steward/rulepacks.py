"""Load and validate client-specific SoD rule packs (R3).

A rule pack is a small YAML file that extends Steward's built-in deterministic
floor with an organization's own segregation-of-duties matrix — without any
code change. A pack may declare:

* ``toxic_combinations`` — toxic tool pairings/sets (2+ tool ids) that must
  never coexist in one agent's effective access;
* ``delegated_high_risk`` — single capabilities whose *delegated* reach is a
  blast-radius concern;
* ``capability_classes`` — extra ids for the high-impact / sensitive-read /
  untrusted-content / exfiltration classes, so scoring and the lethal-trifecta
  check understand the client's own tool vocabulary.

Pack rules are **additive**: the built-in floor is untouched, findings from a
pack are ordinary ``source="deterministic"`` findings carrying the pack's
``rule_id``, and check-type-based control-framework annotation applies to them
for free. Matching is by tool id — the same honest limitation as the built-in
rules — so a rule naming tools absent from the loaded catalog simply never
fires (reported as an inert-rule note rather than an error, since packs are
meant to be portable across fleets).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .capability_classes import DEFAULT_CAPABILITY_CLASSES, CapabilityClasses
from .findings import (
    BUILTIN_RULE_IDS,
    DelegatedHighRiskRule,
    RulePack,
    ToxicCapabilityRule,
)
from .models import ToolCatalog

VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low"})
CAPABILITY_CLASS_KEYS = frozenset(
    {"high_impact", "sensitive_read", "untrusted_content", "exfiltration"}
)
_TOP_LEVEL_KEYS = frozenset(
    {"name", "description", "toxic_combinations", "delegated_high_risk", "capability_classes"}
)
_TOXIC_KEYS = frozenset(
    {"rule_id", "tool_ids", "severity", "title", "business_risk", "recommended_action", "control_mapping"}
)
_DELEGATED_KEYS = frozenset(
    {"tool_id", "rule_id", "severity", "title", "business_risk", "recommended_action", "control_mapping"}
)


class RulePackError(ValueError):
    """Raised when a rule pack is malformed."""


def _require_mapping(value: Any, context: str) -> dict:
    if not isinstance(value, dict):
        raise RulePackError(f"{context}: expected a mapping")
    return value


def _require_str(value: Any, field: str, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RulePackError(f"{context}: '{field}' must be a non-empty string")
    return value.strip()


def _require_severity(value: Any, context: str) -> str:
    severity = _require_str(value, "severity", context)
    if severity not in VALID_SEVERITIES:
        raise RulePackError(
            f"{context}: severity {severity!r} must be one of {sorted(VALID_SEVERITIES)}"
        )
    return severity


def _string_list(value: Any, field: str, context: str) -> list[str]:
    if not isinstance(value, list):
        raise RulePackError(f"{context}: '{field}' must be a list")
    return [_require_str(item, f"{field}[{index}]", context) for index, item in enumerate(value)]


def _reject_unknown_keys(entry: dict, allowed: frozenset[str], context: str) -> None:
    unknown = sorted(set(entry) - allowed)
    if unknown:
        raise RulePackError(f"{context}: unknown keys {unknown}")


def _parse_toxic(entry: Any, index: int) -> ToxicCapabilityRule:
    context = f"toxic_combinations[{index}]"
    entry = _require_mapping(entry, context)
    _reject_unknown_keys(entry, _TOXIC_KEYS, context)
    tool_ids = _string_list(entry.get("tool_ids"), "tool_ids", context)
    if len(set(tool_ids)) < 2:
        raise RulePackError(f"{context}: 'tool_ids' must name at least 2 distinct tools")
    return ToxicCapabilityRule(
        rule_id=_require_str(entry.get("rule_id"), "rule_id", context),
        tool_ids=frozenset(tool_ids),
        severity=_require_severity(entry.get("severity"), context),
        title=_require_str(entry.get("title"), "title", context),
        business_risk=_require_str(entry.get("business_risk"), "business_risk", context),
        recommended_action=_require_str(
            entry.get("recommended_action"), "recommended_action", context
        ),
        control_mapping=_require_str(entry.get("control_mapping"), "control_mapping", context),
    )


def _parse_delegated(entry: Any, index: int) -> DelegatedHighRiskRule:
    context = f"delegated_high_risk[{index}]"
    entry = _require_mapping(entry, context)
    _reject_unknown_keys(entry, _DELEGATED_KEYS, context)
    return DelegatedHighRiskRule(
        tool_id=_require_str(entry.get("tool_id"), "tool_id", context),
        rule_id=_require_str(entry.get("rule_id"), "rule_id", context),
        severity=_require_severity(entry.get("severity"), context),
        title=_require_str(entry.get("title"), "title", context),
        business_risk=_require_str(entry.get("business_risk"), "business_risk", context),
        recommended_action=_require_str(
            entry.get("recommended_action"), "recommended_action", context
        ),
        control_mapping=_require_str(entry.get("control_mapping"), "control_mapping", context),
    )


def _parse_capability_classes(raw: Any, context: str) -> CapabilityClasses:
    data = _require_mapping(raw, f"{context}: capability_classes")
    unknown = sorted(set(data) - CAPABILITY_CLASS_KEYS)
    if unknown:
        raise RulePackError(f"{context}: capability_classes has unknown keys {unknown}")
    extensions = {
        key: _string_list(data[key], key, f"{context}: capability_classes")
        for key in CAPABILITY_CLASS_KEYS
        if key in data
    }
    return DEFAULT_CAPABILITY_CLASSES.extended(**extensions)


def _validate_rule_ids(pack: RulePack, context: str) -> None:
    seen: set[str] = set()
    for rule_id in pack.rule_ids:
        if rule_id in BUILTIN_RULE_IDS:
            raise RulePackError(
                f"{context}: rule_id {rule_id!r} collides with a built-in rule"
            )
        if rule_id in seen:
            raise RulePackError(f"{context}: duplicate rule_id {rule_id!r}")
        seen.add(rule_id)


def load_rule_pack(path: str | Path) -> RulePack:
    """Parse and strictly validate one YAML rule pack."""

    source = Path(path)
    try:
        raw = yaml.safe_load(source.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise
    except yaml.YAMLError as exc:
        raise RulePackError(f"invalid YAML in {source}: {exc}") from exc
    if raw is None:
        raise RulePackError(f"{source}: rule pack is empty")

    data = _require_mapping(raw, str(source))
    _reject_unknown_keys(data, _TOP_LEVEL_KEYS, str(source))
    pack = RulePack(
        sod_rules=tuple(
            _parse_toxic(entry, index)
            for index, entry in enumerate(data.get("toxic_combinations") or [])
        ),
        delegated_rules=tuple(
            _parse_delegated(entry, index)
            for index, entry in enumerate(data.get("delegated_high_risk") or [])
        ),
        capability_classes=_parse_capability_classes(
            data.get("capability_classes") or {}, str(source)
        ),
    )
    if not pack.sod_rules and not pack.delegated_rules and (
        pack.capability_classes == DEFAULT_CAPABILITY_CLASSES
    ):
        raise RulePackError(f"{source}: rule pack declares no rules or capability extensions")
    _validate_rule_ids(pack, str(source))
    return pack


def merge_rule_packs(packs: list[RulePack]) -> RulePack:
    """Combine several packs additively into one (rule ids must stay unique)."""

    if not packs:
        return RulePack()
    capability_classes = DEFAULT_CAPABILITY_CLASSES
    for pack in packs:
        capability_classes = capability_classes.extended(
            high_impact=pack.capability_classes.high_impact,
            sensitive_read=pack.capability_classes.sensitive_read,
            untrusted_content=pack.capability_classes.untrusted_content,
            exfiltration=pack.capability_classes.exfiltration,
        )
    merged = RulePack(
        sod_rules=tuple(rule for pack in packs for rule in pack.sod_rules),
        delegated_rules=tuple(rule for pack in packs for rule in pack.delegated_rules),
        capability_classes=capability_classes,
    )
    _validate_rule_ids(merged, "merged rule packs")
    return merged


def load_rule_packs(paths: list[str | Path]) -> RulePack:
    """Load and merge several pack files into a single additive pack."""

    return merge_rule_packs([load_rule_pack(path) for path in paths])


def inert_rule_ids(pack: RulePack, tools: ToolCatalog) -> list[str]:
    """Rule ids that can never fire because they name tools absent from the catalog."""

    catalog = tools.tool_ids
    inert = [rule.rule_id for rule in pack.sod_rules if not rule.tool_ids <= catalog]
    inert += [rule.rule_id for rule in pack.delegated_rules if rule.tool_id not in catalog]
    return sorted(inert)
