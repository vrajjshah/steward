"""Thin application service used by the FastAPI UI.

The service is deliberately an adapter around the core analysis package.  It
does not invent findings, call an LLM, or bypass citation verification.  That
keeps the browser/UI boundary safe: only verified, serializable results cross
it.
"""

from __future__ import annotations

import inspect
import json
import os
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib import import_module
from pathlib import Path
from time import perf_counter
from typing import Any

from steward.incident_grounding import ground_findings_in_real_world_context
from steward.ledger import AuditLedger, LedgerError
from steward.reporting import (
    as_dict,
    build_fleet_audit_report,
    compute_effective_access,
    fleet_agents,
    normalize_findings,
)

_SECRET_VALUE = re.compile(
    r"(?i)(?:sk-[a-z0-9_-]{8,}|akia[0-9a-z]{12,}|bearer\s+[a-z0-9._~+/=-]{8,}|"
    r"(?:token|key|secret|password)\s*[=:]\s*[^\s,;]+)"
)


def _redact_error(value: Any) -> str:
    """Avoid echoing credentials from a malformed local config in API errors."""

    return _SECRET_VALUE.sub("[REDACTED]", str(value))


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _default_fleet_path() -> Path:
    return _project_root() / "data" / "fleet.json"


def _default_tools_path() -> Path:
    return _project_root() / "data" / "tools.json"


def _default_demo_path() -> Path:
    return _project_root() / "data" / "demo_results.json"


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _first_imported_callable(modules: Iterable[str], attribute: str) -> Callable[..., Any] | None:
    for module_name in modules:
        try:
            module = import_module(module_name)
        except ImportError:
            continue
        candidate = getattr(module, attribute, None)
        if callable(candidate):
            return candidate
    return None


def _call_with_supported_args(function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Call a core function while tolerating a small amount of API evolution."""

    try:
        signature = inspect.signature(function)
    except (TypeError, ValueError):
        return function(*args, **kwargs)
    accepts_kwargs = any(
        parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in signature.parameters.values()
    )
    positional_names: set[str] = set()
    remaining = len(args)
    for name, parameter in signature.parameters.items():
        if remaining <= 0:
            break
        if parameter.kind in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        ):
            positional_names.add(name)
            remaining -= 1
        elif parameter.kind is inspect.Parameter.VAR_POSITIONAL:
            # A vararg consumes any remaining positional values, but it has no
            # named keyword equivalent to remove.
            remaining = 0
    accepted = {
        key: value
        for key, value in kwargs.items()
        if key not in positional_names and (accepts_kwargs or key in signature.parameters)
    }
    return function(*args, **accepted)


def _load_with_core(path: Path, kind: str) -> Any:
    """Use the typed loader when available; otherwise retain a plain JSON shape."""

    attribute = "load_fleet" if kind == "fleet" else "load_tools"
    loader = _first_imported_callable(
        ("steward.ingestion", "steward.loaders", "steward.core", "steward.findings"),
        attribute,
    )
    if loader is not None:
        return _call_with_supported_args(loader, path)
    return _read_json(path)


def _result_value(result: Any, *keys: str, default: Any = None) -> Any:
    for key in keys:
        if isinstance(result, Mapping) and key in result:
            return result[key]
        if hasattr(result, key):
            return getattr(result, key)
    return default


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return sorted(value, key=str)
    return [value]


def _coerce_inventory(fleet: Any, tools: Any) -> tuple[Any, Any]:
    """Turn adapter JSON into the core's typed inventory models when present."""

    try:
        models = import_module("steward.models")
        fleet_model = models.Fleet
        tools_model = models.ToolCatalog
    except (ImportError, AttributeError):
        return fleet, tools

    if isinstance(fleet, Mapping):
        fleet = fleet_model.model_validate(fleet)
    if isinstance(tools, Mapping):
        tools = tools_model.model_validate(tools)
    return fleet, tools


def _capability_signal_map(result: Any, field_name: str, aliases: tuple[str, ...] = ()) -> dict[str, list[str]]:
    """Read enrichment signals from either a top-level result or access summaries."""

    direct = _result_value(result, field_name, *aliases, default={})
    if isinstance(direct, Mapping) and direct:
        return {
            str(agent_id): [str(item) for item in _as_list(values)]
            for agent_id, values in direct.items()
        }

    summaries = _result_value(result, "access_summaries", default={})
    if not isinstance(summaries, Mapping):
        return {}
    signals: dict[str, list[str]] = {}
    for agent_id, summary in summaries.items():
        values = _result_value(summary, field_name, *aliases, default=[])
        if values:
            signals[str(agent_id)] = [str(item) for item in _as_list(values)]
    return signals


def _verified_findings(fleet: Any, tools: Any, findings: Any) -> list[Any]:
    """Apply the same citation gate to live results and committed demo caches."""

    candidates = _as_list(findings)
    try:
        finding_model = import_module("steward.models").Finding
        typed_candidates = []
        for candidate in candidates:
            try:
                typed_candidates.append(finding_model.model_validate(candidate))
            except Exception:
                # A cache or adapter object that cannot satisfy the typed public
                # Finding schema is never eligible for browser/report output.
                continue
        candidates = typed_candidates
    except (ImportError, AttributeError):
        pass

    verifier = _first_imported_callable(
        ("steward.findings", "steward.analysis", "steward.checks"),
        "findings_with_valid_citations",
    )
    if verifier is not None:
        verified = _as_list(
            _call_with_supported_args(
                verifier,
                candidates,
                fleet=fleet,
                findings=candidates,
                tools=tools,
            )
        )
        return ground_findings_in_real_world_context(verified)

    verifier = _first_imported_callable(
        ("steward.findings", "steward.analysis", "steward.checks"),
        "verify_findings",
    )
    if verifier is None:
        # There is no safe graceful fallback for a reporting boundary without
        # a verifier. Suppress rather than trusting unverified configuration.
        return []
    verified = _call_with_supported_args(
        verifier,
        candidates,
        fleet=fleet,
        findings=candidates,
        tools=tools,
    )
    verified_findings = _as_list(
        _result_value(verified, "findings", "valid_findings", default=verified)
    )
    return ground_findings_in_real_world_context(verified_findings)


@dataclass
class AnalysisState:
    fleet: Any
    tools: Any
    findings: list[Any]
    effective_access: dict[str, list[str]]
    tool_capabilities: Any = field(default_factory=dict)
    needed_capabilities: Any = field(default_factory=dict)
    granted_vs_needed_gaps: Any = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    source: str = "synthetic"
    loaded_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def public(self, reviews: Mapping[str, Any]) -> dict[str, Any]:
        report = build_fleet_audit_report(
            self.fleet,
            self.findings,
            tools=self.tools,
            effective_access=self.effective_access,
            needed_capabilities=self.needed_capabilities,
            granted_vs_needed_gaps=self.granted_vs_needed_gaps,
            reviews=reviews,
            metadata=self.metadata,
            generated_at=self.loaded_at,
        )
        return {
            "fleet": _public_fleet(self.fleet, self.tools),
            "findings": normalize_findings(self.findings),
            "effective_access": self.effective_access,
            "tool_capabilities": as_dict(self.tool_capabilities),
            "needed_capabilities": as_dict(self.needed_capabilities),
            "granted_vs_needed_gaps": as_dict(self.granted_vs_needed_gaps),
            "metadata": as_dict(self.metadata),
            "llm_enrichment": report["llm_enrichment"],
            "source": self.source,
            "report": report,
        }


def _public_fleet(fleet: Any, tools: Any) -> dict[str, Any]:
    """Select display-safe metadata; never serialize arbitrary adapter config."""

    agents = []
    for agent in fleet_agents(fleet):
        public = as_dict(agent)
        # Agent models have this exact surface.  Selecting it prevents an MCP
        # config's server/env/args fields from crossing into reports or browser.
        agents.append(
            {
                "id": str(public.get("id", "unknown-agent")),
                "name": str(public.get("name", public.get("id", "unknown-agent"))),
                "owner": public.get("owner"),
                "description": str(public.get("description", "")),
                "granted_tools": [str(item) for item in public.get("granted_tools", [])],
                "can_delegate_to": [str(item) for item in public.get("can_delegate_to", [])],
                "usage_log": [str(item) for item in public.get("usage_log", [])],
                "usage_log_available": bool(public.get("usage_log_available", True)),
            }
        )
    raw_tools = as_dict(tools)
    if isinstance(raw_tools, Mapping):
        raw_tools = raw_tools.get("tools", list(raw_tools.values()))
    tool_list = []
    for tool in _as_list(raw_tools):
        tool_dict = as_dict(tool)
        if isinstance(tool_dict, Mapping):
            tool_list.append(
                {
                    "id": str(tool_dict.get("id", tool_dict.get("name", "unknown-tool"))),
                    "name": str(tool_dict.get("name", tool_dict.get("id", "unknown-tool"))),
                    "description": str(tool_dict.get("description", "")),
                }
            )
    return {"agents": agents, "tools": tool_list}


class StewardService:
    """Own the currently loaded fleet and in-memory certification decisions."""

    def __init__(
        self,
        *,
        fleet_path: Path | str | None = None,
        tools_path: Path | str | None = None,
        demo_path: Path | str | None = None,
        demo_mode: bool | None = None,
        ledger: AuditLedger | None = None,
    ) -> None:
        self.fleet_path = Path(fleet_path) if fleet_path else _default_fleet_path()
        self.tools_path = Path(tools_path) if tools_path else _default_tools_path()
        self.demo_path = Path(demo_path) if demo_path else _default_demo_path()
        self.demo_mode = (
            os.getenv("STEWARD_DEMO", "").strip().lower() in {"1", "true", "yes"}
            if demo_mode is None
            else demo_mode
        )
        self._fleet: Any | None = None
        self._tools: Any | None = None
        self._source = "synthetic"
        self._state: AnalysisState | None = None
        self._reviews: dict[str, dict[str, Any]] = {}
        # Ledger use is opt-in via `steward init`. Keeping it optional preserves
        # the existing zero-key dashboard behavior while ensuring that any
        # initialized local ledger receives every UI-emitted finding/review.
        self._ledger = ledger

    @property
    def reviews(self) -> Mapping[str, Any]:
        return self._reviews

    def load_fleet(
        self,
        *,
        fleet_path: Path | str | None = None,
        tools_path: Path | str | None = None,
        source_type: str = "fleet",
    ) -> dict[str, Any]:
        """Load a synthetic fleet or a locally supplied config adapter input."""

        candidate_fleet = Path(fleet_path) if fleet_path else self.fleet_path
        candidate_tools = Path(tools_path) if tools_path else self.tools_path
        if not candidate_fleet.is_file():
            raise FileNotFoundError(f"Fleet config not found: {candidate_fleet}")

        if source_type in {"mcp", "mcp_json", "mcp-config"}:
            adapter = _first_imported_callable(
                ("steward.adapters", "steward.ingestion", "steward.mcp_adapter"),
                "parse_mcp_config",
            )
            if adapter is None:
                raise RuntimeError("MCP adapter is not installed in this Steward build.")
            adapted = _call_with_supported_args(adapter, candidate_fleet)
            self._fleet = _result_value(adapted, "fleet", "agents", default=adapted)
            self._tools = _result_value(adapted, "tools", "tool_catalog", default=[])
            self._fleet, self._tools = _coerce_inventory(self._fleet, self._tools)
            self._source = "mcp"
        else:
            self._fleet = _load_with_core(candidate_fleet, "fleet")
            self._tools = _load_with_core(candidate_tools, "tools") if candidate_tools.is_file() else []
            self._source = "synthetic" if candidate_fleet == _default_fleet_path() else "file"

        self.fleet_path = candidate_fleet
        self.tools_path = candidate_tools
        self._state = None
        self._reviews = {}
        return self.fleet_summary()

    def fleet_summary(self) -> dict[str, Any]:
        if self._fleet is None:
            self.load_fleet()
        fleet = _public_fleet(self._fleet, self._tools)
        return {
            "source": self._source,
            "fleet_path": self.fleet_path.name,
            "agents": len(fleet["agents"]),
            "tools": len(fleet["tools"]),
            "fleet": fleet,
        }

    def _demo_analysis(self) -> AnalysisState:
        if self._fleet is None:
            self.load_fleet()
        if not self.demo_path.is_file():
            raise FileNotFoundError(
                "Demo mode was requested, but data/demo_results.json is missing. "
                "Run the analyzer once or turn off STEWARD_DEMO."
            )
        raw = _read_json(self.demo_path)
        # Support either a direct result object or a report-shaped cache.
        findings = _result_value(raw, "findings", default=[])
        report = _result_value(raw, "report", default={})
        if not findings and isinstance(report, Mapping):
            findings = report.get("findings", [])
        cached_fleet = _result_value(raw, "fleet", default=None)
        if cached_fleet:
            self._fleet = cached_fleet
        cached_tools = _result_value(raw, "tools", default=None)
        if cached_tools:
            self._tools = cached_tools
        self._fleet, self._tools = _coerce_inventory(self._fleet, self._tools)
        findings = _verified_findings(self._fleet, self._tools, findings)
        effective = _result_value(raw, "effective_access", default=None)
        if effective is None and isinstance(report, Mapping):
            effective = report.get("effective_access")
        needed = _capability_signal_map(raw, "needed_capabilities", ("needed",))
        gaps = _capability_signal_map(raw, "granted_vs_needed_gap", ("granted_vs_needed_gaps",))
        return AnalysisState(
            fleet=self._fleet,
            tools=self._tools,
            findings=findings,
            effective_access={str(key): [str(item) for item in value] for key, value in (effective or compute_effective_access(self._fleet)).items()},
            tool_capabilities=_result_value(raw, "tool_capabilities", default={}),
            needed_capabilities=needed,
            granted_vs_needed_gaps=gaps,
            metadata=as_dict(_result_value(raw, "metadata", "analysis_metadata", default={}) or {}),
            source="demo",
        )

    def _live_analysis(self) -> AnalysisState:
        if self._fleet is None:
            self.load_fleet()
        started = perf_counter()

        # Prefer a complete pipeline when it exists (where LLM enrichment lives),
        # then fall back to the deterministic verifier.  Both paths must return
        # real, cited Finding objects; no UI-only inference happens here.
        pipeline = _first_imported_callable(
            ("steward.pipeline", "steward.analysis", "steward.findings"),
            "analyze_fleet",
        )
        if pipeline is not None:
            result = _call_with_supported_args(
                pipeline,
                self._fleet,
                tools=self._tools,
                fleet=self._fleet,
                enable_llm=not self.demo_mode,
            )
            findings = _result_value(result, "findings", default=result)
            effective = _result_value(result, "effective_access", default=None)
            tool_capabilities = _result_value(result, "tool_capabilities", default={})
            needed = _capability_signal_map(result, "needed_capabilities", ("needed",))
            gaps = _capability_signal_map(result, "granted_vs_needed_gap", ("granted_vs_needed_gaps",))
            metadata = as_dict(_result_value(result, "metadata", "analysis_metadata", default={}) or {})
        else:
            deterministic = _first_imported_callable(
                ("steward.findings", "steward.analysis", "steward.checks"),
                "run_deterministic_checks",
            )
            if deterministic is None:
                raise RuntimeError("The Steward analysis engine is not available.")
            findings = _call_with_supported_args(
                deterministic,
                self._fleet,
                self._tools,
                fleet=self._fleet,
                tools=self._tools,
            )
            effective = None
            tool_capabilities = {}
            needed = {}
            gaps = {}
            metadata = {}

        findings = _verified_findings(self._fleet, self._tools, findings)

        metadata = {
            **metadata,
            "mode": "live",
            "elapsed_ms": round((perf_counter() - started) * 1000, 2),
        }
        return AnalysisState(
            fleet=self._fleet,
            tools=self._tools,
            findings=findings,
            effective_access=as_dict(effective) if effective else compute_effective_access(self._fleet),
            tool_capabilities=tool_capabilities,
            needed_capabilities=needed,
            granted_vs_needed_gaps=gaps,
            metadata=metadata,
            source=self._source,
        )

    def _active_ledger(self) -> AuditLedger | None:
        """Return an injected or initialized local ledger, without auto-creating keys."""

        if self._ledger is not None:
            return self._ledger
        candidate = AuditLedger()
        if candidate.paths.private_key_path.exists() and candidate.paths.public_key_path.exists():
            return candidate
        return None

    @staticmethod
    def _finding_ledger_payload(finding: Any) -> dict[str, Any]:
        """Retain only graph identifiers for an audit event, not narrative prose."""

        raw = as_dict(finding)
        if not isinstance(raw, Mapping):
            return {}
        evidence = raw.get("evidence", [])
        cited_entities = [
            {
                "entity_type": item.get("entity_type"),
                "entity_id": item.get("entity_id"),
            }
            for item in _as_list(evidence)
            if isinstance(item, Mapping)
            and isinstance(item.get("entity_type"), str)
            and isinstance(item.get("entity_id"), str)
        ]
        return {
            "finding_id": raw.get("id"),
            "agent_id": raw.get("agent_id"),
            "check_type": raw.get("check_type"),
            "severity": raw.get("severity"),
            "source": raw.get("source"),
            "rule_id": raw.get("rule_id"),
            "cited_entities": cited_entities,
        }

    def _record_findings_in_ledger(self, state: AnalysisState) -> None:
        """Append event facts for newly emitted UI/API findings when initialized."""

        ledger = self._active_ledger()
        if ledger is None:
            return
        try:
            for finding in state.findings:
                ledger.append_finding(
                    self._finding_ledger_payload(finding), policy_version="steward-analysis/v0.1"
                )
        except (LedgerError, OSError, ValueError) as exc:
            # The analysis is still valid if a historical ledger was tampered
            # with. Make persistence failure visible in metadata rather than
            # changing the findings that already passed graph verification.
            state.metadata["audit_ledger"] = {
                "status": "append_failed",
                "detail": type(exc).__name__,
            }
        else:
            state.metadata["audit_ledger"] = {
                "status": "recorded",
                "finding_events": len(state.findings),
            }

    def analyze(self, *, force: bool = False) -> dict[str, Any]:
        if self._state is None or force:
            # Demo mode is a cache only for the built-in synthetic fleet. A
            # judge who loads their own native/MCP config should still receive
            # genuine deterministic analysis locally—without needing AWS.
            use_demo_cache = self.demo_mode and self._source == "synthetic"
            self._state = self._demo_analysis() if use_demo_cache else self._live_analysis()
            self._record_findings_in_ledger(self._state)
        return self._state.public(self._reviews)

    def current(self) -> dict[str, Any]:
        return self.analyze()

    def risk_card(self, agent_id: str) -> dict[str, Any]:
        packet = self.current()["report"]["certification_packet"]
        for card in packet["risk_cards"]:
            if card["agent"]["id"] == agent_id:
                return card
        raise KeyError(agent_id)

    def report(self) -> dict[str, Any]:
        return self.current()["report"]

    def certification_packet(self) -> dict[str, Any]:
        return self.current()["report"]["certification_packet"]

    def record_review(self, agent_id: str, status: str, note: str = "") -> dict[str, Any]:
        if status not in {"approve", "revoke", "flag", "pending"}:
            raise ValueError("Review status must be approve, revoke, flag, or pending.")
        # Prove the target exists before accepting a reviewer action.
        self.risk_card(agent_id)
        self._reviews[agent_id] = {
            "status": status,
            "note": note.strip(),
            "updated_at": datetime.now(UTC).isoformat(),
        }
        ledger = self._active_ledger()
        if ledger is not None:
            try:
                # ``note`` is deliberately supplied under its semantic key:
                # the ledger stores a SHA-256 commitment, never its contents.
                ledger.append_certification(
                    {
                        "agent_id": agent_id,
                        "decision": status,
                        "note": note.strip(),
                        "updated_at": self._reviews[agent_id]["updated_at"],
                    },
                    policy_version="steward-certification/v0.1",
                )
            except (LedgerError, OSError, ValueError) as exc:
                if self._state is not None:
                    self._state.metadata["audit_ledger"] = {
                        "status": "append_failed",
                        "detail": type(exc).__name__,
                    }
        return self.risk_card(agent_id)
