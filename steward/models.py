"""Typed domain models shared by Steward's ingestion and analysis layers."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

CheckType = Literal["sod", "over_privilege", "escalation", "orphan"]
Severity = Literal["critical", "high", "medium", "low"]
EvidenceEntityType = Literal["agent", "tool", "delegation_edge"]
FindingSource = Literal["deterministic", "llm_generalized"]


class StewardModel(BaseModel):
    """Base model that rejects accidental fields in our canonical inventory."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


def _require_nonempty_identifier(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("identifier must not be empty")
    return value


def _unique_identifier_list(values: list[str]) -> list[str]:
    cleaned = [_require_nonempty_identifier(value) for value in values]
    duplicates = sorted({value for value in cleaned if cleaned.count(value) > 1})
    if duplicates:
        raise ValueError(f"identifier list contains duplicates: {', '.join(duplicates)}")
    return cleaned


class Agent(StewardModel):
    """An AI agent identity and the access it has been granted directly."""

    id: str
    name: str
    owner: str | None = None
    description: str = ""
    granted_tools: list[str] = Field(default_factory=list)
    can_delegate_to: list[str] = Field(default_factory=list)
    usage_log: list[str] = Field(default_factory=list)
    # Real config adapters may know grants but have no runtime telemetry. An
    # empty observed log means "nothing used"; unavailable telemetry must not
    # be misreported as unused standing access.
    usage_log_available: bool = True

    @field_validator("id", "name")
    @classmethod
    def identifiers_are_nonempty(cls, value: str) -> str:
        return _require_nonempty_identifier(value)

    @field_validator("owner", mode="before")
    @classmethod
    def normalize_blank_owner(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip() or None
        return value

    @field_validator("granted_tools", "can_delegate_to", "usage_log")
    @classmethod
    def lists_have_unique_nonempty_ids(cls, value: list[str]) -> list[str]:
        return _unique_identifier_list(value)


class Tool(StewardModel):
    """A tool/entitlement known to the fleet.

    ``business_capability`` is deliberately absent: it is inferred by the LLM
    enrichment layer rather than hand-labelled in the catalog.
    """

    id: str
    name: str
    description: str = ""

    @field_validator("id", "name")
    @classmethod
    def identifiers_are_nonempty(cls, value: str) -> str:
        return _require_nonempty_identifier(value)


class Fleet(StewardModel):
    """Canonical inventory of AI agents."""

    schema_version: str = "0.1"
    fleet_name: str = "Unnamed fleet"
    agents: list[Agent] = Field(default_factory=list)

    @model_validator(mode="after")
    def agent_ids_are_unique(self) -> Fleet:
        ids = [agent.id for agent in self.agents]
        duplicates = sorted({agent_id for agent_id in ids if ids.count(agent_id) > 1})
        if duplicates:
            raise ValueError(f"fleet contains duplicate agent ids: {', '.join(duplicates)}")
        return self

    @property
    def agent_ids(self) -> set[str]:
        return {agent.id for agent in self.agents}

    def agent_by_id(self, agent_id: str) -> Agent:
        for agent in self.agents:
            if agent.id == agent_id:
                return agent
        raise KeyError(f"unknown agent: {agent_id}")


class ToolCatalog(StewardModel):
    """Canonical catalog of tools that may be granted to an agent."""

    schema_version: str = "0.1"
    tools: list[Tool] = Field(default_factory=list)

    @model_validator(mode="after")
    def tool_ids_are_unique(self) -> ToolCatalog:
        ids = [tool.id for tool in self.tools]
        duplicates = sorted({tool_id for tool_id in ids if ids.count(tool_id) > 1})
        if duplicates:
            raise ValueError(f"tool catalog contains duplicate tool ids: {', '.join(duplicates)}")
        return self

    @property
    def tool_ids(self) -> set[str]:
        return {tool.id for tool in self.tools}

    def tool_by_id(self, tool_id: str) -> Tool:
        for tool in self.tools:
            if tool.id == tool_id:
                return tool
        raise KeyError(f"unknown tool: {tool_id}")


class Evidence(StewardModel):
    """A verifiable pointer to an entity in Steward's access graph."""

    entity_type: EvidenceEntityType
    entity_id: str
    detail: str

    @field_validator("entity_id")
    @classmethod
    def entity_id_is_nonempty(cls, value: str) -> str:
        return _require_nonempty_identifier(value)

    @field_validator("detail")
    @classmethod
    def detail_is_nonempty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("evidence detail must not be empty")
        return value


class OwaspMcpReference(StewardModel):
    """A documented OWASP MCP Top 10 category relevant to a finding.

    This is threat context, not graph evidence.  A finding still needs the
    entity-level evidence checked by :func:`verify_finding_evidence` before it
    can surface.
    """

    id: str
    title: str
    url: str
    relevance: str

    @field_validator("id", "title", "url", "relevance")
    @classmethod
    def required_reference_text_is_nonempty(cls, value: str) -> str:
        return _require_nonempty_identifier(value)


class ControlFrameworkReference(StewardModel):
    """A named control in a published governance framework relevant to a finding.

    This is auditor-facing context that speaks control language — it is not a
    compliance certification and never substitutes for the entity-level graph
    evidence a finding must carry.  The ``framework`` string includes the
    framework version so the mapping stays honest as frameworks revise.
    """

    framework: str
    control_id: str
    control_name: str
    relevance: str

    @field_validator("framework", "control_id", "control_name", "relevance")
    @classmethod
    def required_reference_text_is_nonempty(cls, value: str) -> str:
        return _require_nonempty_identifier(value)


class RealWorldIncident(StewardModel):
    """A source-linked external incident or documented attack scenario."""

    title: str
    date: str
    url: str
    relevance: str

    @field_validator("title", "date", "url", "relevance")
    @classmethod
    def required_reference_text_is_nonempty(cls, value: str) -> str:
        return _require_nonempty_identifier(value)


class Finding(StewardModel):
    """A user-visible risk finding. Invalid evidence is filtered before output."""

    id: str
    # The deterministic rule (or LLM policy) responsible for the finding. It
    # is optional for schema compatibility with externally generated reports,
    # but every built-in finding carries one for golden-set evaluation.
    rule_id: str | None = None
    # The source is intentionally part of the public finding contract.  It
    # makes the always-on deterministic floor distinguishable from a
    # model-proposed combination that survived the same citation gate.
    source: FindingSource = "deterministic"
    agent_id: str
    check_type: CheckType
    severity: Severity
    title: str
    business_risk: str
    evidence: list[Evidence] = Field(min_length=1)
    recommended_action: str
    control_mapping: str
    # Threat context is deliberately optional and never substitutes for the
    # graph citations above.  A finding can have no external analogue and
    # still be fully valid if its evidence verifies against the loaded fleet.
    owasp_mcp: list[OwaspMcpReference] = Field(default_factory=list)
    real_world_incident: list[RealWorldIncident] = Field(default_factory=list)
    # Auditor-facing control-framework context (NIST 800-53, SOC 2, ISO 27001,
    # SOX ITGC, EU AI Act), populated deterministically by check type. Context
    # in the auditor's language — not a compliance certification.
    control_frameworks: list[ControlFrameworkReference] = Field(default_factory=list)
    # Deterministic composite risk score (0-100) and its factor breakdown,
    # populated by steward.scoring after citation verification. Reproducible:
    # identical input yields identical scores and ranking.
    risk_score: int | None = None
    risk_factors: dict[str, int] = Field(default_factory=dict)

    @field_validator(
        "id", "agent_id", "title", "business_risk", "recommended_action", "control_mapping"
    )
    @classmethod
    def required_text_is_nonempty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("finding text fields must not be empty")
        return value

    @field_validator("rule_id")
    @classmethod
    def optional_rule_id_is_nonempty(cls, value: str | None) -> str | None:
        return _require_nonempty_identifier(value) if value is not None else None


class AgentAccessSummary(StewardModel):
    """Access posture used by the UI, report, and future LLM enrichment."""

    agent_id: str
    direct_access: list[str] = Field(default_factory=list)
    effective_access: list[str] = Field(default_factory=list)
    used_tools: list[str] = Field(default_factory=list)
    unused_direct_grants: list[str] = Field(default_factory=list)
    # Maps a tool to the delegation path that grants it. Direct grants map to
    # ``[agent_id]``; an inherited grant maps to ``[agent, ..., grantor]``.
    delegation_paths: dict[str, list[str]] = Field(default_factory=dict)
    # Filled by the GPT enrichment layer. They are capability phrases, not tool
    # identifiers, so an empty deterministic default is intentional.
    needed_capabilities: list[str] = Field(default_factory=list)
    granted_vs_needed_gap: list[str] = Field(default_factory=list)

    @field_validator(
        "agent_id",
    )
    @classmethod
    def agent_id_is_nonempty(cls, value: str) -> str:
        return _require_nonempty_identifier(value)


class AnalysisResult(StewardModel):
    """One canonical result object emitted by the deterministic pipeline.

    The LLM layer may enrich a result with capability/needed-access data and
    replace fallback narratives, but it must retain the cited findings created
    here or pass them through the citation verifier again.
    """

    fleet: Fleet
    tools: ToolCatalog
    findings: list[Finding] = Field(default_factory=list)
    direct_access: dict[str, list[str]] = Field(default_factory=dict)
    effective_access: dict[str, list[str]] = Field(default_factory=dict)
    # agent id -> tool id -> path to the direct grant owner
    delegation_paths: dict[str, dict[str, list[str]]] = Field(default_factory=dict)
    unused_grants: dict[str, list[str]] = Field(default_factory=dict)
    access_summaries: dict[str, AgentAccessSummary] = Field(default_factory=dict)
    # Populated by the optional GPT enrichment layer. Keeping these alongside
    # deterministic access facts lets reports distinguish Granted, Used, and
    # Needed without treating an inference as a graph fact.
    tool_capabilities: dict[str, str] = Field(default_factory=dict)
    needed_capabilities: dict[str, list[str]] = Field(default_factory=dict)
    granted_vs_needed_gaps: dict[str, list[str]] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    analysis_version: str = "0.1"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
