"""Deterministic, evidence-backed risk checks for Steward.

The checks in this module intentionally do not call an LLM. They establish the
reliable baseline that works in zero-key demo mode; an enrichment layer can
classify unfamiliar tools and improve the narratives without changing access
facts or bypassing citation verification.
"""

# The module intentionally contains several long auditor-facing policy strings.
# Splitting them further would make the policies harder to review than allowing
# long prose constants.
# ruff: noqa: E501

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from .capability_classes import DEFAULT_CAPABILITY_CLASSES, CapabilityClasses
from .control_mapping import annotate_findings_with_control_frameworks
from .graph import AccessProvenance, EffectiveAccessGraph, delegation_edge_id
from .incident_grounding import ground_findings_in_real_world_context
from .loaders import validate_inventory
from .models import (
    Agent,
    AgentAccessSummary,
    AnalysisResult,
    Evidence,
    Finding,
    Fleet,
    RealWorldIncident,
    ToolCatalog,
)
from .scoring import score_and_rank_findings


@dataclass(frozen=True)
class ToxicCapabilityRule:
    """A deterministic crown-jewel combination that must always be caught."""

    rule_id: str
    tool_ids: frozenset[str]
    severity: str
    title: str
    business_risk: str
    recommended_action: str
    control_mapping: str


# These policies form the non-LLM safety floor. The exfiltration rule is a
# toxic combination and uses check_type="sod" because v0.1 exposes exactly the
# four check types specified in the public finding schema.
CROWN_JEWEL_SOD_RULES: tuple[ToxicCapabilityRule, ...] = (
    ToxicCapabilityRule(
        rule_id="finance_create_vendor_approve_payment",
        tool_ids=frozenset({"create_vendor", "approve_payment"}),
        severity="critical",
        title="Critical fraud path: create vendor and approve payment",
        business_risk=(
            "This agent can create a payee in vendor master data and authorize a payment to that payee. "
            "Combining initiation and approval creates a self-dealing path that can bypass independent finance review."
        ),
        recommended_action=(
            "Revoke either create_vendor or approve_payment from this agent and require an independently owned "
            "approval step for vendor-related disbursements."
        ),
        control_mapping="SOX ITGC — segregation of duties (vendor creation versus payment approval)",
    ),
    ToxicCapabilityRule(
        rule_id="hr_add_employee_run_payroll",
        tool_ids=frozenset({"add_employee", "run_payroll"}),
        severity="critical",
        title="Critical ghost-employee fraud path",
        business_risk=(
            "This agent can create an employee record and run payroll. The combined access can be used to add a "
            "ghost employee and cause compensation to be issued without an independent HR or payroll review."
        ),
        recommended_action=(
            "Separate employee-master-data creation from payroll execution, with an independently owned review "
            "before a new employee can enter a payroll run."
        ),
        control_mapping="SOX ITGC — segregation of duties (employee setup versus payroll execution)",
    ),
    ToxicCapabilityRule(
        rule_id="it_request_access_grant_access",
        tool_ids=frozenset({"request_access", "grant_access"}),
        severity="high",
        title="Self-granting privilege path",
        business_risk=(
            "This agent can initiate an access request and grant the requested access. That removes independent "
            "authorization and enables privilege escalation outside the intended approval workflow."
        ),
        recommended_action=(
            "Keep request initiation and role assignment in separately owned identities, and require a human or "
            "independent approval before any grant is applied."
        ),
        control_mapping="Identity governance — segregation of duties (access request versus access grant)",
    ),
    ToxicCapabilityRule(
        rule_id="sensitive_data_external_egress",
        tool_ids=frozenset({"read_customer_pii", "send_external_email"}),
        severity="critical",
        title="Critical data-exfiltration path",
        business_risk=(
            "This agent can read customer PII and send messages outside the organization. Together those grants "
            "create a direct route for sensitive customer data to leave the company without a separate egress control."
        ),
        recommended_action=(
            "Remove direct external-email capability from the PII-reading agent, or route outbound messages through "
            "a separately controlled service with approved templates, DLP, and human review."
        ),
        control_mapping="Data protection — least privilege and controlled external egress",
    ),
)


@dataclass(frozen=True)
class DelegatedHighRiskRule:
    """A direct capability whose delegated use materially expands blast radius."""

    tool_id: str
    rule_id: str
    severity: str
    title: str
    business_risk: str
    recommended_action: str
    control_mapping: str


# This is deliberately narrow. GPT capability reasoning can propose additional
# high-risk tool classes, but the deterministic layer should not turn ordinary
# read-only delegation into a noisy escalation alert.
DELEGATED_HIGH_RISK_RULES: tuple[DelegatedHighRiskRule, ...] = (
    DelegatedHighRiskRule(
        tool_id="approve_payment",
        rule_id="delegated_high_risk_payment_approval",
        severity="critical",
        title="Delegated payment-approval blast radius",
        business_risk=(
            "This agent does not hold payment approval directly, but it can reach an agent that does through delegation. "
            "Its effective access therefore includes authority to authorize disbursements, creating a confused-deputy path."
        ),
        recommended_action=(
            "Remove or constrain the delegation link to the payment-approving agent. If delegation is necessary, "
            "expose a narrowly scoped workflow action rather than the delegate's general approval authority."
        ),
        control_mapping="Identity governance — effective access review and least privilege",
    ),
    DelegatedHighRiskRule(
        tool_id="run_payroll",
        rule_id="delegated_high_risk_payroll_execution",
        severity="critical",
        title="Delegated payroll-execution blast radius",
        business_risk=(
            "This agent inherits payroll-execution capability through delegation, expanding its effective authority "
            "to release compensation without a direct entitlement on its own identity."
        ),
        recommended_action=(
            "Remove or tightly scope the delegation path, and expose only a reviewed payroll workflow if needed."
        ),
        control_mapping="Identity governance — effective access review and least privilege",
    ),
    DelegatedHighRiskRule(
        tool_id="grant_access",
        rule_id="delegated_high_risk_access_grant",
        severity="high",
        title="Delegated access-granting blast radius",
        business_risk=(
            "This agent inherits the ability to assign application access through delegation, creating an indirect "
            "privilege-escalation path that is easy to miss in direct-grant reviews."
        ),
        recommended_action=(
            "Remove or narrow the delegation path and require an independently authorized access-grant workflow."
        ),
        control_mapping="Identity governance — effective access review and least privilege",
    ),
    DelegatedHighRiskRule(
        tool_id="send_external_email",
        rule_id="delegated_high_risk_external_egress",
        severity="high",
        title="Delegated external-egress blast radius",
        business_risk=(
            "This agent inherits the ability to send messages outside the organization through delegation, increasing "
            "the risk that internal data can leave through a confused-deputy path."
        ),
        recommended_action=(
            "Remove or constrain the delegation path and enforce a reviewed outbound-message workflow."
        ),
        control_mapping="Data protection — controlled external egress and least privilege",
    ),
    DelegatedHighRiskRule(
        tool_id="export_data",
        rule_id="delegated_high_risk_data_export",
        severity="high",
        title="Delegated data-export blast radius",
        business_risk=(
            "This agent inherits data-export capability through delegation, creating an indirect path for bulk data to "
            "leave its expected business workflow."
        ),
        recommended_action=(
            "Remove or narrowly scope the delegation path and require an approved export workflow."
        ),
        control_mapping="Data protection — least privilege and controlled data export",
    ),
    DelegatedHighRiskRule(
        tool_id="delete_records",
        rule_id="delegated_high_risk_record_deletion",
        severity="high",
        title="Delegated destructive-action blast radius",
        business_risk=(
            "This agent inherits record-deletion capability through delegation, which can expand the impact of a "
            "compromised or misdirected agent beyond its direct role."
        ),
        recommended_action=(
            "Remove or tightly scope the delegation path and require a reviewed destructive-action workflow."
        ),
        control_mapping="Least privilege — controlled destructive actions",
    ),
)


HIGH_RISK_UNUSED_TOOL_IDS = frozenset(
    {
        "approve_payment",
        "create_vendor",
        "run_payroll",
        "add_employee",
        "grant_access",
        "delete_records",
        "export_data",
        "send_external_email",
        "read_customer_pii",
    }
)


def find_sod_violations(
    fleet: Fleet,
    graph: EffectiveAccessGraph | None = None,
    *,
    rules: Sequence[ToxicCapabilityRule] = CROWN_JEWEL_SOD_RULES,
) -> list[Finding]:
    """Find deterministic toxic combinations in direct or effective access."""

    graph = graph or EffectiveAccessGraph(fleet)
    findings: list[Finding] = []
    for agent in sorted(fleet.agents, key=lambda item: item.id):
        effective_tools = graph.effective_tools(agent.id)
        for rule in rules:
            if not rule.tool_ids.issubset(effective_tools):
                continue
            evidence = _agent_evidence(agent, "holds this effective-access combination")
            for tool_id in sorted(rule.tool_ids):
                evidence.extend(_access_evidence(agent, graph.provenance_for(agent.id, tool_id)))
            findings.append(
                Finding(
                    id=f"sod:{agent.id}:{rule.rule_id}",
                    rule_id=rule.rule_id,
                    source="deterministic",
                    agent_id=agent.id,
                    check_type="sod",
                    severity=rule.severity,  # Pydantic constrains the literal at construction.
                    title=rule.title,
                    business_risk=rule.business_risk,
                    evidence=_deduplicate_evidence(evidence),
                    recommended_action=rule.recommended_action,
                    control_mapping=rule.control_mapping,
                )
            )
    return findings


def find_over_privilege(
    fleet: Fleet,
    graph: EffectiveAccessGraph | None = None,
) -> list[Finding]:
    """Find direct grants that have not appeared in an agent's usage log."""

    graph = graph or EffectiveAccessGraph(fleet)
    findings: list[Finding] = []
    for agent in sorted(fleet.agents, key=lambda item: item.id):
        if not agent.usage_log_available:
            continue
        unused_tools = sorted(set(agent.granted_tools) - set(agent.usage_log))
        if not unused_tools:
            continue
        severity = "high" if set(unused_tools) & HIGH_RISK_UNUSED_TOOL_IDS else "medium"
        tool_list = ", ".join(unused_tools)
        evidence = _agent_evidence(
            agent,
            f"usage log contains no invocation of these direct grants: {tool_list}",
        )
        for tool_id in unused_tools:
            provenance = graph.provenance_for(agent.id, tool_id)
            evidence.extend(_access_evidence(agent, provenance))
        findings.append(
            Finding(
                id=f"over_privilege:{agent.id}:unused_granted_tools",
                rule_id="unused_granted_tools",
                source="deterministic",
                agent_id=agent.id,
                check_type="over_privilege",
                severity=severity,
                title=f"Unused standing access: {len(unused_tools)} direct grant{'s' if len(unused_tools) != 1 else ''}",
                business_risk=(
                    f"{agent.name} has direct access to {tool_list}, but its supplied usage log shows no invocation of "
                    "those grants. Unused standing permissions enlarge the blast radius of a prompt injection, "
                    "misconfiguration, or compromised agent without supporting observed work."
                ),
                evidence=_deduplicate_evidence(evidence),
                recommended_action=(
                    f"Revoke the unused direct grant{'s' if len(unused_tools) != 1 else ''} ({tool_list}) and re-grant "
                    "only through a time-bound, reviewed workflow if a future business need is confirmed."
                ),
                control_mapping="Least privilege — access certification using granted versus used access",
            )
        )
    return findings


def find_escalation_paths(
    fleet: Fleet,
    graph: EffectiveAccessGraph | None = None,
    *,
    rules: Sequence[DelegatedHighRiskRule] = DELEGATED_HIGH_RISK_RULES,
) -> list[Finding]:
    """Find high-risk powers reachable only through an agent delegation path."""

    graph = graph or EffectiveAccessGraph(fleet)
    findings: list[Finding] = []
    for agent in sorted(fleet.agents, key=lambda item: item.id):
        for rule in rules:
            provenance = graph.provenance_for(agent.id, rule.tool_id)
            if provenance is None or provenance.is_direct:
                continue
            evidence = _agent_evidence(
                agent,
                f"reaches {rule.tool_id} only through delegation to {provenance.grantor_agent_id}",
            )
            evidence.extend(_access_evidence(agent, provenance))
            findings.append(
                Finding(
                    id=f"escalation:{agent.id}:{rule.rule_id}",
                    rule_id=rule.rule_id,
                    source="deterministic",
                    agent_id=agent.id,
                    check_type="escalation",
                    severity=rule.severity,
                    title=rule.title,
                    business_risk=rule.business_risk,
                    evidence=_deduplicate_evidence(evidence),
                    recommended_action=rule.recommended_action,
                    control_mapping=rule.control_mapping,
                )
            )
    return findings


LETHAL_TRIFECTA_SOURCE = RealWorldIncident(
    title="The lethal trifecta for AI agents",
    date="Simon Willison, 16 Jun 2025",
    url="https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/",
    relevance=(
        "Willison names the canonical agent-exfiltration pattern: private-data access, exposure to "
        "untrusted content, and an external communication channel in one agent. This reference explains "
        "the risk class; the evidence for this finding is the cited access graph."
    ),
)


def find_lethal_trifecta(
    fleet: Fleet,
    graph: EffectiveAccessGraph | None = None,
    capability_classes: CapabilityClasses = DEFAULT_CAPABILITY_CLASSES,
) -> list[Finding]:
    """Flag agents whose effective access spans all three trifecta classes.

    An agent that can read private data, is exposed to content the
    organization does not control, and holds an external egress channel is one
    prompt injection away from exfiltration. The three capability classes are
    matched by known tool id (the same honest limitation as the crown-jewel
    rules) against *effective* access, so a leg reached only through
    delegation still completes the trifecta.
    """

    graph = graph or EffectiveAccessGraph(fleet)
    findings: list[Finding] = []
    for agent in sorted(fleet.agents, key=lambda item: item.id):
        effective_tools = graph.effective_tools(agent.id)
        legs = {
            "private-data access": sorted(effective_tools & capability_classes.sensitive_read),
            "untrusted-content exposure": sorted(
                effective_tools & capability_classes.untrusted_content
            ),
            "exfiltration channel": sorted(effective_tools & capability_classes.exfiltration),
        }
        if not all(legs.values()):
            continue
        evidence = _agent_evidence(
            agent,
            "effective access spans private data, untrusted content, and an exfiltration channel",
        )
        for tool_ids in legs.values():
            for tool_id in tool_ids:
                evidence.extend(_access_evidence(agent, graph.provenance_for(agent.id, tool_id)))
        leg_summary = "; ".join(
            f"{leg}: {', '.join(tool_ids)}" for leg, tool_ids in legs.items()
        )
        findings.append(
            Finding(
                id=f"sod:{agent.id}:lethal_trifecta",
                rule_id="lethal_trifecta",
                source="deterministic",
                agent_id=agent.id,
                check_type="sod",
                severity="critical",
                title="Lethal trifecta exposure: private data + untrusted content + exfiltration channel",
                business_risk=(
                    f"{agent.name} combines all three legs of the lethal trifecta — {leg_summary}. "
                    "One prompt injection arriving through the untrusted-content channel can instruct the agent "
                    "to read private data and deliver it through the egress channel; no additional compromise is required."
                ),
                evidence=_deduplicate_evidence(evidence),
                recommended_action=(
                    "Break at least one leg: remove the untrusted-content channel, remove the external egress "
                    "capability, or isolate private-data access into a separately controlled identity."
                ),
                control_mapping="Least privilege — separation of private data, untrusted input, and external egress",
                real_world_incident=[LETHAL_TRIFECTA_SOURCE],
            )
        )
    return findings


def find_orphans(fleet: Fleet) -> list[Finding]:
    """Find agents with no accountable business owner."""

    findings: list[Finding] = []
    for agent in sorted(fleet.agents, key=lambda item: item.id):
        if agent.owner is not None:
            continue
        findings.append(
            Finding(
                id=f"orphan:{agent.id}:missing_owner",
                rule_id="missing_owner",
                source="deterministic",
                agent_id=agent.id,
                check_type="orphan",
                severity="high",
                title="Ownerless agent has no accountable reviewer",
                business_risk=(
                    f"{agent.name} has no recorded owner. Without an accountable person to certify its purpose and "
                    "access, stale permissions and unsafe behavior can persist without a clear remediation decision."
                ),
                evidence=_agent_evidence(agent, "owner is null in the fleet inventory"),
                recommended_action=(
                    "Assign a named business owner to certify this agent's purpose and access, or disable the agent "
                    "until ownership is established."
                ),
                control_mapping="Accountability — named owner required for agent access certification",
            )
        )
    return findings


@dataclass(frozen=True)
class RulePack:
    """Additive, client-specific detection vocabulary loaded from a YAML pack.

    A pack extends the always-on built-in floor: extra toxic combinations and
    delegated-high-risk rules become ordinary ``source="deterministic"``
    findings, and the capability-class extensions feed scoring and the trifecta
    check so both understand the client's own tool ids. The empty default keeps
    every existing code path byte-identical.
    """

    sod_rules: tuple[ToxicCapabilityRule, ...] = ()
    delegated_rules: tuple[DelegatedHighRiskRule, ...] = ()
    capability_classes: CapabilityClasses = DEFAULT_CAPABILITY_CLASSES

    @property
    def rule_ids(self) -> tuple[str, ...]:
        return tuple(rule.rule_id for rule in (*self.sod_rules, *self.delegated_rules))


# Every rule id the built-in floor emits. A pack may not reuse one, so pack
# findings never collide with a built-in finding's id.
BUILTIN_RULE_IDS = frozenset(
    {rule.rule_id for rule in CROWN_JEWEL_SOD_RULES}
    | {rule.rule_id for rule in DELEGATED_HIGH_RISK_RULES}
    | {"lethal_trifecta", "unused_granted_tools", "missing_owner"}
)


def run_deterministic_checks(
    fleet: Fleet,
    tools: ToolCatalog | None = None,
    graph: EffectiveAccessGraph | None = None,
    *,
    rule_pack: RulePack | None = None,
) -> list[Finding]:
    """Run all four deterministic check types and suppress bad evidence.

    An optional ``rule_pack`` adds client-specific toxic combinations and
    delegated-high-risk rules and extends the capability classes used by
    scoring and the trifecta. Pack rules are additive; the built-in floor is
    unchanged, so ``rule_pack=None`` reproduces the original output exactly.
    """

    if tools is not None:
        validate_inventory(fleet, tools)
    graph = graph or EffectiveAccessGraph(fleet)
    pack = rule_pack or RulePack()
    capability_classes = pack.capability_classes
    findings = [
        *find_sod_violations(fleet, graph, rules=(*CROWN_JEWEL_SOD_RULES, *pack.sod_rules)),
        *find_lethal_trifecta(fleet, graph, capability_classes),
        *find_over_privilege(fleet, graph),
        *find_escalation_paths(
            fleet, graph, rules=(*DELEGATED_HIGH_RISK_RULES, *pack.delegated_rules)
        ),
        *find_orphans(fleet),
    ]
    # External incident and control-framework annotations plus the composite
    # risk score are deterministic context applied only to graph-verified
    # findings. They never create a signal or relax the citation gate above;
    # scoring changes only the presentation rank.
    return score_and_rank_findings(
        annotate_findings_with_control_frameworks(
            ground_findings_in_real_world_context(
                filter_valid_findings(findings, fleet, graph=graph, tools=tools)
            )
        ),
        fleet,
        graph,
        capability_classes,
    )


def analyze_fleet(
    fleet: Fleet, tools: ToolCatalog, *, rule_pack: RulePack | None = None
) -> AnalysisResult:
    """Build graph-derived access maps and run the deterministic safety floor.

    This is the preferred public entry point for an API, CLI, or report layer.
    A caller with Bedrock configured can enrich its output afterwards; the same
    result still carries the deterministic citations required for trust. An
    optional ``rule_pack`` adds client-specific SoD rules and capability classes.
    """

    validate_inventory(fleet, tools)
    graph = EffectiveAccessGraph(fleet)
    findings = run_deterministic_checks(fleet, tools, graph, rule_pack=rule_pack)
    direct_access = graph.direct_access_map()
    effective_access = graph.effective_access_map()
    delegation_paths = graph.delegation_paths_map()
    unused_grants = {
        agent.id: (
            sorted(set(agent.granted_tools) - set(agent.usage_log))
            if agent.usage_log_available
            else []
        )
        for agent in sorted(fleet.agents, key=lambda item: item.id)
    }
    summaries = {
        agent.id: AgentAccessSummary(
            agent_id=agent.id,
            direct_access=direct_access[agent.id],
            effective_access=effective_access[agent.id],
            used_tools=sorted(agent.usage_log),
            unused_direct_grants=unused_grants[agent.id],
            delegation_paths=delegation_paths[agent.id],
        )
        for agent in sorted(fleet.agents, key=lambda item: item.id)
    }
    return AnalysisResult(
        fleet=fleet,
        tools=tools,
        findings=findings,
        direct_access=direct_access,
        effective_access=effective_access,
        delegation_paths=delegation_paths,
        unused_grants=unused_grants,
        access_summaries=summaries,
    )


def citation_errors(
    finding: Finding,
    fleet: Fleet,
    *,
    graph: EffectiveAccessGraph | None = None,
    tools: ToolCatalog | None = None,
) -> list[str]:
    """Return every reason a finding cannot be tied to real graph entities.

    The function intentionally validates more than an entity's spelling: a
    cited tool must be effective access for the finding's subject, and a cited
    delegation edge must be reachable from that subject. This keeps an LLM
    narrative from attaching real-but-unrelated graph nodes as fake evidence.
    """

    graph = graph or EffectiveAccessGraph(fleet)
    errors: list[str] = []
    if finding.agent_id not in graph.agent_ids:
        return [f"finding agent {finding.agent_id!r} does not exist in the fleet"]

    if not finding.evidence:
        return ["finding has no evidence"]

    cited_principal = False
    effective_tools = graph.effective_tools(finding.agent_id)
    direct_tools = graph.direct_tools(finding.agent_id)
    catalog_tool_ids = tools.tool_ids if tools is not None else graph.tool_ids

    for evidence in finding.evidence:
        if evidence.entity_type == "agent":
            if evidence.entity_id not in graph.agent_ids:
                errors.append(f"unknown agent evidence: {evidence.entity_id}")
                continue
            if evidence.entity_id == finding.agent_id:
                cited_principal = True
            elif graph.delegation_path(finding.agent_id, evidence.entity_id) is None:
                errors.append(
                    f"agent evidence {evidence.entity_id!r} is not reachable from {finding.agent_id!r}"
                )
        elif evidence.entity_type == "tool":
            if (
                evidence.entity_id not in graph.tool_ids
                or evidence.entity_id not in catalog_tool_ids
            ):
                errors.append(f"unknown tool evidence: {evidence.entity_id}")
                continue
            if evidence.entity_id not in effective_tools:
                errors.append(
                    f"tool evidence {evidence.entity_id!r} is not effective access for {finding.agent_id!r}"
                )
            if finding.check_type == "over_privilege" and evidence.entity_id not in direct_tools:
                errors.append(
                    f"over-privilege tool evidence {evidence.entity_id!r} is not a direct grant for {finding.agent_id!r}"
                )
        elif evidence.entity_type == "delegation_edge":
            if not graph.has_delegation_edge(evidence.entity_id):
                errors.append(f"unknown delegation edge evidence: {evidence.entity_id}")
                continue
            source_agent_id = evidence.entity_id.split("->", maxsplit=1)[0]
            if graph.delegation_path(finding.agent_id, source_agent_id) is None:
                errors.append(
                    f"delegation edge {evidence.entity_id!r} is not reachable from {finding.agent_id!r}"
                )

    if not cited_principal:
        errors.append(f"finding does not cite its subject agent {finding.agent_id!r}")
    return errors


def verify_finding_evidence(
    finding: Finding,
    fleet: Fleet,
    *,
    graph: EffectiveAccessGraph | None = None,
    tools: ToolCatalog | None = None,
) -> bool:
    """Return whether one finding passes Steward's citation-verification gate."""

    return not citation_errors(finding, fleet, graph=graph, tools=tools)


def filter_valid_findings(
    findings: Iterable[Finding],
    fleet: Fleet,
    *,
    graph: EffectiveAccessGraph | None = None,
    tools: ToolCatalog | None = None,
) -> list[Finding]:
    """Drop findings whose evidence is empty, missing, or graph-incoherent."""

    graph = graph or EffectiveAccessGraph(fleet)
    return [
        finding
        for finding in findings
        if verify_finding_evidence(finding, fleet, graph=graph, tools=tools)
    ]


# A concise alias for report/API layers and eval code that previously used the
# phrase "verify findings" rather than "filter valid findings".
verify_findings = filter_valid_findings
# Explicitly named for the application boundary: only this filtered list may
# reach the API, report, or dashboard.
findings_with_valid_citations = filter_valid_findings


def _agent_evidence(agent: Agent, detail: str) -> list[Evidence]:
    return [Evidence(entity_type="agent", entity_id=agent.id, detail=detail)]


def _access_evidence(agent: Agent, provenance: AccessProvenance | None) -> list[Evidence]:
    """Build evidence for a direct grant or its full delegation path."""

    if provenance is None:
        # This should be unreachable for all built-in checks. Do not fabricate
        # a tool reference: the verifier will suppress a future malformed rule.
        return []

    evidence: list[Evidence] = []
    if provenance.is_direct:
        evidence.append(
            Evidence(
                entity_type="tool",
                entity_id=provenance.tool_id,
                detail=f"{agent.name} has a direct grant of {provenance.tool_id}.",
            )
        )
        return evidence

    # Full path proof: every delegation edge and the direct grant-holder agent
    # are cited before the inherited entitlement itself.
    for source_agent_id, target_agent_id in zip(provenance.path, provenance.path[1:], strict=False):
        evidence.append(
            Evidence(
                entity_type="delegation_edge",
                entity_id=delegation_edge_id(source_agent_id, target_agent_id),
                detail=f"{source_agent_id} can delegate to {target_agent_id}.",
            )
        )
    evidence.append(
        Evidence(
            entity_type="agent",
            entity_id=provenance.grantor_agent_id,
            detail=(
                f"{provenance.grantor_agent_id} is the direct grant holder reached through "
                f"{' -> '.join(provenance.path)}."
            ),
        )
    )
    evidence.append(
        Evidence(
            entity_type="tool",
            entity_id=provenance.tool_id,
            detail=(
                f"{agent.name} effectively reaches {provenance.tool_id} through "
                f"{' -> '.join(provenance.path)}."
            ),
        )
    )
    return evidence


def _deduplicate_evidence(evidence: Iterable[Evidence]) -> list[Evidence]:
    """Keep evidence readable while preserving the first explanatory detail."""

    result: list[Evidence] = []
    seen: set[tuple[str, str]] = set()
    for item in evidence:
        key = (item.entity_type, item.entity_id)
        if key not in seen:
            result.append(item)
            seen.add(key)
    return result
