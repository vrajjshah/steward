"""Deterministic, source-linked MCP threat context for verified findings.

The graph is still the only evidence source for whether a particular Steward
finding exists.  This module only adds carefully scoped external context *after*
the finding has been generated and citation-verified.  It is deliberately
small, static, and zero-key so the demo can explain why a risk class matters
without making another network or model call.
"""

from __future__ import annotations

from collections.abc import Iterable

from .models import Finding, OwaspMcpReference, RealWorldIncident

# OWASP publishes the MCP Top 10 as a living beta.  Keep the source links next
# to the mappings so a reviewer can distinguish Steward's graph evidence from
# external threat taxonomy.
MCP01 = OwaspMcpReference(
    id="MCP01:2025",
    title="Token Mismanagement & Secret Exposure",
    url=(
        "https://owasp.org/www-project-mcp-top-10/2025/"
        "MCP01-2025-Token-Mismanagement-and-Secret-Exposure"
    ),
    relevance="Credentials and token handling are a distinct MCP risk class; this reference is context, not evidence of a token issue in this finding.",
)
MCP02 = OwaspMcpReference(
    id="MCP02:2025",
    title="Privilege Escalation via Scope Creep",
    url=(
        "https://owasp.org/www-project-mcp-top-10/2025/"
        "MCP02-2025%E2%80%93Privilege-Escalation-via-Scope-Creep"
    ),
    relevance="Delegated authority can turn a narrowly scoped agent into a higher-impact actor through effective access.",
)
MCP03 = OwaspMcpReference(
    id="MCP03:2025",
    title="Tool Poisoning",
    url="https://owasp.org/www-project-mcp-top-10/2025/MCP03-2025%E2%80%93Tool-Poisoning",
    relevance="A compromised or misleading tool can steer an agent toward unintended data handling or external actions.",
)
MCP04 = OwaspMcpReference(
    id="MCP04:2025",
    title="Software Supply Chain Attacks & Dependency Tampering",
    url=(
        "https://owasp.org/www-project-mcp-top-10/2025/"
        "MCP04-2025%E2%80%93Software-Supply-Chain-Attacks%26Dependency-Tampering"
    ),
    relevance="A compromised MCP dependency can add covert external egress to an otherwise trusted workflow.",
)


SUPABASE_MCP_SCENARIO = RealWorldIncident(
    title="Supabase MCP stored prompt-injection scenario",
    date="Documented 16 Sep 2025",
    url="https://supabase.com/blog/defense-in-depth-mcp",
    relevance=(
        "Supabase documented a scenario where stored instructions led an MCP-connected agent to read private "
        "database data and write it into an attacker-visible field. It illustrates this read-to-egress risk class; "
        "it is not evidence that this fleet uses Supabase."
    ),
)
POSTMARK_MCP_BACKDOOR = RealWorldIncident(
    title="Malicious postmark-mcp package backdoor (v1.0.16)",
    date="Postmark advisory, 25 Sep 2025",
    url="https://postmarkapp.com/blog/information-regarding-malicious-postmark-mcp-package",
    relevance=(
        "Postmark reported that an impersonating npm package silently BCC'd email to an external server. "
        "It is an analogous tool-poisoning and supply-chain incident, not evidence that this fleet installed the package."
    ),
)
INVARIANT_TOXIC_AGENT_FLOW = RealWorldIncident(
    title="Invariant Labs GitHub MCP toxic agent flow",
    date="26 May 2025",
    url="https://invariantlabs.ai/blog/mcp-github-vulnerability",
    relevance=(
        "Invariant demonstrated an untrusted GitHub issue coercing an MCP-connected agent to move private repository "
        "data into a public pull request. It illustrates how composed authority paths can exceed an agent's apparent role."
    ),
)


TOKEN_REPLAY_CONTEXT = {
    "title": "MCP01 authentication and token-replay context (not a Steward finding)",
    "owasp_mcp": MCP01.model_dump(mode="json"),
    "incident": {
        "title": "CVE-2026-32211 — Azure MCP Server missing authentication",
        "date": "NVD published 2 Apr 2026",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-32211",
        "relevance": (
            "NVD records missing authentication for a critical Azure MCP Server function. Microsoft, the CNA, "
            "assigned CVSS 3.1 9.1 Critical; NVD's own score is 7.5 High. Token replay is a related MCP01 concern, "
            "but this CVE record specifically describes missing authentication—not token replay."
        ),
    },
}


def _cited_tool_ids(finding: Finding) -> set[str]:
    """Use only graph-cited tools to decide whether external context applies."""

    return {
        evidence.entity_id
        for evidence in finding.evidence
        if evidence.entity_type == "tool"
    }


def _deduplicate_by_key[T](items: Iterable[T], key: str) -> list[T]:
    """Preserve source order while avoiding duplicate references after replays."""

    output: list[T] = []
    seen: set[str] = set()
    for item in items:
        value = str(getattr(item, key))
        if value not in seen:
            output.append(item)
            seen.add(value)
    return output


def ground_finding_in_real_world_context(finding: Finding) -> Finding:
    """Attach exact, conservative incident context to known fixture patterns.

    This mapping intentionally does not create findings or alter severity,
    evidence, recommendations, or check semantics.  The external references
    help a reviewer understand a documented analogue once a graph-derived
    finding already exists.
    """

    tools = _cited_tool_ids(finding)
    owasp = list(finding.owasp_mcp)
    incidents = list(finding.real_world_incident)

    # SupportBot's deterministic exfiltration finding and SalesBot's
    # graph-verified LLM-generalized CRM/email pair are deliberately covered
    # by their cited capability pairs, not a display-name heuristic.
    has_external_email = "send_external_email" in tools
    has_sensitive_read = bool({"read_customer_pii", "read_crm"} & tools)
    if has_external_email and has_sensitive_read:
        owasp.extend((MCP03, MCP04))
        incidents.extend((SUPABASE_MCP_SCENARIO, POSTMARK_MCP_BACKDOOR))

    # Preserve the exact, cited SummaryBot -> FinanceBot delegation proof. We
    # do not annotate unrelated escalation findings with a claimed real-world
    # incident merely because they are also delegated.
    has_summary_finance_path = {
        "summary_bot->finance_bot",
        "approve_payment",
    }.issubset(
        {
            evidence.entity_id
            for evidence in finding.evidence
            if evidence.entity_type in {"delegation_edge", "tool"}
        }
    )
    if finding.agent_id == "summary_bot" and has_summary_finance_path:
        owasp.append(MCP02)
        incidents.append(INVARIANT_TOXIC_AGENT_FLOW)

    return finding.model_copy(
        update={
            "owasp_mcp": _deduplicate_by_key(owasp, "id"),
            "real_world_incident": _deduplicate_by_key(incidents, "url"),
        }
    )


def ground_findings_in_real_world_context(findings: Iterable[Finding]) -> list[Finding]:
    """Return findings with deterministic incident annotations, preserving order."""

    return [ground_finding_in_real_world_context(finding) for finding in findings]
