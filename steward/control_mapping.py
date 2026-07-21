"""Deterministic mapping from Steward findings to published control frameworks.

Auditors and CISOs reason in control language: NIST SP 800-53, SOC 2 Trust
Services Criteria, ISO/IEC 27001, SOX ITGC, and — for AI systems — the EU AI
Act. Each Steward check type corresponds to well-established controls in those
frameworks, so every finding carries a structured ``control_frameworks`` list
naming the specific control, in the specific framework version, with a
one-line reason the mapping applies to an agent identity.

This is **context, not certification**: the mapping says "this finding speaks
to AC-5", never "you are (non)compliant with AC-5". It is applied only to
findings that already passed citation verification, exactly like the OWASP/
incident grounding annotations, and it never creates or suppresses a finding.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Any

from .models import ControlFrameworkReference, Finding

NIST = "NIST SP 800-53 Rev. 5"
SOC2 = "SOC 2 Trust Services Criteria (2017)"
ISO = "ISO/IEC 27001:2022"
SOX = "SOX ITGC"
EU_AI_ACT = "EU AI Act (Regulation (EU) 2024/1689)"
OWASP_LLM = "OWASP LLM Top 10 (2025)"


def _reference(framework: str, control_id: str, control_name: str, relevance: str) -> ControlFrameworkReference:
    return ControlFrameworkReference(
        framework=framework,
        control_id=control_id,
        control_name=control_name,
        relevance=relevance,
    )


CHECK_TYPE_CONTROLS: dict[str, tuple[ControlFrameworkReference, ...]] = {
    "sod": (
        _reference(
            NIST, "AC-5", "Separation of Duties",
            "One agent identity holds both sides of a duty that the control requires to be separated.",
        ),
        _reference(
            SOC2, "CC6.3", "Access modification and segregation of duties",
            "Toxic capability combinations in one identity undermine segregation-of-duties objectives.",
        ),
        _reference(
            ISO, "A.5.15", "Access control",
            "Access rules should prevent a single identity from combining conflicting capabilities.",
        ),
        _reference(
            ISO, "A.5.18", "Access rights",
            "Provisioned rights should be reviewed so conflicting entitlements are not co-held.",
        ),
        _reference(
            SOX, "SoD", "Segregation of duties over financial processes",
            "An agent that can initiate and approve the same transaction defeats independent review.",
        ),
        _reference(
            EU_AI_ACT, "Art. 14", "Human oversight",
            "A toxic combination lets an AI agent complete a consequential action without an independent human checkpoint.",
        ),
    ),
    "over_privilege": (
        _reference(
            NIST, "AC-6 / AC-6(1)", "Least Privilege / Authorize Access to Security Functions",
            "Standing grants with no observed use exceed the minimum access the agent's function requires.",
        ),
        _reference(
            SOC2, "CC6.1", "Logical access security",
            "Unused standing entitlements enlarge the logical-access attack surface without business need.",
        ),
        _reference(
            SOC2, "CC6.3", "Access modification and segregation of duties",
            "Granted-but-unused access should be removed through the access-modification process.",
        ),
        _reference(
            ISO, "A.8.2", "Privileged access rights",
            "High-risk unused entitlements are privileged rights that should be restricted and reviewed.",
        ),
        _reference(
            ISO, "A.5.18", "Access rights",
            "Access rights should be adjusted when observed use does not support the grant.",
        ),
        _reference(
            SOX, "Least privilege", "Least-privilege provisioning",
            "Unused financially-relevant entitlements weaken ITGC access assertions.",
        ),
    ),
    "escalation": (
        _reference(
            NIST, "AC-6", "Least Privilege",
            "Delegation extends the agent's effective privilege beyond its direct provisioning.",
        ),
        _reference(
            NIST, "AC-5", "Separation of Duties",
            "Authority reachable through delegation recombines duties the direct grants kept separate.",
        ),
        _reference(
            SOC2, "CC6.1", "Logical access security",
            "Effective access through delegation is logical access and must be evaluated as such.",
        ),
        _reference(
            ISO, "A.8.2", "Privileged access rights",
            "A privileged capability reachable only through delegation is still a privileged right of that identity.",
        ),
    ),
    "orphan": (
        _reference(
            NIST, "AC-2", "Account Management",
            "An agent identity with no accountable owner cannot be certified, reviewed, or deprovisioned on schedule.",
        ),
        _reference(
            SOC2, "CC6.2", "User registration and authorization",
            "Identities must be traceable to an accountable party throughout their lifecycle.",
        ),
        _reference(
            ISO, "A.5.16", "Identity management",
            "The full life cycle of an identity — including this non-human one — requires a responsible owner.",
        ),
        _reference(
            SOX, "Access accountability", "Accountable ownership of access",
            "Ownerless identities break the accountability chain ITGC access reviews depend on.",
        ),
    ),
}

# Rule-specific additions layered on top of the check-type mapping. Keyed by
# Finding.rule_id so a named pattern (e.g. the lethal trifecta) can carry
# pattern-specific control context.
RULE_CONTROLS: dict[str, tuple[ControlFrameworkReference, ...]] = {
    "lethal_trifecta": (
        _reference(
            OWASP_LLM, "LLM01", "Prompt Injection",
            "Untrusted content reaching an agent that holds private data and an egress channel is the canonical prompt-injection exfiltration setup.",
        ),
    ),
}

# Controls the governance *process* itself speaks to — the signed ledger and
# the certification workflow rather than any individual finding. Surfaced at
# report level, deliberately not attached to findings.
PROCESS_CONTROLS: tuple[ControlFrameworkReference, ...] = (
    _reference(
        EU_AI_ACT, "Art. 12", "Record-keeping",
        "Findings and certification decisions are recorded in a tamper-evident, verifiable log.",
    ),
    _reference(
        NIST, "AU-2", "Event Logging",
        "Analysis and review events are captured as signed, append-only audit records.",
    ),
    _reference(
        NIST, "AU-6", "Audit Record Review, Analysis, and Reporting",
        "The ledger supports independent offline verification and review of recorded events.",
    ),
    _reference(
        NIST, "AC-2", "Account Management (review)",
        "The certification queue implements periodic review of agent-identity access.",
    ),
    _reference(
        ISO, "A.8.15", "Logging",
        "Governance events are logged in a form protected against tampering.",
    ),
)


def annotate_findings_with_control_frameworks(findings: Iterable[Finding]) -> list[Finding]:
    """Attach the deterministic control mapping to verified findings.

    Idempotent by design: a finding that already carries control references is
    passed through unchanged, so applying the boundary twice (deterministic
    checks, then the public pipeline boundary) cannot duplicate context.
    """

    annotated: list[Finding] = []
    for finding in findings:
        if finding.control_frameworks:
            annotated.append(finding)
            continue
        references = list(CHECK_TYPE_CONTROLS.get(finding.check_type, ()))
        if finding.rule_id and finding.rule_id in RULE_CONTROLS:
            references.extend(RULE_CONTROLS[finding.rule_id])
        if not references:
            annotated.append(finding)
            continue
        annotated.append(finding.model_copy(update={"control_frameworks": references}))
    return annotated


def control_framework_coverage(findings: Iterable[Any]) -> list[dict[str, Any]]:
    """Aggregate per-finding control references into a framework coverage matrix.

    Accepts Finding models or already-normalized mappings. Output rows are
    grouped by framework, then control, with the finding count and the check
    types that touched the control — the summary an audit workpaper wants.
    """

    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for finding in findings:
        if isinstance(finding, Mapping):
            references = finding.get("control_frameworks", []) or []
            check_type = str(finding.get("check_type", "unknown"))
        else:
            references = getattr(finding, "control_frameworks", []) or []
            check_type = str(getattr(finding, "check_type", "unknown"))
        for reference in references:
            if isinstance(reference, Mapping):
                framework = str(reference.get("framework", "")).strip()
                control_id = str(reference.get("control_id", "")).strip()
                control_name = str(reference.get("control_name", "")).strip()
            else:
                framework = reference.framework
                control_id = reference.control_id
                control_name = reference.control_name
            if not framework or not control_id:
                continue
            key = (framework, control_id, control_name)
            row = grouped.setdefault(
                key,
                {
                    "framework": framework,
                    "control_id": control_id,
                    "control_name": control_name,
                    "findings": 0,
                    "check_types": set(),
                },
            )
            row["findings"] += 1
            row["check_types"].add(check_type)

    by_framework: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in grouped.values():
        by_framework[row["framework"]].append(
            {**row, "check_types": sorted(row["check_types"])}
        )
    return [
        {
            "framework": framework,
            "controls": sorted(rows, key=lambda item: item["control_id"]),
        }
        for framework, rows in sorted(by_framework.items())
    ]
