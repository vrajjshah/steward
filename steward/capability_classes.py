"""Capability classes shared by deterministic scoring and named pattern checks.

These sets classify *tool ids* the way the deterministic crown-jewel rules do:
by known identifier, honestly documented as such. They are intentionally small
and conservative — a tool outside these sets simply contributes no modifier —
and they are the single place the "what counts as sensitive / high-impact /
untrusted / exfiltration" judgment lives, so the risk score (steward.scoring)
and the lethal-trifecta check (steward.findings) cannot drift apart.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

# Capabilities whose misuse has direct financial, destructive, or privilege
# consequences. Used for the blast-radius component of the risk score.
HIGH_IMPACT_TOOL_IDS = frozenset(
    {
        "approve_payment",
        "run_payroll",
        "delete_records",
        "export_data",
        "send_external_email",
        "grant_access",
    }
)

# Reads of private/regulated business data. Also the "private data access" leg
# of the lethal trifecta.
SENSITIVE_READ_TOOL_IDS = frozenset(
    {
        "read_customer_pii",
        "read_crm",
        "read_db",
        "read_contract_repository",
    }
)

# Channels that expose the agent to content the organization does not control
# (the classic prompt-injection ingress). Also the "untrusted content" leg of
# the lethal trifecta.
UNTRUSTED_CONTENT_TOOL_IDS = frozenset({"web_search"})

# Channels that can move data outside the organization boundary. Also the
# "exfiltration" leg of the lethal trifecta.
EXFILTRATION_TOOL_IDS = frozenset({"send_external_email", "export_data"})


@dataclass(frozen=True)
class CapabilityClasses:
    """The four tool-id classes used by scoring and the trifecta check.

    A single value object so a custom rule pack can *extend* the built-in
    vocabulary with a client's tool ids without any code forking a copy of the
    canonical sets. The default instance below wraps the module constants; a
    pack composes onto them with :meth:`extended`.
    """

    high_impact: frozenset[str]
    sensitive_read: frozenset[str]
    untrusted_content: frozenset[str]
    exfiltration: frozenset[str]

    def extended(
        self,
        *,
        high_impact: Iterable[str] = (),
        sensitive_read: Iterable[str] = (),
        untrusted_content: Iterable[str] = (),
        exfiltration: Iterable[str] = (),
    ) -> CapabilityClasses:
        """Return a copy with the given ids added to each class (union)."""

        return CapabilityClasses(
            high_impact=self.high_impact | frozenset(high_impact),
            sensitive_read=self.sensitive_read | frozenset(sensitive_read),
            untrusted_content=self.untrusted_content | frozenset(untrusted_content),
            exfiltration=self.exfiltration | frozenset(exfiltration),
        )


# The canonical classes every code path uses unless a rule pack extends them.
DEFAULT_CAPABILITY_CLASSES = CapabilityClasses(
    high_impact=HIGH_IMPACT_TOOL_IDS,
    sensitive_read=SENSITIVE_READ_TOOL_IDS,
    untrusted_content=UNTRUSTED_CONTENT_TOOL_IDS,
    exfiltration=EXFILTRATION_TOOL_IDS,
)
