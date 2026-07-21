# Changelog

All notable changes to Steward are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Architecture documentation (`docs/ARCHITECTURE.md`) with system, Granted/Used/Needed,
  detect→close→prove, and domain-model diagrams; a **mapping of each check to the OWASP
  LLM Top 10 (2025)** — over-privilege / toxic-combos / escalation as facets of
  **LLM06 Excessive Agency**, and the exfiltration path as **LLM02 Sensitive Information
  Disclosure**.
- Contributing guide, security policy, README badges, and CI that now runs lint + tests + eval.

### Planned
- Ingestion of real agent execution traces (the "Used" pillar) with drift detection.
- Live connectors for agent registries, MCP gateways, and cloud IAM.
- Continuous access-certification campaigns and remediation workflows.

## [0.1.0] — 2026-07-18

First public release.

### Added
- **Effective-access graph** over agents, tools, owners, and delegation edges,
  computing direct ∪ transitively-delegated access (`steward/graph.py`).
- **Deterministic risk checks** — segregation of duties, over-privilege,
  escalation via delegation, and orphaned agents — each emitting evidence-backed
  findings (`steward/findings.py`).
- **Citation verifier** that drops any finding whose cited agents/tools/edges are
  not real, reachable graph entities; nothing hallucinated ever surfaces.
- **Two-tier trust model** — an always-on deterministic floor plus an optional
  model-generalization tier (`gpt-oss-120b` on Amazon Bedrock, any Converse model
  via `MODEL_*`) that proposes toxic combinations beyond the hardcoded rules and
  is measured separately.
- **Secret-redaction boundary** — `env` values and secret-shaped strings are
  stripped before any model call, log, cache, or ledger write
  (`steward/redaction.py`).
- **Least-privilege policy generation** (default-deny) from cited findings
  (`steward/policy_gen.py`) and a narrow **MCP enforcement gate**
  (`steward/enforce.py`).
- **Signed, tamper-evident audit ledger** — Ed25519-signed, SHA-256-chained
  entries with PII stored as commitments; offline `audit verify` catches any
  single-byte tampering (`steward/ledger.py`).
- **Red-team exfiltration scenario** demonstrating an unguarded attempt
  succeeding and being blocked through the policy gate (`steward/redteam.py`).
- **OWASP MCP Top-10 and documented-incident context** attached to findings as
  source-linked context, never as a substitute for graph evidence
  (`steward/incident_grounding.py`).
- **Reporting surfaces** — FastAPI dashboard, per-agent certification risk cards,
  and JSON/Markdown/HTML report exports.
- **MCP config adapter** for Claude Desktop / Cursor `mcp.json`, importing each
  server as a conservative server-level capability bundle.
- **Golden-set evaluation** — a labeled 21-agent synthetic fleet (13 clean
  controls) with a precision/recall + citation-validity gate wired into CI.
- **Zero-key demo mode** (`STEWARD_DEMO=1`) serving a committed analysis cache so
  the full dashboard and detect→close→prove flow run with no cloud account.

[Unreleased]: https://github.com/vrajjshah/steward/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/vrajjshah/steward/releases/tag/v0.1.0
