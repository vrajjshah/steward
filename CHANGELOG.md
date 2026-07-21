# Changelog

All notable changes to Steward are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Labeled LLM-tier accuracy benchmark** (`evals/benchmark/`, `make llm-benchmark`):
  20 ground-truth scenarios — 8 in-scope toxic sensitive-read + external-egress pairs,
  8 benign near-misses, 4 out-of-scope toxic pairs — measuring the model tier's
  precision/recall and hallucinated-citation rate separately from the deterministic
  gate. Cached live `gpt-oss-120b` result: 8/8 recall, 0/8 false positives, 0
  hallucinated citations; CI re-verifies the cache offline.
- **Known-server capability mapping in the MCP adapter**: eleven widely used MCP
  servers (filesystem, GitHub, Slack, PostgreSQL, SQLite, fetch, Brave Search,
  Google Drive, memory, Puppeteer, Sentry), recognized by exact package identifier
  in `command`/`args`, now import as their documented capability sets instead of
  one opaque bundle. Unrecognized servers keep conservative server-bundle
  granularity, provenance disclaimers are embedded in every mapped node, and a
  realistic credential-free sample lives at `examples/claude_desktop_config.json`.
- Architecture documentation (`docs/ARCHITECTURE.md`) with system, Granted/Used/Needed,
  detect→close→prove, and domain-model diagrams; a **mapping of each check to the OWASP
  LLM Top 10 (2025)** — over-privilege / toxic-combos / escalation as facets of
  **LLM06 Excessive Agency**, and the exfiltration path as **LLM02 Sensitive Information
  Disclosure**.
- Contributing guide, security policy, README badges, and CI that now runs lint + tests + eval.
- Expanded the synthetic fleet to **30 agents** across ~20 departments, adding a **two-hop
  delegation chain** (ExecBriefingBot → ChiefOfStaffBot → FinanceBot) that surfaces a deeper
  multi-hop escalation finding. Answer key and demo cache regenerated in lockstep; the
  deterministic gate remains 1.000.

### Fixed
- The high-entropy secret heuristic no longer masks long snake/kebab-case word
  identifiers (e.g. `read_financial_statements`) in outbound LLM payloads. Two
  synthetic-fleet tools were previously unclassifiable because their ids arrived
  at the model as `[REDACTED]`; the regenerated demo cache now records complete
  (34/34) tool classification. Credential-shaped strings are still masked.

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
