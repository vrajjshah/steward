# Changelog

All notable changes to Steward are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **CI gating flags on `steward analyze`**: `--fail-on <severity>` exits non-zero
  when any finding at or above the threshold exists, and `--fail-on-drift` (with
  `--traces`) exits non-zero on used-but-not-granted access or unknown identities
  — so a pull request that grants a toxic pair, or a trace window showing drift,
  fails the build. Findings and the reconciliation report are printed before the
  exit so the CI log carries the evidence.
- **Pluggable model backends** (`LLM_BACKEND`): the enrichment tier now runs on
  (1) a local Ollama or any OpenAI-compatible `/v1/chat/completions` endpoint —
  zero cloud account, zero data egress, the recommended posture for security
  teams; (2) Amazon Bedrock (default) with open-weight `gpt-oss-120b` as the
  tested default and Anthropic Claude models as verified drop-ins (sampling
  parameters are automatically omitted for Claude, which rejects them); or
  (3) any hosted OpenAI-compatible API. All backends share the same redaction
  boundary, metadata-only cost logger, and `MODEL_*` tier contract; trust
  properties are model- and backend-independent. An A/B of the toxic-combination
  tier on the labeled benchmark measured `gpt-oss-120b` and Claude Opus 4.8 at
  identical ceiling accuracy (8/8 recall, 0 FP, 0 hallucinated citations), so
  the open-weight model remains the recommended Bedrock default on cost. The
  accuracy benchmark gained `--output` for A/B runs and now records the actual
  backend/model ids in its provenance metadata.
- **Control-framework mapping**: every verified finding carries structured,
  versioned references into NIST SP 800-53 Rev. 5, SOC 2 TSC (2017), ISO/IEC
  27001:2022, SOX ITGC, and the EU AI Act (Art. 12/14), surfaced on finding
  cards and in a report coverage matrix; the ledger and certification queue map
  separately as process controls. Auditor context, not a certification.
- **Deterministic composite risk score** (0–100, recomputable by hand): base
  severity + blast radius over high-impact effective capabilities + data
  sensitivity + exploitability (direct vs. delegated, untrusted-content boost).
  Findings, reports, and the certification review queue rank by it; the factor
  breakdown ships in the API and report payloads.
- **"Lethal trifecta" named check** (after Simon Willison's pattern): a
  deterministic, citation-verified finding when one agent's *effective* access
  spans private-data reads, untrusted-content exposure, and an exfiltration
  channel. Zero-noise on the shipped fleet (proven in tests, including a
  delegation-completed trifecta); mapped to AC-6/AC-5 and OWASP LLM01.
- **Executive summary for CISOs**: the audit report (JSON/Markdown/HTML) opens
  with a board-ready rollup — fleet scope, top risks ranked by the reproducible
  composite score, control-framework coverage counts, and certification review
  status — derived entirely from the same verified findings as the rest of the
  report. Docs position Steward as non-human identity (NHI) governance with
  zero-risk deployment (config-time, read-only, nothing leaves the machine) and
  an auditor-usable evidence trail.

### Planned
- Live connectors for agent registries, MCP gateways, and cloud IAM.
- Continuous access-certification campaigns and remediation workflows.
- Streaming trace ingestion with windowed drift alerts.

## [0.1.0] — 2026-07-21

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
- **Golden-set evaluation** — a labeled 30-agent synthetic fleet (20 clean
  controls, ~20 departments, including a two-hop delegation escalation chain)
  with a precision/recall + citation-validity gate wired into CI.
- **Labeled LLM-tier accuracy benchmark** (`evals/benchmark/`, `make llm-benchmark`):
  20 ground-truth scenarios — 8 in-scope toxic sensitive-read + external-egress pairs,
  8 benign near-misses, 4 out-of-scope toxic pairs — measuring the model tier's
  precision/recall and hallucinated-citation rate separately from the deterministic
  gate. Cached live `gpt-oss-120b` result: 8/8 recall, 0/8 false positives, 0
  hallucinated citations; CI re-verifies the cache offline.
- **Secret-redaction boundary** — `env` values and secret-shaped strings are
  stripped before any model call, log, cache, or ledger write
  (`steward/redaction.py`).
- **MCP config adapter** for Claude Desktop / Cursor `mcp.json` with a
  **known-server capability registry**: eleven widely used MCP servers
  (filesystem, GitHub, Slack, PostgreSQL, SQLite, fetch, Brave Search, Google
  Drive, memory, Puppeteer, Sentry), recognized by exact package identifier in
  `command`/`args`, import as their documented capability sets with provenance
  disclaimers embedded in every mapped node; unrecognized servers import as
  conservative server-level bundles. Realistic credential-free sample at
  `examples/claude_desktop_config.json`.
- **Runtime-trace ingestion — the "Used" pillar** (`steward analyze --traces`,
  `steward/traces.py`): a minimal JSONL event format (timestamp/agent_id/tool_id/status,
  mappable from OpenTelemetry GenAI spans) fills observed usage for traced agents,
  drives the over-privilege check with runtime data, and reconciles Granted vs. Used
  vs. Needed: *granted-but-never-used*, *used-but-not-granted* (drift — deliberately a
  reconciliation signal, not a finding, because citation verification rejects evidence
  outside effective access), and model-assisted *used-but-not-needed*. Payload fields
  are dropped at parse time; sample trace at `examples/traces.jsonl`.
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
- **Zero-key demo mode** (`STEWARD_DEMO=1`) serving a committed analysis cache so
  the full dashboard and detect→close→prove flow run with no cloud account.
- **Documentation** — architecture deep-dive with native Mermaid diagrams and an
  OWASP LLM Top 10 (2025) mapping (`docs/ARCHITECTURE.md`), a measured cost
  analysis with 100/1K/10K/100K scaling projections (`docs/COST.md`), an audience
  and automation-rationale guide (`docs/USERS.md`), contributing guide, security
  policy, and CI that runs lint + tests + eval on every push.

### Fixed
- **Needed-capability inference runs in bounded agent batches** (six agents per
  request, mirroring tool-classification recovery). A whole-fleet request
  outgrew the structured-output token budget at 30 agents, so Needed inference
  silently failed and the Granted vs. Needed view was empty; the committed demo
  cache now records Needed inference for all 30 agents, and a batch failure
  degrades to a partial result instead of erasing the signal.
- The high-entropy secret heuristic no longer masks long snake/kebab-case word
  identifiers (e.g. `read_financial_statements`) in outbound LLM payloads. Two
  synthetic-fleet tools were previously unclassifiable because their ids arrived
  at the model as `[REDACTED]`; the committed demo cache now records complete
  (34/34) tool classification. Credential-shaped strings are still masked.

[Unreleased]: https://github.com/vrajjshah/steward/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/vrajjshah/steward/releases/tag/v0.1.0
