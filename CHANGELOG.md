# Changelog

All notable changes to Steward are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Peer-group outlier analytics**: a deterministic heuristic that flags agents
  whose *effective* access is unlike any peer's (pairwise Jaccard similarity;
  an agent isolated from every peer while holding enough access is flagged),
  the unsupervised complement to the rule-based checks for spotting likely
  over-grants. It is deliberately **not** a `Finding` — an unusual access
  profile can't satisfy the graph-citation contract — so it surfaces as a
  clearly labeled analytics section in the audit report (computed straight from
  the effective-access map, so the CLI report and dashboard both show it), and
  the closed four-member `check_type` set is preserved. Thresholds live in one
  documented place; the small-fleet honesty caveat travels with the output.
- **Recurring certification campaigns (`steward campaign`)**: a scoped
  recertification workflow — `start` (scope by explicit agents, a severity or
  risk-score floor, or all, with an optional due date), `status`, `decide`
  (approve/revoke/flag with a note), and `close` (requires all decisions, or
  `--force --reason`). Every lifecycle event appends a signed `certification`
  entry to the Ed25519 audit ledger through the existing redacted commitment
  path, so the who/what/when record is tamper-evident and offline-verifiable;
  mutable state persists in `.steward/campaigns.json` and survives restarts. The
  audit report gains a certification-campaigns rollup (open/complete/overdue
  counts and per-campaign progress) in its executive summary. Honest scope: a
  single-reviewer local workflow with a tamper-evident trail, not multi-approver
  enterprise routing.
- **SoD policy-as-code — custom rule packs (`--rules`)**: a YAML pack extends
  the built-in deterministic floor with an organization's own toxic
  combinations, delegated-high-risk capabilities, and capability-class
  vocabulary (high-impact / sensitive-read / untrusted-content / exfiltration
  ids that feed the risk score and the lethal-trifecta check). Pack rules are
  additive — the built-in floor is unchanged, pack findings are ordinary
  deterministic findings carrying the pack's `rule_id` with automatic
  control-framework annotation, and a rule naming tools absent from the loaded
  catalog simply never fires (reported as an inert-rule note). `--rules` is
  repeatable and works on `analyze`, `diff`, `simulate`, `remediate`, and
  `policy generate`; malformed packs and built-in rule-id collisions fail
  loudly. The eval golden set never loads packs, so the 1.000 gate is untouched
  (a regression test asserts pack-free analysis is byte-identical). Ships
  `examples/rules/finance_sod_pack.yaml`, a realistic finance/ERP conflict
  matrix.
- **Remediation simulation and planning (`steward simulate`, `steward
  remediate`)**: `simulate` applies hypothetical revocations (direct grants
  and/or delegation edges) to an in-memory fleet copy, re-runs the deterministic
  analysis, and reports the result as a `steward diff` of current → simulated —
  recomputed facts, not estimates. `remediate` proposes a greedy minimal
  revocation set drawn from the levers cited in current findings, each step
  clearing the most remaining findings, with ties broken toward larger risk
  reduction and then toward unused (zero-business-impact) grants using observed
  usage data. On the demo fleet, 5 revocations clear 7 of 9 deterministic
  findings and drop fleet risk exposure from 451 to 88 (−80%). Nothing is ever
  written to disk; the plan is a labeled proposal for human review (optimizes
  finding count, not business feasibility; greedy is not provably minimal).
- **Access change review (`steward diff`)**: compares two fleet snapshots
  deterministically — agents added/removed, owner changes, direct-grant and
  delegation deltas, effective-access expansions (flagging newly reachable
  high-impact capabilities), findings introduced/resolved/persisting, and the
  change in aggregate risk exposure. `--fail-on-new <severity>` is the
  change-review CI gate: it fails a build only for findings the change
  *introduces* at or above the threshold, so pre-existing debt never blocks an
  unrelated merge. Optional `--json` / `--markdown` exports for the audit trail.
  A config-time snapshot diff (not an event log); a renamed agent id reads as a
  removal plus an addition.
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
