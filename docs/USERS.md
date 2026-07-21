# Who Steward is for

Steward is an open-source identity-and-access governance analyzer for AI agent
fleets. This page says plainly who gets value from it, what job it does for
each of them, and why this is an automation problem rather than a
review-meeting problem.

## The people it serves

**Security and identity engineers rolling out AI agents.** You are wiring
agents to MCP servers, internal tools, and each other, and you need to answer
"what can this thing actually reach?" *before* it ships. Steward turns a
config file — a native fleet export or a `claude_desktop_config.json` — into an
effective-access graph and a findings list in minutes, locally, with no cloud
account. The zero-key deterministic tier means the answer does not depend on
anyone's API key.

**IAM / IGA practitioners and auditors.** Segregation of duties, least
privilege, access certification, ownership accountability — the controls are
familiar; the population is new. Agents hold tool grants instead of app
entitlements and delegate to each other instead of sharing group membership.
Steward maps the classical control language onto that population (every
finding carries a control mapping and an evidence trail), produces per-agent
certification risk cards with an approve/revoke/flag workflow, and signs
review events into a tamper-evident ledger — the artifacts an audit
conversation actually needs.

**Platform and AI-engineering leads.** A fleet inventory drifts the moment
someone edits a config. Steward's analysis is deterministic and fast, so it
runs in CI: a pull request that grants an agent a toxic capability pair, or
quietly wires a delegation path to a payment-approving agent, fails the build
with the exact entities cited. The trace-ingestion path (`--traces`) adds the
runtime view: which grants are actually used, and which invocations happened
outside the inventory entirely.

**People learning or evaluating agent-governance design.** Steward is a
compact, tested reference implementation of a specific trust architecture:
deterministic floor + model generalization, with every finding — from either
tier — forced through graph-citation verification before it can surface. The
eval gate, the labeled model-tier benchmark, and the signed ledger are all
runnable in one clone.

## Who it is *not* for (today)

Steward is configuration-time analysis plus a narrow enforcement demo. It is
not a production authorization system, not an authentication gateway, and not
a compliance certification. If you need SCIM feeds, HR-driven joiner/mover/
leaver lifecycle, hundreds of app connectors, or campaign management at
enterprise scale, that is platform IGA territory (SailPoint, Saviynt, Okta) —
see the honest comparison in the [README](../README.md#how-steward-compares).

## Why automation, not a review meeting

- **Effective access is a graph property.** What an agent can reach includes
  everything reachable through delegation — a transitive closure. Humans
  reviewing config files reliably catch direct grants and reliably miss
  two-hop paths (the demo fleet's `ExecBriefingBot → ChiefOfStaffBot →
  FinanceBot` chain exists precisely because it is easy to miss).
- **Toxic combinations are combinatorial.** Thirty agents and thirty-four
  tools produce far more capability pairs than a spreadsheet review covers;
  each new tool multiplies the surface. Deterministic rules plus a
  citation-gated model tier scan all of it on every run.
- **Reviews decay; re-runs don't.** A quarterly access review is stale the
  week after it finishes. An analysis that costs seconds and $0 (deterministic
  tier) re-runs on every config change.
- **Evidence beats assertion.** A human review produces opinions in a
  document. Steward produces findings whose cited agents, tools, and
  delegation edges are machine-verified against the loaded graph — and a
  signed, offline-verifiable record that the review happened.

## Five-minute starting points

| You are | Start with |
|---|---|
| Evaluating quickly | `STEWARD_DEMO=1 make demo` → dashboard on `:8000`, no keys |
| Reviewing your own MCP setup | `steward analyze --mcp path/to/claude_desktop_config.json --no-llm` |
| Wiring a CI gate | `make eval` (deterministic gate) on your fleet export |
| Bringing runtime data | `steward analyze --traces your-traces.jsonl --no-llm` |
| Reading the design | [`docs/ARCHITECTURE.md`](ARCHITECTURE.md), then [`docs/COST.md`](COST.md) |
