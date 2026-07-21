# Steward — Cost analysis at scale

What one fleet analysis actually costs, what the whole development history cost,
and what has to change architecturally at 100 / 1K / 10K / 100K analyses.
Numbers below are **measured from Steward's own cost/latency log**
(`data/cost_latency.jsonl`, which records operation, model id, timing, and
character counts — never prompts or config values), not estimated from
first principles.

Price basis: Amazon Bedrock on-demand, July 2026 — `gpt-oss-120b` at
**$0.15 / 1M input tokens and $0.60 / 1M output tokens**, `gpt-oss-20b` at
$0.07 / $0.30 ([Bedrock pricing](https://aws.amazon.com/bedrock/pricing/)).
Tokens are approximated as `chars / 4` plus ~220 tokens per call for the system
instruction and prompt wrapper; treat every figure as ±30%, which is precise
enough for every decision this document makes.

## 1. What one analysis actually calls

The deterministic tier — graph build, all four checks, citation verification,
policy generation, the ledger — makes **zero model calls and costs $0**. That
is the zero-key mode, and it is the floor the rest of this document stands on.

With enrichment enabled, one analysis of the 30-agent / 34-tool synthetic
fleet makes ~49 requests (measured from the latest complete live run):

| Operation | Calls | Scales with | Input chars | Output chars | Serial time |
|---|---|---|---|---|---|
| Tool classification (≤6 tools/request) | 6 | catalog size | 3,946 | 4,008 | 15 s |
| Needed-access inference (≤6 agents/request) | 5 (+2 retries) | fleet size | 31,374 | 13,845 | 57 s |
| Toxic-combination reasoning (1/agent with ≥2 effective tools) | 26 | eligible agents | 18,737 | 1,020 | 61 s |
| Finding narratives (1/finding) | 10 | finding count | 7,887 | 7,747 | 43 s |
| **Total** | **≈49** | | **61,944** | **26,620** | **≈3 min serial** |

That is roughly **26K input + 6.7K output tokens ⇒ ~$0.008 per enriched
analysis** — under one cent. For context, the *entire* recorded development
history of this project (611 logged calls: every live run, the accuracy
benchmark, every demo-cache regeneration, and 49 errored/retried requests)
totals ~318K input + 57K output tokens ⇒ **about $0.08 of model spend,
total**.

Two structural facts matter more than the totals:

- **Spend is not uniform.** Toxic-combination reasoning scales with agent
  count, classification with catalog size, narratives with finding count, and
  Needed inference with fleet size. They respond to different optimizations.
- **Errors cost input without output.** ~8% of all logged requests errored and
  were retried (chiefly structured-output truncation before needed-access
  inference was batched). Retry overhead is real spend and real latency, and
  it is invisible in a naive `cost-per-token × N` model.

## 2. Projections — and the architectural change each tier forces

Costs below are per-run × N for the measured 30-agent fleet. A 10× larger
fleet is roughly 10× the toxic/Needed calls per run; the *shape* of each
tier's conclusion does not change.

| Analyses | Naive cost | Binding constraint | What actually changes |
|---|---|---|---|
| **100** (a pilot; weekly scans of a handful of fleets) | ~$0.80 | nothing | Nothing. Run it serial and on demand. Engineering time spent optimizing at this tier is waste. |
| **1K** (daily scans across teams; CI on config changes) | ~$8 | latency, not cost | **Cache what is deterministic-in, deterministic-out.** A tool's capability classification depends only on its id/name/description — memoize by content hash and re-classify only changed tools (catalogs barely churn between runs). Narratives depend only on the finding's evidence — cache by finding id + evidence hash. A re-analysis after one grant change should re-request only the affected agent, which the per-agent toxic-call design already permits. Steady-state cost falls an order of magnitude below naive. |
| **10K** (org-wide continuous posture; every config PR analyzed) | ~$80 | throughput + quota | **Go event-driven and delta-only.** Full-fleet enrichment becomes the *cold-start* path; the hot path re-analyzes only agents whose effective-access set changed (key the toxic-reasoning memo on a hash of the agent's effective tool-id set). Parallelize the per-agent calls — 3 min serial is a design choice, not a floor. Move classification and narratives to `gpt-oss-20b` (½–¼ the price; those tasks don't need the larger model), reserving the big model for toxic reasoning. Bedrock's batch/provisioned options apply here if on-demand quotas pinch. |
| **100K** (SaaS multi-tenant; every fleet, every day) | ~$800 | ops, not the invoice | **Invert the default: deterministic-only scans, model tier on triggers.** The $0 deterministic floor runs on every scan; the model tier runs on *change events* (new tool, new grant, new delegation edge) and on a periodic cadence, not per scan. At this tier the real costs are quota management, retry storms, tenant isolation, and observability — $800/month of tokens is small next to the engineering that keeps 100K runs trustworthy. The two-tier design is what makes this inversion possible at all: accuracy-critical findings never depended on the model tier, so throttling it degrades enrichment, not safety. |

## 3. Why this is not `cost-per-token × N`

1. **The floor is free.** Every scan gets the deterministic tier at $0. The
   question is never "can we afford to scan?" — it is "which scans deserve
   enrichment?"
2. **Caching asymmetry.** Classification and narratives are pure functions of
   stable inputs and cache indefinitely; toxic reasoning is a function of an
   agent's effective-access set and caches until the graph changes under that
   agent. Only genuinely novel access patterns cost tokens in steady state.
3. **Retries and truncation are a real tax.** The needed-access operation
   failed silently for weeks because a whole-fleet request outgrew the
   response budget; every one of those failures billed input tokens for zero
   output. Bounded batches (≤6 tools, ≤6 agents) exist precisely to keep one
   truncated response from erasing — and re-billing — a whole operation.
4. **Latency binds before cost.** At $0.008/run, a million runs is $8K/year —
   but 49 serial calls × 100K runs is ~5,000 machine-hours. Concurrency,
   deltas, and caching are throughput decisions that happen to also cut cost.
5. **Model-tier right-sizing is a lever, not a rewrite.** The `MODEL_*` env
   contract means dropping narratives/classification to `gpt-oss-20b` (or any
   cheaper Converse model) is configuration, not code.

## 4. Honest limits

- Measurements come from one fleet size (30 agents / 34 tools) on one model;
  the per-operation scaling columns, not the absolute totals, are the durable
  content.
- `chars/4 + 220/call` is an approximation; Bedrock bills actual tokenizer
  counts.
- Prices are on-demand list prices as of July 2026 and will drift.
- The projection table assumes analyses of comparable fleets; a 1,000-agent
  fleet changes per-run cost (~linearly in agents) before the per-tier
  architecture advice applies.
