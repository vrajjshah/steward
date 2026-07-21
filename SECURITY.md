# Security Policy

Steward is a security and governance tool, so it holds itself to the standard it
audits.

## Design guarantees

- **No payloads to a model.** Steward analyzes *configuration metadata* only —
  tool names/descriptions, agent purpose, grants, and delegation edges. Agent
  payloads, customer data, and PII are never sent to a model.
- **Secrets are scrubbed before any egress.** `env` values and secret-shaped
  strings (`sk-…`, `AKIA…`, `Bearer …`, tokens, passwords, high-entropy values)
  are removed before any model call, log line, cache write, or ledger entry.
  This is enforced in `steward/redaction.py` and covered by
  `tests/test_llm_redaction.py`, which plants a fake secret and asserts it never
  leaves the process.
- **Metadata-only logs.** The cost/latency log records operation, model ID,
  timing, status, and character counts — never prompts or configuration values.
- **Local-only signing key.** The audit ledger's Ed25519 private key
  (`.steward/ledger_ed25519.pem`) is generated locally and gitignored. Only the
  public key is ever shareable.
- **No committed credentials.** Model IDs and AWS credentials come from the
  environment; `.env` is gitignored and nothing sensitive is committed.

## Scope & non-goals

v0.1 is configuration-time analysis. The enforcement component is a deliberately
narrow, policy-evaluating demonstration pass-through — it is **not** an
authentication gateway and makes no production authorization claims.

## Reporting a vulnerability

If you find a security issue, please report it privately rather than opening a
public issue:

- Use GitHub's **[Report a vulnerability](https://github.com/vrajjshah/steward/security/advisories/new)**
  (Security → Advisories) to open a private advisory, **or**
- open a minimal public issue that says only "security issue — please make
  contact" with no exploit details.

Please include reproduction steps and affected versions. You can expect an
initial acknowledgement within a few days.
