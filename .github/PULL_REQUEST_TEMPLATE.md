## What & why

<!-- What does this change, and why? Link any related issue. -->

## Trust checklist

- [ ] `make lint` passes
- [ ] `make test` passes
- [ ] `make eval` passes — deterministic tier still **1.000**, no new false positives on the clean control agents
- [ ] Every new finding cites real graph entities and passes `verify_finding_evidence`
- [ ] No payloads or secrets cross the model / log / ledger boundary (covered by a redaction test)
- [ ] `CHANGELOG.md` updated under `[Unreleased]`; docs updated if behavior changed
