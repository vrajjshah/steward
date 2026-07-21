# Contributing to Steward

Thanks for your interest. Steward is a small, focused project with a strong
point of view about trust, so contributions are held to one central principle:

> **No finding reaches a user without cited, verifiable evidence.** The
> deterministic floor must stay deterministic, and anything model-assisted must
> pass the same citation gate.

## Development setup

Requires Python 3.12+.

```bash
git clone https://github.com/vrajjshah/steward.git
cd steward
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## The checks you must pass

CI runs on every push and pull request. Run the same gates locally before
opening a PR:

```bash
make lint    # ruff
make test    # pytest — focused safety, adapter, ledger, and enforcement tests
make eval    # golden-set precision/recall + citation-validity gate
```

- **`make eval` is a hard gate.** The deterministic tier must retain
  precision = recall = **1.000** on the labeled synthetic fleet with zero false
  positives on the clean control agents. A regression, an invalid citation, or a
  new false positive fails the build.
- **The model tier is measured separately** and is not required-perfect — but it
  must never bypass citation verification.

## Guidelines

- **Every finding cites real graph entities.** If you add a check, add its
  evidence construction and make sure `verify_finding_evidence` accepts it.
- **Never send payloads or secrets to a model.** Only configuration metadata
  crosses the boundary, and it goes through `steward/redaction.py` first. Add a
  redaction assertion for any new egress path.
- **Keep the deterministic floor free of model calls.** It must run with
  `STEWARD_DEMO=1` and no credentials.
- **Add a test that documents the failure mode it guards against.** Prefer
  boundary/adversarial cases over happy paths.
- **Match the surrounding style.** Types are Pydantic with `extra="forbid"`;
  keep public contracts typed.

## Pull requests

1. Branch from `main`.
2. Keep the change focused; explain the *why* in the description.
3. Ensure `make lint && make test && make eval` all pass.
4. Update `CHANGELOG.md` under `[Unreleased]` and, if you change behavior, the
   README and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Reporting security issues

Please do **not** open a public issue for vulnerabilities. See
[`SECURITY.md`](SECURITY.md).
