"""Run the bundled SupportBot exfiltration attack against a generated policy.

Usage:
    python examples/redteam/exfil/attack.py policy.yaml

For the signed-ledger version of the demonstration, use the Steward CLI
command wired by the application layer.  This standalone script intentionally
uses no credentials and no network connection.
"""

from __future__ import annotations

import sys
from pathlib import Path

from steward.policy_gen import load_policy
from steward.redteam import run_exfiltration_scenario


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python examples/redteam/exfil/attack.py policy.yaml")
        return 2
    policy_path = Path(sys.argv[1])
    result = run_exfiltration_scenario(load_policy(policy_path))
    print("UNGUARDED:", "SUCCEEDED" if result.unguarded_succeeded else "FAILED")
    print("GUARDED:", "BLOCKED" if result.guarded_blocked else "NOT BLOCKED")
    return 0 if result.unguarded_succeeded and result.guarded_blocked else 1


if __name__ == "__main__":
    raise SystemExit(main())
