# SupportBot exfiltration scenario

This intentionally harmless scenario sends a synthetic support-case record to
an external address through the bundled demo MCP upstream. It exists solely to
show Steward's policy loop:

1. A direct call to the demo upstream succeeds.
2. The exact same `tools/call` is denied when passed through Steward's policy gate.
3. When invoked through Steward's ledger-aware CLI flow, that deny is a signed audit event.

After generating a policy with the Steward CLI, the standalone zero-key demo
can be run with:

```bash
python examples/redteam/exfil/attack.py policy.yaml
```

For the complete signed detect → close → prove sequence, use:

```bash
steward init
steward analyze --no-llm
steward policy generate --output policy.yaml
steward redteam exfil --policy policy.yaml
steward audit verify
```

The upstream server is available separately for HTTP inspection:

```bash
python examples/redteam/exfil/server.py
```

It is deliberately not an authentication gateway and does not send real email.
