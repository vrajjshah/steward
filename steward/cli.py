"""Typer command-line interface for local Steward analysis."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from steward.adapters import AdapterError, load_mcp_config
from steward.enforce import create_enforcement_app
from steward.ledger import AuditLedger, LedgerError, LedgerKeyError
from steward.loaders import load_inventory
from steward.models import Fleet, ToolCatalog
from steward.pipeline import analyze_fleet
from steward.policy_gen import generate_policy as build_policy
from steward.policy_gen import load_policy, write_policy
from steward.redaction import safe_json_dumps
from steward.redteam import DemoMCPUpstream, run_exfiltration_scenario
from steward.reporting import build_fleet_audit_report, render_markdown_report
from steward.traces import TraceReconciliation, apply_usage, load_traces, reconcile

app = typer.Typer(
    add_completion=False,
    help="Citation-verified effective-access analysis for AI agent fleets.",
    no_args_is_help=True,
)
audit_app = typer.Typer(
    add_completion=False,
    help="Verify or export Steward's signed, append-only local audit ledger.",
)
policy_app = typer.Typer(
    add_completion=False,
    help="Generate a deterministic least-privilege policy from cited findings.",
)
enforce_app = typer.Typer(
    add_completion=False,
    help="Run the scoped MCP tools/call policy-enforcement demonstration gate.",
)
redteam_app = typer.Typer(
    add_completion=False,
    help="Run harmless, bundled red-team scenarios against a generated policy.",
)
app.add_typer(audit_app, name="audit")
app.add_typer(policy_app, name="policy")
app.add_typer(enforce_app, name="enforce")
app.add_typer(redteam_app, name="redteam")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FLEET = PROJECT_ROOT / "data" / "fleet.json"
DEFAULT_TOOLS = PROJECT_ROOT / "data" / "tools.json"
DEFAULT_LEDGER_STATE = Path(".steward")


def _finding_audit_payload(finding: object) -> dict[str, object]:
    """Select graph facts for a finding event without copying payload-like prose.

    The ledger already redacts defensively, but keeping only IDs and finding
    classification here makes the audit record intentionally small.  Evidence
    details and business narratives can contain real configuration wording and
    are available in the report instead of being duplicated into the ledger.
    """

    model_dump = getattr(finding, "model_dump", None)
    dumped = model_dump(mode="json") if callable(model_dump) else {}
    raw = dumped if isinstance(dumped, dict) else {}
    evidence = raw.get("evidence", [])
    cited_entities = [
        {
            "entity_type": item.get("entity_type"),
            "entity_id": item.get("entity_id"),
        }
        for item in evidence
        if isinstance(item, dict)
        and isinstance(item.get("entity_type"), str)
        and isinstance(item.get("entity_id"), str)
    ]
    return {
        "finding_id": raw.get("id"),
        "agent_id": raw.get("agent_id"),
        "check_type": raw.get("check_type"),
        "severity": raw.get("severity"),
        "source": raw.get("source"),
        "rule_id": raw.get("rule_id"),
        "cited_entities": cited_entities,
    }


def _initialized_ledger(state_dir: Path, *, required: bool = False) -> AuditLedger | None:
    """Return a writable ledger only after an explicit ``steward init``.

    Analysis must retain its zero-key, no-setup behavior.  Once a user opts
    into the audit ledger, every CLI-emitted finding and red-team decision is
    signed; an absent keypair never changes the analyzer's result.
    """

    ledger = AuditLedger(state_dir)
    if ledger.paths.private_key_path.exists() and ledger.paths.public_key_path.exists():
        return ledger
    if required:
        raise typer.BadParameter(
            f"Audit ledger is not initialized at {state_dir}. Run `steward init --state-dir {state_dir}` first."
        )
    return None


def _append_findings_to_ledger(ledger: AuditLedger | None, findings: list[object]) -> int:
    """Append compact finding facts without making audit persistence a detector dependency."""

    if ledger is None:
        return 0
    appended = 0
    try:
        for finding in findings:
            ledger.append_finding(_finding_audit_payload(finding), policy_version="steward-analysis/v0.1")
            appended += 1
    except LedgerError as exc:
        # A tampered ledger must be reported rather than silently ignored, but
        # it must not alter the analyzer's verified findings or availability.
        typer.echo(f"Audit ledger was not updated: {exc}", err=True)
    return appended


def _ledger_appender(ledger: AuditLedger):
    """Adapt the ledger's typed append method to the enforcement hook."""

    def append(event_type: str, payload: object, policy_version: str | None) -> object:
        if not isinstance(payload, dict):
            raise TypeError("enforcement ledger payload must be an object")
        return ledger.append(event_type, payload, policy_version=policy_version)  # type: ignore[arg-type]

    return append


def _load_input(
    fleet_path: Path | None,
    tools_path: Path | None,
    mcp_path: Path | None,
) -> tuple[Fleet, ToolCatalog, str]:
    if mcp_path and fleet_path:
        raise typer.BadParameter("Use either --mcp or --fleet, not both.")
    if mcp_path:
        try:
            imported = load_mcp_config(mcp_path)
        except (AdapterError, FileNotFoundError) as exc:
            raise typer.BadParameter(str(exc), param_hint="--mcp") from exc
        return (
            Fleet.model_validate(imported.fleet),
            ToolCatalog.model_validate(imported.tools),
            "mcp",
        )
    try:
        fleet, tools = load_inventory(fleet_path or DEFAULT_FLEET, tools_path or DEFAULT_TOOLS)
    except (FileNotFoundError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    return fleet, tools, "fleet"


def _echo_reconciliation(reconciliation: TraceReconciliation) -> None:
    """Print the Granted vs. Used vs. Needed runtime summary."""

    observed = [agent for agent in reconciliation.agents if agent.observed_in_trace]
    typer.echo(
        f"Runtime trace reconciliation ({reconciliation.source_name}: "
        f"{reconciliation.events_total} events, {reconciliation.events_malformed} malformed, "
        f"{len(observed)}/{len(reconciliation.agents)} agents observed)."
    )
    for agent in reconciliation.agents:
        if agent.used_not_granted:
            typer.echo(
                f"- DRIFT {agent.agent_id}: used tools outside its effective access: "
                f"{', '.join(agent.used_not_granted)}. Either the inventory is stale or the "
                "runtime is not enforcing it."
            )
    for agent_id in reconciliation.unrecognized_agent_ids:
        typer.echo(
            f"- DRIFT trace names an agent absent from the inventory: {agent_id} "
            "(retired identity still running, or a trace from another fleet)."
        )
    for agent_id, tool_ids in sorted(reconciliation.unrecognized_tool_ids.items()):
        typer.echo(
            f"- DRIFT {agent_id}: invoked tool ids absent from the catalog: {', '.join(tool_ids)}."
        )
    for agent in observed:
        if agent.granted_never_used:
            typer.echo(
                f"- unused {agent.agent_id}: granted but never used in this window: "
                f"{', '.join(agent.granted_never_used)}"
            )
        if agent.used_not_needed:
            typer.echo(
                f"- review {agent.agent_id}: used but not needed per declared purpose "
                f"(model-assisted): {', '.join(agent.used_not_needed)}"
            )
    if not reconciliation.drift_detected:
        typer.echo("- no drift: every observed invocation stayed within effective access.")


@app.command()
def analyze(
    fleet: Annotated[Path | None, typer.Option(help="Path to Steward fleet JSON.")] = None,
    tools: Annotated[Path | None, typer.Option(help="Path to tool catalog JSON.")] = None,
    mcp: Annotated[Path | None, typer.Option(help="Claude Desktop / Cursor mcp.json path.")] = None,
    traces: Annotated[
        Path | None,
        typer.Option(
            help="JSONL runtime trace (timestamp/agent_id/tool_id[/status] per line). "
            "Fills the Used pillar and reports Granted vs. Used vs. Needed drift."
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write a redacted JSON result to this path."),
    ] = None,
    report: Annotated[
        Path | None, typer.Option(help="Write a readable Markdown fleet audit report to this path.")
    ] = None,
    no_llm: Annotated[
        bool,
        typer.Option(
            "--no-llm", help="Skip optional Bedrock enrichment; deterministic checks still run."
        ),
    ] = False,
    state_dir: Annotated[
        Path,
        typer.Option(
            help="Optional initialized audit-ledger directory. Findings are signed there when present."
        ),
    ] = DEFAULT_LEDGER_STATE,
) -> None:
    """Analyze a native fleet or MCP config and print a concise summary."""

    loaded_fleet, loaded_tools, source = _load_input(fleet, tools, mcp)
    trace_log = None
    if traces is not None:
        try:
            trace_log = load_traces(traces)
        except (OSError, ValueError) as exc:
            raise typer.BadParameter(str(exc), param_hint="--traces") from exc
        # Observed usage replaces the inventory's usage log for observed
        # agents, so the over-privilege check runs on real runtime data.
        loaded_fleet = apply_usage(loaded_fleet, trace_log, loaded_tools)
    result = analyze_fleet(loaded_fleet, loaded_tools, enable_llm=False if no_llm else None)
    typer.echo(
        f"Analyzed {len(loaded_fleet.agents)} agents / {len(loaded_tools.tools)} tools "
        f"from {source}: {len(result.findings)} cited findings."
    )
    for finding in result.findings:
        typer.echo(
            f"- [{finding.source}] [{finding.severity.upper()}] "
            f"{finding.agent_id}: {finding.title}"
        )
    if trace_log is not None:
        _echo_reconciliation(reconcile(result, trace_log))

    appended = _append_findings_to_ledger(_initialized_ledger(state_dir), result.findings)
    if appended:
        typer.echo(f"Signed {appended} finding event{'s' if appended != 1 else ''} to {state_dir}.")

    report_payload = build_fleet_audit_report(
        result.fleet,
        result.findings,
        tools=result.tools,
        effective_access=result.effective_access,
        needed_capabilities=result.needed_capabilities,
        granted_vs_needed_gaps=result.granted_vs_needed_gaps,
        metadata=result.metadata,
    )
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(safe_json_dumps(result, indent=2) + "\n", encoding="utf-8")
        typer.echo(f"Wrote redacted analysis JSON: {output}")
    if report:
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(render_markdown_report(report_payload), encoding="utf-8")
        typer.echo(f"Wrote Markdown audit report: {report}")


@app.command()
def serve(
    host: Annotated[str, typer.Option(help="Interface to bind.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Port to bind.")] = 8000,
    demo: Annotated[
        bool,
        typer.Option("--demo/--live", help="Serve committed zero-key demo cache or live analysis."),
    ] = True,
) -> None:
    """Run the local FastAPI dashboard."""

    import os

    import uvicorn

    if demo:
        os.environ["STEWARD_DEMO"] = "1"
    else:
        os.environ.pop("STEWARD_DEMO", None)
    uvicorn.run("steward.app:app", host=host, port=port, reload=False)


@app.command("eval")
def run_eval() -> None:
    """Run the synthetic-fleet precision/recall and citation-validity gate."""

    from evals.run import evaluate, print_result

    result = evaluate()
    print_result(result)
    if not result.passed:
        raise typer.Exit(code=1)


@app.command("init")
def initialize(
    state_dir: Annotated[
        Path,
        typer.Option(help="Directory for the local private key, public key, and append-only ledger."),
    ] = DEFAULT_LEDGER_STATE,
) -> None:
    """Create the local Ed25519 keypair used by Steward's audit ledger."""

    ledger = AuditLedger(state_dir)
    try:
        paths = ledger.initialize()
    except LedgerError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(f"Initialized signed audit ledger at {paths.state_dir}.")
    typer.echo(f"Private signing key: {paths.private_key_path} (local and gitignored)")
    typer.echo(f"Public verification key: {paths.public_key_path} (safe to publish with exports)")


@audit_app.command("verify")
def verify_audit(
    state_dir: Annotated[
        Path,
        typer.Option(help="Directory containing the signed audit ledger and public verification key."),
    ] = DEFAULT_LEDGER_STATE,
) -> None:
    """Recompute and verify every local chain link and Ed25519 signature offline."""

    try:
        result = AuditLedger(state_dir).verify()
    except LedgerKeyError as exc:
        typer.echo(f"Audit verification unavailable: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    if result.valid:
        typer.echo(
            f"chain valid, {result.entry_count} entries, head hash {result.head_hash or '(empty ledger)'}"
        )
        return
    typer.echo(
        f"TAMPER DETECTED at entry {result.broken_index}: {result.reason or 'chain verification failed'}",
        err=True,
    )
    raise typer.Exit(code=1)


@audit_app.command("export")
def export_audit(
    format: Annotated[
        str,
        typer.Option("--format", help="Export format; v0.1 intentionally supports canonical JSONL only."),
    ] = "jsonl",
    state_dir: Annotated[
        Path,
        typer.Option(help="Directory containing the signed audit ledger."),
    ] = DEFAULT_LEDGER_STATE,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the JSONL export to this path instead of stdout."),
    ] = None,
) -> None:
    """Export the exact canonical JSONL records for independent offline verification."""

    if format.lower() != "jsonl":
        raise typer.BadParameter("Only --format jsonl is supported in v0.1.", param_hint="--format")
    ledger = AuditLedger(state_dir)
    try:
        exported = ledger.export_jsonl()
    except LedgerError as exc:
        raise typer.BadParameter(str(exc)) from exc
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(exported, encoding="utf-8")
        typer.echo(f"Exported canonical JSONL ledger to {output}.")
        return
    typer.echo(exported, nl=False)


@policy_app.command("generate")
def generate_policy_command(
    fleet: Annotated[Path | None, typer.Option(help="Path to Steward fleet JSON.")] = None,
    tools: Annotated[Path | None, typer.Option(help="Path to tool catalog JSON.")] = None,
    mcp: Annotated[Path | None, typer.Option(help="Claude Desktop / Cursor mcp.json path.")] = None,
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Destination for the deterministic least-privilege policy YAML."),
    ] = Path("policy.yaml"),
) -> None:
    """Generate a default-deny policy from cited, deterministic analysis findings."""

    loaded_fleet, loaded_tools, source = _load_input(fleet, tools, mcp)
    # Policy generation is deliberately zero-key: it uses the analyzer's
    # deterministic floor and never consults optional Bedrock enrichment.
    result = analyze_fleet(loaded_fleet, loaded_tools, enable_llm=False)
    policy = build_policy(result)
    target = write_policy(policy, output)
    typer.echo(
        f"Generated default-deny policy for {len(policy.agents)} agents from {source} at {target}."
    )


@enforce_app.command("serve")
def serve_enforcement_gate(
    policy: Annotated[Path, typer.Option(help="Generated Steward policy YAML to enforce.")],
    state_dir: Annotated[
        Path,
        typer.Option(help="Initialized ledger directory for signed allow/deny decisions."),
    ] = DEFAULT_LEDGER_STATE,
    host: Annotated[str, typer.Option(help="Interface to bind.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Port to bind.")] = 8787,
) -> None:
    """Serve the scoped POST /mcp/{agent_id} JSON-RPC policy gate for the bundled demo upstream."""

    import uvicorn

    ledger = _initialized_ledger(state_dir, required=True)
    assert ledger is not None
    try:
        loaded_policy = load_policy(policy)
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc), param_hint="--policy") from exc
    typer.echo(
        f"Serving Steward's demo MCP policy gate at http://{host}:{port}/mcp/{{agent_id}} "
        "(trusted caller; default-deny policy enforcement only)."
    )
    uvicorn.run(
        create_enforcement_app(
            loaded_policy,
            DemoMCPUpstream(),
            ledger_append=_ledger_appender(ledger),
        ),
        host=host,
        port=port,
        reload=False,
    )


@redteam_app.command("exfil")
def run_redteam_exfiltration(
    policy: Annotated[Path, typer.Option(help="Generated Steward policy YAML to test.")],
    state_dir: Annotated[
        Path,
        typer.Option(help="Initialized ledger directory where the deny decision will be signed."),
    ] = DEFAULT_LEDGER_STATE,
) -> None:
    """Show a synthetic SupportBot exfiltration succeeding unguarded, then being blocked."""

    ledger = _initialized_ledger(state_dir, required=True)
    assert ledger is not None
    try:
        result = run_exfiltration_scenario(
            load_policy(policy), ledger_append=_ledger_appender(ledger)
        )
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc), param_hint="--policy") from exc
    typer.echo(f"UNGUARDED: {'SUCCEEDED' if result.unguarded_succeeded else 'FAILED'}")
    typer.echo(f"GUARDED: {'BLOCKED' if result.guarded_blocked else 'NOT BLOCKED'}")
    typer.echo(f"Upstream calls: {result.upstream_calls} (one unguarded call only is expected)")
    if not result.unguarded_succeeded or not result.guarded_blocked:
        raise typer.Exit(code=1)
    verified = ledger.verify()
    typer.echo(
        f"Ledger proof: chain valid, {verified.entry_count} entries, "
        f"head hash {verified.head_hash or '(empty ledger)'}"
    )


@app.command()
def version() -> None:
    """Print the v0.1 CLI version."""

    typer.echo("Steward 0.1.0")
