"""A deliberately minimal, policy-enforcing MCP ``tools/call`` pass-through.

The gate is a demonstration of Steward's detect → close → prove loop.  It is
not an identity provider, authentication gateway, or general MCP proxy: its
caller is trusted, it accepts one policy document, and it forwards allowed
calls to one supplied upstream handler.  Every allow/deny decision can be
sent to a ledger through an injected callable without coupling this module to
the ledger implementation.
"""

from __future__ import annotations

import hashlib
import inspect
import json
from collections.abc import Awaitable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from steward.policy_gen import PolicyDecision, StewardPolicy, evaluate_policy
from steward.redaction import redact_for_llm, redact_text

JSONRPC_INVALID_REQUEST = -32600
JSONRPC_POLICY_DENIED = -32001
JSONRPC_UPSTREAM_ERROR = -32603


class MCPUpstream(Protocol):
    """One bundled/upstream MCP handler accepted by the pass-through gate."""

    def __call__(self, request: Mapping[str, Any]) -> Mapping[str, Any] | Awaitable[Mapping[str, Any]]:
        """Forward an already-validated JSON-RPC ``tools/call`` request."""


class EnforcementLedgerAppender(Protocol):
    """Dependency seam for a signed audit ledger.

    The concrete ledger supplies this as a small adapter, typically
    ``lambda event, payload, version: ledger.append(...)``.  Keeping the seam
    callable prevents the enforcement gate from taking a hard dependency on
    filesystem/key management details.
    """

    def __call__(
        self,
        event_type: str,
        payload: Mapping[str, Any],
        *,
        policy_version: str | None,
    ) -> Any:
        """Append one safe-to-persist enforcement event."""


@dataclass(frozen=True)
class ParsedToolCall:
    """The minimal safe subset of an MCP JSON-RPC tool invocation."""

    request_id: str | int | float | None
    tool_id: str
    arguments: Any


def _jsonrpc_error(
    request_id: str | int | float | None,
    code: int,
    message: str,
    *,
    data: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data:
        error["data"] = dict(data)
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def _request_id(raw_request: object) -> str | int | float | None:
    if not isinstance(raw_request, Mapping):
        return None
    candidate = raw_request.get("id")
    # JSON-RPC permits strings/numbers/null identifiers. Avoid reflecting an
    # object or array that could accidentally contain a payload value.
    return candidate if isinstance(candidate, (str, int, float)) or candidate is None else None


def parse_tool_call(raw_request: object) -> ParsedToolCall:
    """Validate exactly the JSON-RPC shape the scoped pass-through supports."""

    if not isinstance(raw_request, Mapping):
        raise ValueError("request must be a JSON object")
    if raw_request.get("jsonrpc") != "2.0":
        raise ValueError("request must use JSON-RPC 2.0")
    if raw_request.get("method") != "tools/call":
        raise ValueError("only MCP tools/call is supported")
    params = raw_request.get("params")
    if not isinstance(params, Mapping):
        raise ValueError("tools/call params must be an object")
    tool_id = params.get("name")
    if not isinstance(tool_id, str) or not tool_id.strip():
        raise ValueError("tools/call params.name must be a non-empty tool id")
    return ParsedToolCall(
        request_id=_request_id(raw_request),
        tool_id=tool_id.strip(),
        arguments=params.get("arguments", {}),
    )


def _canonical_argument_hash(arguments: Any) -> str:
    """Return a digest without persisting the potentially sensitive argument."""

    try:
        canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        canonical = json.dumps({"unserializable_argument_type": type(arguments).__name__})
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _argument_metadata(arguments: Any) -> dict[str, Any]:
    """Keep shape-only, redacted metadata out of the audit payload values."""

    if isinstance(arguments, Mapping):
        return {
            "type": "object",
            "keys": sorted(redact_text(str(key)) for key in arguments)[:50],
        }
    if isinstance(arguments, list):
        return {"type": "array", "length": len(arguments)}
    if arguments is None:
        return {"type": "null"}
    return {"type": type(arguments).__name__}


def enforcement_event_payload(
    decision: PolicyDecision,
    arguments: Any,
    *,
    request_valid: bool,
) -> dict[str, Any]:
    """Build the secret/PII-minimizing payload supplied to a ledger hook.

    Argument values are never persisted.  Their SHA-256 digest makes repeated
    decisions auditable, while only argument *shape* is retained as redacted
    metadata.  ``redact_for_llm`` is used defensively for IDs/reasons too, so
    a malformed caller cannot turn the ledger into a credential sink.
    """

    payload = {
        "agent_id": redact_text(decision.agent_id),
        "tool_id": redact_text(decision.tool_id),
        "decision": "allow" if decision.allowed else "deny",
        "reason": redact_text(decision.reason),
        "request_valid": request_valid,
        "arguments_sha256": _canonical_argument_hash(arguments),
        "arguments_metadata": _argument_metadata(arguments),
    }
    safe_payload = redact_for_llm(payload)
    assert isinstance(safe_payload, dict)  # Narrowing for type checkers; the input is a dict.
    # A SHA-256 digest is intentionally high-entropy-looking, so the generic
    # secret scrubber correctly masks it by default. Restore only this digest:
    # it is locally computed from the arguments, has a fixed hex format, and
    # is the explicit non-reversible audit correlation value this event needs.
    safe_payload["arguments_sha256"] = payload["arguments_sha256"]
    return safe_payload


class MCPToolCallGate:
    """Default-deny JSON-RPC tool-call evaluator with one upstream handler."""

    def __init__(
        self,
        policy: StewardPolicy,
        upstream: MCPUpstream,
        *,
        ledger_append: EnforcementLedgerAppender | None = None,
    ) -> None:
        self.policy = policy
        self.upstream = upstream
        self.ledger_append = ledger_append

    def _record(
        self,
        decision: PolicyDecision,
        arguments: Any,
        *,
        request_valid: bool,
    ) -> None:
        if self.ledger_append is None:
            return
        self.ledger_append(
            "enforcement",
            enforcement_event_payload(
                decision,
                arguments,
                request_valid=request_valid,
            ),
            policy_version=decision.policy_version,
        )

    def _authorize(
        self, agent_id: str, raw_request: object
    ) -> tuple[ParsedToolCall | None, PolicyDecision, dict[str, Any] | None]:
        request_id = _request_id(raw_request)
        try:
            parsed = parse_tool_call(raw_request)
        except ValueError as exc:
            decision = PolicyDecision(
                agent_id=agent_id,
                tool_id="<invalid_tools_call>",
                allowed=False,
                reason=str(exc),
                policy_version=self.policy.policy_version,
            )
            self._record(decision, {}, request_valid=False)
            return (
                None,
                decision,
                _jsonrpc_error(
                    request_id,
                    JSONRPC_INVALID_REQUEST,
                    "Invalid MCP tools/call request.",
                ),
            )

        decision = evaluate_policy(self.policy, agent_id, parsed.tool_id)
        self._record(decision, parsed.arguments, request_valid=True)
        if not decision.allowed:
            return (
                parsed,
                decision,
                _jsonrpc_error(
                    parsed.request_id,
                    JSONRPC_POLICY_DENIED,
                    "Denied by Steward least-privilege policy.",
                    data={"agent_id": redact_text(agent_id), "tool_id": redact_text(parsed.tool_id)},
                ),
            )
        return parsed, decision, None

    def handle(self, agent_id: str, raw_request: object) -> dict[str, Any]:
        """Evaluate and synchronously forward one tool call.

        The bundled red-team upstream is synchronous.  Use
        :meth:`handle_async` when installing an asynchronous upstream in the
        FastAPI application.
        """

        _, _, denied_response = self._authorize(agent_id, raw_request)
        if denied_response is not None:
            return denied_response
        response = self.upstream(raw_request)  # type: ignore[arg-type]
        if inspect.isawaitable(response):
            raise TypeError("asynchronous upstream requires handle_async")
        if not isinstance(response, Mapping):
            raise TypeError("upstream must return a JSON-RPC object")
        return dict(response)

    async def handle_async(self, agent_id: str, raw_request: object) -> dict[str, Any]:
        """Evaluate and forward one tool call, awaiting an async upstream if needed."""

        _, _, denied_response = self._authorize(agent_id, raw_request)
        if denied_response is not None:
            return denied_response
        response = self.upstream(raw_request)  # type: ignore[arg-type]
        if inspect.isawaitable(response):
            response = await response
        if not isinstance(response, Mapping):
            raise TypeError("upstream must return a JSON-RPC object")
        return dict(response)


def create_enforcement_app(
    policy: StewardPolicy,
    upstream: MCPUpstream,
    *,
    ledger_append: EnforcementLedgerAppender | None = None,
) -> FastAPI:
    """Create the scoped ``POST /mcp/{agent_id}`` policy-enforcement app."""

    app = FastAPI(title="Steward MCP policy gate", version="0.1")
    gate = MCPToolCallGate(policy, upstream, ledger_append=ledger_append)
    app.state.steward_gate = gate

    @app.post("/mcp/{agent_id}")
    async def forward_tool_call(agent_id: str, request: Request) -> JSONResponse:
        try:
            raw_request = await request.json()
        except Exception:
            raw_request = None
        response = await gate.handle_async(agent_id, raw_request)
        return JSONResponse(content=response)

    return app
