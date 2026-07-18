"""Tamper-evident, local audit ledger for Steward decisions.

The ledger is intentionally small and file-backed.  It is not a distributed
transparency log: callers who need to prove a particular historical head can
publish the exported JSONL and its public key.  Within one ledger, each entry
is an Ed25519-signed canonical JSON document chained to the canonical body of
the prior entry.

Only redacted configuration metadata is stored.  Tool-call arguments and
common PII-bearing fields are represented by a SHA-256 commitment rather than
their original values, so the ledger can prove a decision occurred without
becoming a second store of agent payload data.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from steward.redaction import redact_for_llm

EventType = Literal["finding", "certification", "enforcement"]

DEFAULT_STATE_DIR = Path(".steward")
DEFAULT_LEDGER_FILENAME = "audit.jsonl"
DEFAULT_PRIVATE_KEY_FILENAME = "ledger_ed25519.pem"
# ``.pub`` is deliberately not ignored in .gitignore.  It may be committed or
# handed to an external reviewer; only the private key must remain local.
DEFAULT_PUBLIC_KEY_FILENAME = "ledger_ed25519.pub"

# These fields conventionally hold agent request data or identifiers rather
# than inventory metadata.  Replace their *values* with commitments before
# persistence.  The field name and object shape remain useful audit metadata.
_COMMITMENT_FIELD_NAMES = frozenset(
    {
        "arg",
        "args",
        "argument",
        "arguments",
        "body",
        "bcc",
        "cc",
        "comment",
        "content",
        "email",
        "email_address",
        "input",
        "inputs",
        "message",
        "note",
        "parameters",
        "params",
        "payload",
        "phone",
        "pii",
        "prompt",
        "query",
        "recipient",
        "request",
        "response_body",
        "ssn",
        "to",
        "tool_arguments",
        "tool_input",
    }
)
_SHA256_FIELD_RE = re.compile(r"^[a-z0-9_]+_sha256$")
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_PII_FIELD_MARKERS = (
    "address",
    "email",
    "phone",
    "recipient",
    "social_security",
    "ssn",
)
_SECRET_FIELD_MARKERS = (
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "password",
    "private_key",
    "secret",
    "token",
)


class LedgerError(RuntimeError):
    """Base error raised for invalid ledger state or operations."""


class LedgerKeyError(LedgerError):
    """Raised when a signing or verification key is absent or inconsistent."""


@dataclass(frozen=True)
class LedgerPaths:
    """Locations belonging to one local ledger state directory."""

    state_dir: Path
    ledger_path: Path
    private_key_path: Path
    public_key_path: Path

    @classmethod
    def from_state_dir(cls, state_dir: Path | str = DEFAULT_STATE_DIR) -> LedgerPaths:
        resolved = Path(state_dir)
        return cls(
            state_dir=resolved,
            ledger_path=resolved / DEFAULT_LEDGER_FILENAME,
            private_key_path=resolved / DEFAULT_PRIVATE_KEY_FILENAME,
            public_key_path=resolved / DEFAULT_PUBLIC_KEY_FILENAME,
        )


@dataclass(frozen=True)
class LedgerEntry:
    """One signed record as returned after it has been appended."""

    seq: int
    timestamp_rfc3339: str
    prev_hash: str | None
    event_type: EventType
    payload: dict[str, Any]
    signature: str
    policy_version: str | None = None

    def body(self) -> dict[str, Any]:
        """Return the signed, chained portion of a persisted entry."""

        body: dict[str, Any] = {
            "seq": self.seq,
            "timestamp_rfc3339": self.timestamp_rfc3339,
            "prev_hash": self.prev_hash,
            "event_type": self.event_type,
            "payload": self.payload,
        }
        if self.policy_version is not None:
            body["policy_version"] = self.policy_version
        return body

    def record(self) -> dict[str, Any]:
        """Return the exact JSON object persisted in the JSONL store."""

        body = self.body()
        body["signature"] = self.signature
        return body


@dataclass(frozen=True)
class VerificationResult:
    """Result of an offline full-chain and signature verification pass."""

    valid: bool
    entry_count: int
    head_hash: str | None
    broken_index: int | None = None
    reason: str | None = None

    @property
    def broken_seq(self) -> int | None:
        """Alias used by CLI wording: sequence numbers start at one."""

        return self.broken_index


def canonical_json(value: Any) -> bytes:
    """Serialize JSON in the one representation used for signing and hashing."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(value: bytes) -> str:
    """Return a lower-case SHA-256 hex digest."""

    return hashlib.sha256(value).hexdigest()


def redact_ledger_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Make an audit-safe payload without retaining secrets or request data.

    ``redact_for_llm`` handles credential names, env containers, inline keys,
    and high-entropy token-like values.  This ledger-specific layer then
    replaces tool arguments and common PII-bearing fields with a deterministic
    SHA-256 commitment of the original value.  Hashes are useful for
    correlating a decision with an external request without preserving the
    request itself.
    """

    if not isinstance(payload, Mapping):
        raise TypeError("ledger payload must be a mapping")
    raw = _json_compatible(payload)
    redacted = _json_compatible(redact_for_llm(raw))
    if not isinstance(raw, dict) or not isinstance(redacted, dict):  # Defensive for type checkers.
        raise TypeError("ledger payload must serialize as a JSON object")
    return _commit_sensitive_fields(raw, redacted)


def init_ledger(state_dir: Path | str = DEFAULT_STATE_DIR) -> LedgerPaths:
    """Create a local signing keypair and empty state directory if needed.

    The private key is written with owner-only permissions.  A public key is
    generated beside it with a ``.pub`` suffix so users can publish it with an
    exported ledger.  Existing, matching keys are left untouched.
    """

    paths = LedgerPaths.from_state_dir(state_dir)
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    _best_effort_chmod(paths.state_dir, 0o700)

    private_exists = paths.private_key_path.exists()
    public_exists = paths.public_key_path.exists()
    if private_exists and public_exists:
        private_key = _load_private_key(paths.private_key_path)
        public_key = _load_public_key(paths.public_key_path)
        if _public_key_bytes(private_key.public_key()) != _public_key_bytes(public_key):
            raise LedgerKeyError("existing ledger public key does not match its private key")
        return paths
    if public_exists and not private_exists:
        # A repository may publish an example/public verification key but not
        # its private counterpart.  A fresh clone with no audit history must
        # still be able to initialize its *own* local signer.  Once even one
        # entry exists, replacing the public key would make that history
        # unverifiable, so fail closed instead.
        if paths.ledger_path.exists() and paths.ledger_path.stat().st_size:
            raise LedgerKeyError(
                "public key exists but the local private signing key is missing; "
                "refusing to replace a key for a non-empty ledger"
            )
        private_key = Ed25519PrivateKey.generate()
        _write_private_key(paths.private_key_path, private_key)
        _write_public_key(paths.public_key_path, private_key.public_key())
        return paths
    if private_exists:
        private_key = _load_private_key(paths.private_key_path)
        _write_public_key(paths.public_key_path, private_key.public_key())
        return paths

    private_key = Ed25519PrivateKey.generate()
    _write_private_key(paths.private_key_path, private_key)
    _write_public_key(paths.public_key_path, private_key.public_key())
    return paths


class AuditLedger:
    """Append and verify a signed, chained JSONL ledger.

    ``AuditLedger`` does not silently initialize keys: use :func:`init_ledger`
    (the ``steward init`` command calls it) so a reviewer can distinguish an
    uninitialized state from an empty but valid ledger.
    """

    def __init__(self, state_dir: Path | str = DEFAULT_STATE_DIR) -> None:
        self.paths = LedgerPaths.from_state_dir(state_dir)

    def initialize(self) -> LedgerPaths:
        """Initialize and return this ledger's local paths."""

        return init_ledger(self.paths.state_dir)

    def append(
        self,
        event_type: EventType,
        payload: Mapping[str, Any],
        *,
        policy_version: str | None = None,
        timestamp: datetime | None = None,
    ) -> LedgerEntry:
        """Redact, sign, and append one event after validating the full chain."""

        if event_type not in {"finding", "certification", "enforcement"}:
            raise ValueError(f"unsupported ledger event type: {event_type!r}")
        paths = self._require_signing_paths()
        verification = self.verify()
        if not verification.valid:
            broken = verification.broken_index
            raise LedgerError(f"refusing to append to a tampered ledger at entry {broken}")

        private_key = _load_private_key(paths.private_key_path)
        sequence = verification.entry_count + 1
        body: dict[str, Any] = {
            "seq": sequence,
            "timestamp_rfc3339": _rfc3339(timestamp or datetime.now(UTC)),
            "prev_hash": verification.head_hash,
            "event_type": event_type,
            "payload": redact_ledger_payload(payload),
        }
        if policy_version:
            body["policy_version"] = policy_version
        body_bytes = canonical_json(body)
        signature = base64.b64encode(private_key.sign(body_bytes)).decode("ascii")
        record = {**body, "signature": signature}
        line = canonical_json(record) + b"\n"

        paths.state_dir.mkdir(parents=True, exist_ok=True)
        with paths.ledger_path.open("ab") as store:
            store.write(line)
            store.flush()
            os.fsync(store.fileno())
        return LedgerEntry(
            seq=sequence,
            timestamp_rfc3339=body["timestamp_rfc3339"],
            prev_hash=verification.head_hash,
            event_type=event_type,
            payload=body["payload"],
            signature=signature,
            policy_version=policy_version,
        )

    def append_finding(
        self, payload: Mapping[str, Any], *, policy_version: str | None = None
    ) -> LedgerEntry:
        """Append a finding event using the canonical event type."""

        return self.append("finding", payload, policy_version=policy_version)

    def append_certification(
        self, payload: Mapping[str, Any], *, policy_version: str | None = None
    ) -> LedgerEntry:
        """Append an approve/revoke/flag certification decision."""

        return self.append("certification", payload, policy_version=policy_version)

    def append_enforcement(
        self, payload: Mapping[str, Any], *, policy_version: str | None = None
    ) -> LedgerEntry:
        """Append an allow or deny decision from the enforcement gate."""

        return self.append("enforcement", payload, policy_version=policy_version)

    def verify(self) -> VerificationResult:
        """Verify canonical encoding, chain links, and every Ed25519 signature.

        A result pinpoints the first bad *one-based sequence/line index*.  The
        strict canonical-record check means even a whitespace-only byte change
        is detected rather than being tolerated by a permissive JSON parser.
        """

        if not self.paths.public_key_path.exists():
            raise LedgerKeyError(
                f"missing ledger public key: run `steward init` first ({self.paths.public_key_path})"
            )
        public_key = _load_public_key(self.paths.public_key_path)
        if not self.paths.ledger_path.exists():
            return VerificationResult(valid=True, entry_count=0, head_hash=None)

        previous_hash: str | None = None
        head_hash: str | None = None
        entry_count = 0
        raw_lines = _jsonl_lines(self.paths.ledger_path.read_bytes())
        for line_index, raw_line in enumerate(raw_lines, start=1):
            if not raw_line:
                continue
            try:
                decoded = raw_line.decode("utf-8")
                if not decoded.endswith("\n"):
                    return _invalid(line_index, entry_count, head_hash, "entry is missing its newline")
                record = json.loads(decoded)
            except (UnicodeDecodeError, json.JSONDecodeError):
                return _invalid(line_index, entry_count, head_hash, "entry is not valid UTF-8 JSON")
            if not isinstance(record, dict):
                return _invalid(line_index, entry_count, head_hash, "entry is not a JSON object")
            if canonical_json(record) + b"\n" != raw_line:
                return _invalid(line_index, entry_count, head_hash, "entry is not canonical JSON")

            body, signature = _extract_body_and_signature(record)
            if body is None or signature is None:
                return _invalid(line_index, entry_count, head_hash, "entry has an invalid schema")
            if body["seq"] != line_index:
                return _invalid(line_index, entry_count, head_hash, "sequence number is out of order")
            if body["prev_hash"] != previous_hash:
                return _invalid(line_index, entry_count, head_hash, "previous entry hash does not match")
            try:
                _validate_rfc3339(body["timestamp_rfc3339"])
                signature_bytes = base64.b64decode(signature, validate=True)
                # ``b64decode(validate=True)`` still accepts alternate pad-bit
                # spellings that decode to the same bytes.  Require the one
                # canonical Base64 spelling too, otherwise a one-byte store
                # mutation could evade a byte-for-byte tamper test.
                if base64.b64encode(signature_bytes).decode("ascii") != signature:
                    raise ValueError("signature is not canonical Base64")
                public_key.verify(signature_bytes, canonical_json(body))
            except (InvalidSignature, ValueError, TypeError):
                return _invalid(line_index, entry_count, head_hash, "Ed25519 signature is invalid")

            entry_count += 1
            previous_hash = sha256_hex(canonical_json(body))
            head_hash = previous_hash

        return VerificationResult(valid=True, entry_count=entry_count, head_hash=head_hash)

    def export_jsonl(self) -> str:
        """Return the persisted canonical JSONL exactly as an export artifact."""

        if not self.paths.ledger_path.exists():
            return ""
        return self.paths.ledger_path.read_text(encoding="utf-8")

    def export_public_key(self) -> str:
        """Return the PEM public key for offline verification or publication."""

        if not self.paths.public_key_path.exists():
            raise LedgerKeyError(
                f"missing ledger public key: run `steward init` first ({self.paths.public_key_path})"
            )
        return self.paths.public_key_path.read_text(encoding="ascii")

    def _require_signing_paths(self) -> LedgerPaths:
        if not self.paths.private_key_path.exists() or not self.paths.public_key_path.exists():
            raise LedgerKeyError(
                f"missing ledger signing keypair: run `steward init` first ({self.paths.state_dir})"
            )
        return self.paths


def _invalid(
    broken_index: int, entry_count: int, head_hash: str | None, reason: str
) -> VerificationResult:
    return VerificationResult(
        valid=False,
        entry_count=entry_count,
        head_hash=head_hash,
        broken_index=broken_index,
        reason=reason,
    )


def _jsonl_lines(contents: bytes) -> list[bytes]:
    """Split only canonical LF delimiters, retaining whether each line had one.

    ``bytes.splitlines`` treats several non-LF bytes as delimiters.  That would
    make the reported index depend on the value of a tampered byte, so JSONL
    verification deliberately recognizes only the single byte this writer
    emits.
    """

    if not contents:
        return []
    pieces = contents.split(b"\n")
    if pieces[-1] == b"":
        return [piece + b"\n" for piece in pieces[:-1]]
    return [piece + b"\n" for piece in pieces[:-1]] + [pieces[-1]]


def _extract_body_and_signature(record: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    allowed_keys = {
        "seq",
        "timestamp_rfc3339",
        "prev_hash",
        "event_type",
        "payload",
        "policy_version",
        "signature",
    }
    if set(record) - allowed_keys or "signature" not in record:
        return None, None
    signature = record.get("signature")
    body = {key: value for key, value in record.items() if key != "signature"}
    required = {"seq", "timestamp_rfc3339", "prev_hash", "event_type", "payload"}
    if set(body) - (allowed_keys - {"signature"}) or not required.issubset(body):
        return None, None
    if not isinstance(body["seq"], int) or isinstance(body["seq"], bool) or body["seq"] < 1:
        return None, None
    if not isinstance(body["timestamp_rfc3339"], str):
        return None, None
    if body["prev_hash"] is not None and (
        not isinstance(body["prev_hash"], str) or len(body["prev_hash"]) != 64
    ):
        return None, None
    if body["event_type"] not in {"finding", "certification", "enforcement"}:
        return None, None
    if not isinstance(body["payload"], dict):
        return None, None
    if "policy_version" in body and not isinstance(body["policy_version"], str):
        return None, None
    if not isinstance(signature, str):
        return None, None
    return body, signature


def _json_compatible(value: Any) -> Any:
    """Normalize common Python model values before canonical JSON serialization."""

    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return _json_compatible(model_dump(mode="json"))
    if isinstance(value, Mapping):
        return {str(key): _json_compatible(child) for key, child in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_compatible(child) for child in value]
    if isinstance(value, (bytes, bytearray)):
        return base64.b64encode(bytes(value)).decode("ascii")
    if isinstance(value, datetime):
        return _rfc3339(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _commit_sensitive_fields(raw: Any, redacted: Any, *, key: str | None = None) -> Any:
    # An enforcement gate may already have converted call arguments into a
    # SHA-256 commitment.  It is safe and useful to retain a syntactically
    # valid digest even though generic high-entropy redaction would otherwise
    # mask it.  Do not make this exception for arbitrary token-like strings.
    if key is not None and _is_named_sha256_digest(key, raw):
        return raw
    if key is not None and _is_secret_metadata_field(key):
        # Unlike a tool-call argument commitment, a credential should not be
        # retained even as a low-entropy/guessable hash.
        return "[REDACTED]"
    if key is not None and _requires_commitment(key):
        return _commitment(raw)
    if isinstance(raw, Mapping) and isinstance(redacted, Mapping):
        return {
            str(child_key): _commit_sensitive_fields(
                raw_value,
                redacted.get(str(child_key)),
                key=str(child_key),
            )
            for child_key, raw_value in raw.items()
        }
    if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes, bytearray)):
        if not isinstance(redacted, Sequence) or isinstance(redacted, (str, bytes, bytearray)):
            return _commitment(raw)
        return [
            _commit_sensitive_fields(raw_value, redacted_value, key=key)
            for raw_value, redacted_value in zip(raw, redacted, strict=True)
        ]
    return redacted


def _commitment(value: Any) -> dict[str, Any]:
    normalized = _json_compatible(value)
    metadata: dict[str, Any] = {
        "sha256": sha256_hex(canonical_json(normalized)),
        "redacted": True,
        "value_type": _value_type(normalized),
    }
    if isinstance(normalized, Mapping):
        metadata["keys"] = sorted(str(key) for key in normalized)
    elif isinstance(normalized, Sequence) and not isinstance(normalized, (str, bytes, bytearray)):
        metadata["items"] = len(normalized)
    return metadata


def _normalise_field_name(value: str) -> str:
    return value.strip().lower().replace("-", "_").replace(" ", "_")


def _is_named_sha256_digest(key: str, value: Any) -> bool:
    normalized_key = _normalise_field_name(key)
    return (
        isinstance(value, str)
        and bool(_SHA256_FIELD_RE.fullmatch(normalized_key))
        and bool(_SHA256_HEX_RE.fullmatch(value))
    )


def _requires_commitment(key: str) -> bool:
    normalized_key = _normalise_field_name(key)
    return normalized_key in _COMMITMENT_FIELD_NAMES or any(
        marker in normalized_key for marker in _PII_FIELD_MARKERS
    )


def _is_secret_metadata_field(key: str) -> bool:
    normalized_key = _normalise_field_name(key)
    return any(marker in normalized_key for marker in _SECRET_FIELD_MARKERS)


def _value_type(value: Any) -> str:
    if isinstance(value, Mapping):
        return "object"
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return "array"
    if value is None:
        return "null"
    return type(value).__name__


def _rfc3339(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _validate_rfc3339(value: str) -> None:
    if not value.endswith("Z"):
        raise ValueError("timestamp must use UTC RFC3339 Z suffix")
    datetime.fromisoformat(value.removesuffix("Z") + "+00:00")


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        loaded = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise LedgerKeyError(f"unable to load ledger private key: {path}") from exc
    if not isinstance(loaded, Ed25519PrivateKey):
        raise LedgerKeyError("ledger private key is not Ed25519")
    return loaded


def _load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        loaded = serialization.load_pem_public_key(path.read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise LedgerKeyError(f"unable to load ledger public key: {path}") from exc
    if not isinstance(loaded, Ed25519PublicKey):
        raise LedgerKeyError("ledger public key is not Ed25519")
    return loaded


def _public_key_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _write_private_key(path: Path, key: Ed25519PrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    _best_effort_chmod(path, 0o600)


def _write_public_key(path: Path, key: Ed25519PublicKey) -> None:
    path.write_bytes(
        key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    _best_effort_chmod(path, 0o644)


def _best_effort_chmod(path: Path, mode: int) -> None:
    try:
        path.chmod(mode)
    except OSError:
        # Windows permission semantics differ; the key format and signature
        # verification still provide integrity there.
        pass
