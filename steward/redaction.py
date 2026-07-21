"""Secret-safe serialization for LLM payloads, logs, and cached demo output.

Steward analyzes permissions metadata, never agent payload data. Real MCP
configuration files often contain credentials in ``env`` or command arguments,
so callers should always run data through :func:`redact_for_llm` before sending
it to Bedrock and :func:`safe_json_dumps` before persisting diagnostic output.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping, Sequence
from typing import Any

REDACTED = "[REDACTED]"

# Deliberately broad enough for the common key names found in MCP/Agents SDK
# configs, while bounded on word separators so a harmless field like
# ``monkey_name`` is not suppressed merely because it contains "key".
SENSITIVE_FIELD_RE = re.compile(
    r"(?:^|[_\-.])(?:"
    r"token|access[_-]?token|refresh[_-]?token|id[_-]?token|"
    r"api[_-]?key|apikey|key|secret|client[_-]?secret|"
    r"password|passwd|credential|credentials|authorization|auth|"
    r"private[_-]?key|bearer"
    r")(?:$|[_\-.])",
    re.IGNORECASE,
)
ENV_CONTAINER_KEYS = frozenset({"env", "environment", "environment_variables"})

_INLINE_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bsk-[A-Za-z0-9_-]{6,}\b"), REDACTED),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), REDACTED),
    (re.compile(r"\bASIA[0-9A-Z]{16}\b"), REDACTED),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b"), REDACTED),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), REDACTED),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), REDACTED),
    (
        re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{6,}\b", re.IGNORECASE),
        "Bearer " + REDACTED,
    ),
    (
        re.compile(
            r"(?i)\b((?:api[_-]?key|token|secret|password|passwd|authorization)\s*[=:]\s*)"
            r"([^\s,;\[\]\}" + "'\"]+)"
        ),
        r"\1" + REDACTED,
    ),
    (
        re.compile(
            r"(?i)(--(?:api[_-]?key|token|secret|password|passwd|authorization)(?:=|\s+))"
            r"([^\s,;\[\]\}" + "'\"]+)"
        ),
        r"\1" + REDACTED,
    ),
)


def is_sensitive_field_name(key: object) -> bool:
    """Return whether a mapping key conventionally stores a secret value."""

    return isinstance(key, str) and bool(SENSITIVE_FIELD_RE.search(key.strip()))


def looks_like_high_entropy_secret(value: object) -> bool:
    """Conservatively identify standalone token-like strings.

    This catches opaque credentials that do not use a recognizable prefix. It
    intentionally only redacts a *standalone* value, never a natural-language
    sentence that happens to contain varied characters.
    """

    if not isinstance(value, str):
        return False
    candidate = value.strip()
    if len(candidate) < 24 or any(character.isspace() for character in candidate):
        return False
    if "://" in candidate or candidate.startswith(("/", "./", "../")):
        return False
    # A snake/kebab-case identifier made of plain lowercase words is
    # configuration vocabulary (e.g. "read_financial_statements"), not an
    # opaque credential: real tokens mix digits or case. Without this
    # exemption, long tool ids are silently replaced in LLM payloads and the
    # model can never classify or cite them.
    if re.fullmatch(r"[a-z]+(?:[_-][a-z]+)+", candidate):
        return False
    # API credentials usually have multiple character classes. Requiring at
    # least two avoids treating a long ordinary identifier as sensitive.
    classes = sum(
        (
            any(character.islower() for character in candidate),
            any(character.isupper() for character in candidate),
            any(character.isdigit() for character in candidate),
            any(not character.isalnum() for character in candidate),
        )
    )
    if classes < 2:
        return False
    frequencies = {
        character: candidate.count(character) / len(candidate) for character in set(candidate)
    }
    entropy = -sum(probability * math.log2(probability) for probability in frequencies.values())
    return entropy >= 3.4


def redact_text(value: str) -> str:
    """Mask recognizable credentials embedded in arbitrary free text."""

    result = value
    for pattern, replacement in _INLINE_SECRET_PATTERNS:
        result = pattern.sub(replacement, result)
    if result == value and looks_like_high_entropy_secret(value):
        return REDACTED
    return result


def redact_for_llm(value: Any) -> Any:
    """Return a deep-copied, credential-free representation of ``value``.

    Environment-variable *names* and config structure are retained because
    those are helpful for understanding a tool's integration, but every env
    value is replaced. The output is safe to send to a model, write to an
    analysis log, or cache in ``demo_results.json``.
    """

    return _redact(value, force_redact=False)


def redact_config(value: Any) -> Any:
    """Alias with an explicit name for config ingestion code."""

    return redact_for_llm(value)


def safe_json_dumps(value: Any, *, indent: int | None = None) -> str:
    """Serialize only a redacted representation, never raw config input."""

    return json.dumps(redact_for_llm(value), indent=indent, sort_keys=True, default=str)


def contains_secret_like_value(value: Any) -> bool:
    """Best-effort detector useful for tests that guard outbound LLM payloads."""

    if isinstance(value, Mapping):
        for key, child in value.items():
            if is_sensitive_field_name(key) and child not in (None, "", REDACTED):
                return True
            if contains_secret_like_value(child):
                return True
        return False
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return any(contains_secret_like_value(child) for child in value)
    if isinstance(value, str):
        return redact_text(value) != value or looks_like_high_entropy_secret(value)
    return False


def _redact(value: Any, *, force_redact: bool) -> Any:
    # Pydantic models and dataclasses can expose a JSON-friendly dump without
    # making this low-level safety module depend on either package.
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return _redact(model_dump(mode="json"), force_redact=force_redact)

    if isinstance(value, Mapping):
        redacted: dict[Any, Any] = {}
        for key, child in value.items():
            normalized_key = key.strip().lower() if isinstance(key, str) else ""
            child_force_redact = (
                force_redact or normalized_key in ENV_CONTAINER_KEYS or is_sensitive_field_name(key)
            )
            redacted[key] = _redact(child, force_redact=child_force_redact)
        return redacted

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_redact(child, force_redact=force_redact) for child in value]

    if force_redact and value not in (None, ""):
        return REDACTED
    if isinstance(value, bytes):
        return REDACTED if value else value
    if isinstance(value, bytearray):
        return REDACTED if value else value
    if isinstance(value, str):
        return redact_text(value)
    return value
