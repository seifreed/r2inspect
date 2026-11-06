"""Secret minimization and execution-local logging context."""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

_log_context: ContextVar[dict[str, Any] | None] = ContextVar("r2inspect_log_context", default=None)
_SENSITIVE_KEY = re.compile(
    r"(?i)(?:authorization|cookie|credential|password|passwd|private[_-]?key|"
    r"api[_-]?key|access[_-]?token|refresh[_-]?token|session[_-]?id|secret|token)"
)
_SECRET_TEXT = re.compile(
    r"(?i)\b([a-z0-9_-]*(?:authorization|cookies?|credentials?|password|passwd|pwd|"
    r"private[_-]?key|api[_-]?key|session[_-]?id|secret|token))"
    r"([\"']?\s*[:=]\s*[\"']?)(?:bearer\s+)?([^\"'\s,;&}]+)"
)
_BEARER_TEXT = re.compile(r"(?i)\bbearer\s+[^\s,;&]+")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_text(value: Any) -> str:
    """Return single-line, secret-minimized text safe for log output."""
    try:
        text = str(value)
    except Exception:
        text = "<unprintable>"
    text = _SECRET_TEXT.sub(lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]", text)
    text = _BEARER_TEXT.sub("Bearer [REDACTED]", text)
    text = text.replace("\r", r"\r").replace("\n", r"\n")
    return _CONTROL_CHARS.sub("?", text)


def command_name(command: str) -> str:
    """Return only the non-sensitive verb of an external or radare2 command."""
    parts = command.strip().split(maxsplit=1)
    verb = parts[0].split("@", 1)[0] if parts else "unknown"
    return sanitize_text(verb or "unknown")[:64]


def redact(value: Any, *, key: str | None = None) -> Any:
    """Recursively redact secrets while preserving JSON-friendly structure."""
    if key is not None and _SENSITIVE_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {sanitize_text(k): redact(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [redact(item) for item in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return sanitize_text(value)


def current_log_context() -> dict[str, Any]:
    """Return a copy of the context attached to logs in the current execution flow."""
    return dict(_log_context.get() or {})


@contextmanager
def bind_log_context(**fields: Any) -> Iterator[None]:
    """Bind correlation fields to this thread or async context and restore them on exit."""
    merged = {
        **(_log_context.get() or {}),
        **{key: value for key, value in fields.items() if value},
    }
    token = _log_context.set(merged)
    try:
        yield
    finally:
        _log_context.reset(token)


def parse_traceparent(value: str | None) -> tuple[str | None, str | None]:
    """Extract valid W3C trace/span identifiers without creating synthetic traces."""
    if not value:
        return None, None
    parts = value.strip().split("-")
    if len(parts) != 4 or parts[0].lower() == "ff":
        return None, None
    version, trace_id, span_id, flags = (part.lower() for part in parts)
    if not (
        len(version) == 2
        and len(trace_id) == 32
        and len(span_id) == 16
        and len(flags) == 2
        and all(re.fullmatch(r"[0-9a-f]+", part) for part in (version, trace_id, span_id, flags))
        and int(trace_id, 16)
        and int(span_id, 16)
    ):
        return None, None
    return trace_id, span_id


class ContextFilter(logging.Filter):
    """Attach the current execution context to each emitted record."""

    def filter(self, record: logging.LogRecord) -> bool:
        for key, value in (_log_context.get() or {}).items():
            if not hasattr(record, key):
                setattr(record, key, value)
        return True


__all__ = [
    "ContextFilter",
    "bind_log_context",
    "command_name",
    "current_log_context",
    "parse_traceparent",
    "redact",
    "sanitize_text",
]
