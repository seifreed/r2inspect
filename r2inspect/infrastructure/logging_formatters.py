"""Safe human-readable and structured log formatters."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from .logging_context import redact, sanitize_text

_STANDARD_RECORD_FIELDS = frozenset(logging.makeLogRecord({}).__dict__) | {
    "message",
    "asctime",
}


class SafeFormatter(logging.Formatter):
    """Text formatter that redacts secrets and prevents multiline log injection."""

    converter = staticmethod(lambda timestamp: datetime.fromtimestamp(timestamp, UTC).timetuple())

    def format(self, record: logging.LogRecord) -> str:
        original_msg, original_args = record.msg, record.args
        try:
            record.msg = sanitize_text(record.getMessage())
            record.args = ()
            rendered = super().format(record)
            context = " ".join(
                f"{key}={sanitize_text(getattr(record, key))}"
                for key in ("request_id", "correlation_id", "trace_id", "span_id")
                if getattr(record, key, None)
            )
            return f"{rendered} [{context}]" if context else rendered
        finally:
            record.msg, record.args = original_msg, original_args

    def formatException(self, exc_info: Any) -> str:
        return sanitize_text(super().formatException(exc_info))


class JsonFormatter(logging.Formatter):
    """One-event-per-line JSON formatter with a stable production schema."""

    def __init__(self, *, service: str, environment: str) -> None:
        super().__init__()
        self.service = service
        self.environment = environment

    def format(self, record: logging.LogRecord) -> str:
        event: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(
                timespec="milliseconds"
            ),
            "level": record.levelname,
            "message": sanitize_text(record.getMessage()),
            "service": self.service,
            "environment": self.environment,
            "component": record.name,
            "module": record.module,
        }
        for key, value in record.__dict__.items():
            if key not in _STANDARD_RECORD_FIELDS and not key.startswith("_"):
                event[key] = redact(value, key=key)
        if record.exc_info:
            if record.exc_info[0] is not None:
                event.setdefault("error_type", record.exc_info[0].__name__)
            event["stack_trace"] = sanitize_text(self.formatException(record.exc_info))
        return json.dumps(event, ensure_ascii=False, separators=(",", ":"), default=sanitize_text)


__all__ = ["JsonFormatter", "SafeFormatter"]
