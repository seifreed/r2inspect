"""HTTP request correlation and completion events for the local API."""

from __future__ import annotations

import logging
import re
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from typing import Any
from urllib.parse import urlparse

from ..infrastructure.logging import bind_log_context, get_logger, parse_traceparent

logger = get_logger(__name__)


def request_identifier(value: str | None, fallback: str) -> str:
    if value and re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", value):
        return value
    return fallback


def request_route(path: str) -> str:
    parsed = urlparse(path).path
    if parsed in {"/health", "/v1/jobs"}:
        return parsed
    return "/v1/jobs/{job_id}" if parsed.startswith("/v1/jobs/") else "unknown"


@contextmanager
def observed_request(handler: Any, operation: str) -> Iterator[None]:
    """Bind inbound context and emit exactly one request outcome event."""
    started = time.perf_counter()
    handler._response_status = 0
    handler._request_id = request_identifier(handler.headers.get("X-Request-ID"), uuid.uuid4().hex)
    correlation_id = request_identifier(
        handler.headers.get("X-Correlation-ID"), handler._request_id
    )
    trace_id, span_id = parse_traceparent(handler.headers.get("traceparent"))
    failed = False
    with bind_log_context(
        request_id=handler._request_id,
        correlation_id=correlation_id,
        trace_id=trace_id,
        span_id=span_id,
        operation=operation,
    ):
        try:
            yield
        except Exception:
            failed = True
            logger.exception(
                "HTTP request failed",
                extra={
                    "event_name": "api.request_failed",
                    "route": request_route(handler.path),
                    "method": handler.command,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                    "outcome": "error",
                },
            )
            if not handler._response_status:
                with suppress(Exception):
                    handler._send(500, {"error": "internal server error"})
        finally:
            if not failed:
                status = handler._response_status or 500
                level = logging.DEBUG if request_route(handler.path) == "/health" else logging.INFO
                if status >= 500:
                    level = logging.ERROR
                elif status == 401:
                    level = logging.DEBUG
                logger.log(
                    level,
                    "HTTP request completed",
                    extra={
                        "event_name": "api.request_completed",
                        "route": request_route(handler.path),
                        "method": handler.command,
                        "status": status,
                        "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                        "outcome": "success" if status < 400 else "rejected",
                    },
                )


__all__ = ["observed_request", "request_identifier", "request_route"]
