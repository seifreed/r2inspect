#!/usr/bin/env python3
"""Central configuration facade for r2inspect logging."""

from __future__ import annotations

import logging
import logging.handlers
import os
import sys
import threading
from collections.abc import Callable
from io import TextIOWrapper
from pathlib import Path
from typing import Any

from .logging_context import (
    ContextFilter,
    bind_log_context,
    command_name,
    current_log_context,
    parse_traceparent,
    redact,
    sanitize_text,
)
from .logging_formatters import JsonFormatter, SafeFormatter

TRACE = 5
logging.addLevelName(TRACE, "TRACE")

_logger_lock = threading.Lock()
_loggers_initialized: set[str] = set()


class _PrivateRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """Keep every active log file private across rollover."""

    def _open(self) -> TextIOWrapper[Any]:
        stream = super()._open()
        try:
            os.chmod(self.baseFilename, 0o600)
        except OSError:
            stream.close()
            raise
        return stream


def _handler_is_closed(handler: logging.Handler) -> bool:
    stream = getattr(handler, "stream", None)
    return bool(getattr(handler, "_closed", False) or (stream and getattr(stream, "closed", False)))


def _reuse_existing_handlers(logger: logging.Logger, name: str) -> logging.Logger | None:
    """Return the logger when its handlers are reusable, else clear closed ones."""
    if not logger.handlers:
        return None
    if any(_handler_is_closed(handler) for handler in logger.handlers):
        for handler in list(logger.handlers):
            try:
                handler.close()
            finally:
                logger.removeHandler(handler)
        _loggers_initialized.discard(name)
        return None
    _loggers_initialized.add(name)
    return logger


def _build_file_handler(
    log_file: Path,
    *,
    thread_safe: bool,
    file_handler_factory: Callable[[], logging.Handler] | None,
) -> logging.Handler:
    if file_handler_factory is not None:
        return file_handler_factory()
    if thread_safe:
        return _PrivateRotatingFileHandler(
            log_file,
            maxBytes=max(int(os.getenv("R2INSPECT_LOG_MAX_BYTES", str(10 * 1024 * 1024))), 1),
            backupCount=max(int(os.getenv("R2INSPECT_LOG_BACKUP_COUNT", "5")), 1),
            encoding="utf-8",
        )
    handler = logging.FileHandler(log_file, encoding="utf-8")
    try:
        log_file.chmod(0o600)
    except OSError:
        handler.close()
        raise
    return handler


def _formatter(format_name: str, thread_safe: bool) -> logging.Formatter:
    if format_name == "json":
        return JsonFormatter(
            service=os.getenv("R2INSPECT_SERVICE", "r2inspect"),
            environment=os.getenv("R2INSPECT_ENVIRONMENT", "development"),
        )
    suffix = " [%(thread)d]" if thread_safe else ""
    return SafeFormatter(
        f"%(asctime)sZ %(levelname)s %(name)s{suffix} %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


def _configured_level(level: int | str) -> int:
    configured = os.getenv("R2INSPECT_LOG_LEVEL")
    candidate: int | str = configured if configured else level
    if isinstance(candidate, int):
        return candidate
    normalized = candidate.strip().upper()
    if normalized == "TRACE":
        return TRACE
    resolved = logging.getLevelName(normalized)
    if isinstance(resolved, int):
        return resolved
    raise ValueError(f"invalid log level: {candidate}")


def setup_logger(
    name: str = "r2inspect",
    level: int | str = logging.INFO,
    thread_safe: bool = True,
    *,
    file_handler_factory: Callable[[], logging.Handler] | None = None,
    format_name: str | None = None,
    destination: str | None = None,
    log_file: str | Path | None = None,
) -> logging.Logger:
    """Configure a logger from explicit values or ``R2INSPECT_LOG_*`` environment variables."""
    with _logger_lock:
        logger = logging.getLogger(name)
        configured_level = _configured_level(level)
        logger.setLevel(configured_level)
        logger.propagate = False

        reused = _reuse_existing_handlers(logger, name)
        if reused is not None:
            for handler in reused.handlers:
                if not isinstance(handler, logging.FileHandler):
                    handler.setLevel(configured_level)
            return reused

        selected_format = (format_name or os.getenv("R2INSPECT_LOG_FORMAT") or "text").lower()
        if selected_format not in {"json", "text"}:
            raise ValueError("log format must be 'json' or 'text'")
        selected_destination = (
            destination or os.getenv("R2INSPECT_LOG_DESTINATION") or "both"
        ).lower()
        if selected_destination not in {"stderr", "file", "both"}:
            raise ValueError("log destination must be 'stderr', 'file', or 'both'")

        formatter = _formatter(selected_format, thread_safe)
        context_filter = ContextFilter()
        if selected_destination in {"stderr", "both"}:
            console_handler = logging.StreamHandler(sys.stderr)
            console_handler.setLevel(configured_level)
            console_handler.setFormatter(formatter)
            console_handler.addFilter(context_filter)
            logger.addHandler(console_handler)

        if selected_destination in {"file", "both"}:
            try:
                path = Path(
                    log_file
                    or os.getenv("R2INSPECT_LOG_FILE", "")
                    or Path.home() / ".r2inspect" / "logs" / "r2inspect.log"
                ).expanduser()
                path.parent.mkdir(parents=True, exist_ok=True)
                file_handler = _build_file_handler(
                    path,
                    thread_safe=thread_safe,
                    file_handler_factory=file_handler_factory,
                )
                file_handler.setLevel(TRACE)
                file_handler.setFormatter(formatter)
                file_handler.addFilter(context_filter)
                logger.addHandler(file_handler)
            except Exception as exc:
                if not logger.handlers:
                    console_handler = logging.StreamHandler(sys.stderr)
                    console_handler.setLevel(configured_level)
                    console_handler.setFormatter(formatter)
                    console_handler.addFilter(context_filter)
                    logger.addHandler(console_handler)
                logger.warning(
                    "File logging unavailable; using stderr",
                    extra={
                        "event_name": "logging.file_unavailable",
                        "error_type": type(exc).__name__,
                        "outcome": "degraded",
                    },
                )

        _loggers_initialized.add(name)
        return logger


def get_logger(name: str = "r2inspect") -> logging.Logger:
    """Return a standard logger; children propagate to the configured r2inspect logger."""
    return logging.getLogger(name)


def flush_logging() -> None:
    """Best-effort flush for controlled shutdown boundaries."""
    for logger_name in tuple(_loggers_initialized):
        for handler in logging.getLogger(logger_name).handlers:
            _flush_handler(handler)


def _flush_handler(handler: logging.Handler) -> bool:
    try:
        handler.flush()
    except Exception:
        return False
    return True


_MANAGED_LOGGERS = (
    "r2inspect",
    "r2inspect.core",
    "r2inspect.pipeline",
    "r2inspect.modules",
    "r2inspect.infrastructure",
    "r2inspect.utils",
)


def configure_batch_logging() -> None:
    """Reduce per-item batch noise while preserving warnings and failures."""
    with _logger_lock:
        for logger_name in _MANAGED_LOGGERS:
            logging.getLogger(logger_name).setLevel(logging.WARNING)


def reset_logging_levels() -> None:
    """Reset managed logger levels to the configured operational default."""
    with _logger_lock:
        level = _configured_level(logging.INFO)
        for logger_name in _MANAGED_LOGGERS:
            logging.getLogger(logger_name).setLevel(level)


__all__ = [
    "JsonFormatter",
    "SafeFormatter",
    "TRACE",
    "bind_log_context",
    "command_name",
    "configure_batch_logging",
    "current_log_context",
    "flush_logging",
    "get_logger",
    "parse_traceparent",
    "redact",
    "reset_logging_levels",
    "sanitize_text",
    "setup_logger",
]
