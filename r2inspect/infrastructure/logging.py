#!/usr/bin/env python3
"""Thread-safe logging utilities for r2inspect infrastructure."""

from __future__ import annotations

import logging
import logging.handlers
import sys
import threading
from collections.abc import Callable
from pathlib import Path

_logger_lock = threading.Lock()
_loggers_initialized: set[str] = set()


def _handler_is_closed(handler: logging.Handler) -> bool:
    stream = getattr(handler, "stream", None)
    return bool(stream is not None and getattr(stream, "closed", False))


def _reuse_existing_handlers(logger: logging.Logger, name: str) -> logging.Logger | None:
    """Return the logger when its handlers are reusable, else clear closed ones and return None."""
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
    log_dir: Path,
    *,
    thread_safe: bool,
    file_handler_factory: Callable[[], logging.Handler] | None,
) -> logging.Handler:
    if file_handler_factory is not None:
        return file_handler_factory()
    if thread_safe:
        return logging.handlers.RotatingFileHandler(
            log_dir / "r2inspect.log",
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
        )
    return logging.FileHandler(log_dir / "r2inspect.log")


def _standard_formatter(thread_safe: bool) -> logging.Formatter:
    if thread_safe:
        return logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - [%(thread)d] - %(message)s"
        )
    return logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")


def setup_logger(
    name: str = "r2inspect",
    level: int = logging.INFO,
    thread_safe: bool = True,
    *,
    file_handler_factory: Callable[[], logging.Handler] | None = None,
) -> logging.Logger:
    """Setup a logger with console and file handlers."""
    with _logger_lock:
        logger = logging.getLogger(name)
        logger.setLevel(level)

        reused = _reuse_existing_handlers(logger, name)
        if reused is not None:
            return reused

        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(level)

        if thread_safe:
            console_handler.lock = threading.Lock()

        try:
            log_dir = Path.home() / ".r2inspect" / "logs"
            log_dir.mkdir(parents=True, exist_ok=True)

            file_handler = _build_file_handler(
                log_dir, thread_safe=thread_safe, file_handler_factory=file_handler_factory
            )
            file_handler.setLevel(logging.DEBUG)

            formatter = _standard_formatter(thread_safe)
            console_handler.setFormatter(formatter)
            file_handler.setFormatter(formatter)
            logger.addHandler(console_handler)
            logger.addHandler(file_handler)

        except Exception:
            formatter = logging.Formatter(
                "%(levelname)s - [%(thread)d] - %(message)s"
                if thread_safe
                else "%(levelname)s - %(message)s"
            )
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

        _loggers_initialized.add(name)
        return logger


def get_logger(name: str = "r2inspect") -> logging.Logger:
    """Get an existing logger instance."""
    return logging.getLogger(name)


def configure_batch_logging() -> None:
    """Configure logging for batch processing to reduce noise."""
    with _logger_lock:
        logging.getLogger("r2inspect").setLevel(logging.WARNING)
        logging.getLogger("r2inspect.core").setLevel(logging.WARNING)
        logging.getLogger("r2inspect.pipeline").setLevel(logging.WARNING)
        logging.getLogger("r2inspect.modules").setLevel(logging.WARNING)
        logging.getLogger("r2inspect.infrastructure").setLevel(logging.WARNING)
        logging.getLogger("r2inspect.utils").setLevel(logging.WARNING)


def reset_logging_levels() -> None:
    """Reset logging levels to normal."""
    with _logger_lock:
        logging.getLogger("r2inspect").setLevel(logging.INFO)
        logging.getLogger("r2inspect.core").setLevel(logging.INFO)
        logging.getLogger("r2inspect.pipeline").setLevel(logging.INFO)
        logging.getLogger("r2inspect.modules").setLevel(logging.INFO)
        logging.getLogger("r2inspect.infrastructure").setLevel(logging.INFO)
        logging.getLogger("r2inspect.utils").setLevel(logging.INFO)
