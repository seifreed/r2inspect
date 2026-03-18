#!/usr/bin/env python3
"""R2pipe error suppression utilities."""

from __future__ import annotations

import contextlib
import io
import sys
import warnings
from collections.abc import Iterator
from types import TracebackType
from typing import Any, Literal, TextIO

from ..interfaces import R2CommandInterface
from .logging import get_logger
from .r2_helpers import safe_cmdj

logger = get_logger(__name__)
_CMDJ_FAILED = object()


class R2PipeErrorSuppressor:
    """Context manager to suppress r2pipe.cmdj errors."""

    def __init__(self) -> None:
        self.original_stderr: TextIO | None = None
        self.original_stdout: TextIO | None = None
        self.devnull: io.StringIO | None = None

    def __enter__(self) -> R2PipeErrorSuppressor:
        self.original_stderr = sys.stderr
        self.original_stdout = sys.stdout
        self.devnull = io.StringIO()
        sys.stderr = self.devnull
        sys.stdout = self.devnull
        warnings.filterwarnings("ignore", message=".*r2pipe.*")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> Literal[False]:
        sys.stderr = self.original_stderr
        sys.stdout = self.original_stdout
        return False


def silent_cmdj(
    r2_instance: R2CommandInterface | None, command: str, default: Any | None = None
) -> Any | None:
    """Execute cmdj with complete r2pipe error suppression."""
    if not r2_instance:
        return default

    with R2PipeErrorSuppressor():
        try:
            result = _try_cmdj(r2_instance, command, default)
            if result is _CMDJ_FAILED:
                logger.debug("cmdj failed for %s, falling back to text parsing", command)
                result = None
            if result is not None or (default is not None and result == default):
                return result
            parsed = _try_cmd_parse(r2_instance, command, default)
            if parsed is not None or parsed == default:
                return parsed
            logger.debug(
                "text parsing produced no result for %s, using safe_cmdj fallback", command
            )
            return safe_cmdj(r2_instance, command, default)
        except (OSError, ValueError, TypeError, RuntimeError, AttributeError) as exc:
            logger.debug("Suppressed unexpected r2pipe error for %s: %s", command, exc)
            return default


def _try_cmdj(r2_instance: R2CommandInterface, command: str, default: Any | None) -> Any | None:
    with R2PipeErrorSuppressor():
        try:
            result = r2_instance.cmdj(command)
            return result if result is not None else default
        except OSError:
            return default
        except (ValueError, TypeError, RuntimeError, AttributeError):
            return _CMDJ_FAILED


def _try_cmd_parse(
    r2_instance: R2CommandInterface, command: str, default: Any | None
) -> Any | None:
    with R2PipeErrorSuppressor():
        raw_result = r2_instance.cmd(command)
        if raw_result and raw_result.strip():
            parsed = _parse_raw_result(raw_result)
            if parsed is not None:
                return parsed
    return default


def _parse_raw_result(raw_result: str) -> Any | None:
    import json

    try:
        return json.loads(raw_result)
    except (json.JSONDecodeError, TypeError):
        if len(raw_result.strip()) > 2:
            return raw_result.strip()
    return None


@contextlib.contextmanager
def suppress_r2pipe_errors() -> Iterator[None]:
    """Context manager to suppress all r2pipe errors."""
    with R2PipeErrorSuppressor():
        yield


__all__ = ["R2PipeErrorSuppressor", "silent_cmdj", "suppress_r2pipe_errors"]
