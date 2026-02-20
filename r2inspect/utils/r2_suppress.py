#!/usr/bin/env python3
"""
R2pipe error suppression utilities
"""

import contextlib
import io
import sys
import warnings
from collections.abc import Iterator
from types import TracebackType
from typing import Any, Literal, TextIO

from ..interfaces import R2CommandInterface
from .logger import get_logger
from .r2_helpers import safe_cmdj

logger = get_logger(__name__)


class R2PipeErrorSuppressor:
    """Context manager to suppress r2pipe.cmdj errors"""

    def __init__(self) -> None:
        self.original_stderr: TextIO | None = None
        self.original_stdout: TextIO | None = None
        self.devnull: io.StringIO | None = None

    def __enter__(self) -> "R2PipeErrorSuppressor":
        """Suppress stderr output temporarily"""
        self.original_stderr = sys.stderr
        self.original_stdout = sys.stdout
        self.devnull = io.StringIO()
        sys.stderr = self.devnull
        sys.stdout = self.devnull
        # Also suppress warnings
        warnings.filterwarnings("ignore", message=".*r2pipe.*")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> Literal[False]:
        """Restore stderr"""
        sys.stderr = self.original_stderr
        sys.stdout = self.original_stdout
        # Don't suppress the exception
        return False


def silent_cmdj(
    r2_instance: R2CommandInterface | None, command: str, default: Any | None = None
) -> Any | None:
    """
    Execute r2pipe cmdj command with complete error suppression.

    Args:
        r2_instance: The r2pipe instance
        command: The radare2 command to execute
        default: Default value to return on error

    Returns:
        JSON result or default value on error
    """
    # Check if r2_instance is still valid
    if not r2_instance:
        return default

    with R2PipeErrorSuppressor():
        try:
            result = _try_cmdj(r2_instance, command, default)
            if result is not None or result == default:
                return result
            parsed = _try_cmd_parse(r2_instance, command, default)  # pragma: no cover
            if parsed is not None or parsed == default:  # pragma: no cover
                return parsed  # pragma: no cover
            return safe_cmdj(r2_instance, command, default)  # pragma: no cover
        except Exception as exc:
            logger.debug("Suppressed unexpected r2pipe error for %s: %s", command, exc)
            return default


def _try_cmdj(r2_instance: R2CommandInterface, command: str, default: Any | None) -> Any | None:
    with R2PipeErrorSuppressor():
        try:
            result = r2_instance.cmdj(command)
            return result if result is not None else default
        except OSError:
            return default


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
    """Context manager to suppress all r2pipe errors"""
    with R2PipeErrorSuppressor():
        yield
