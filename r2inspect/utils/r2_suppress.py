#!/usr/bin/env python3
"""
R2pipe error suppression utilities
"""

import contextlib
import io
import sys
import warnings
from typing import Any

from .logger import get_logger

logger = get_logger(__name__)


class R2PipeErrorSuppressor:
    """Context manager to suppress r2pipe.cmdj errors"""

    def __init__(self):
        self.original_stderr = None
        self.devnull = None

    def __enter__(self):
        """Suppress stderr output temporarily"""
        self.original_stderr = sys.stderr
        self.devnull = io.StringIO()
        sys.stderr = self.devnull
        # Also suppress warnings
        warnings.filterwarnings("ignore", message=".*r2pipe.*")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Restore stderr"""
        sys.stderr = self.original_stderr
        if self.devnull:
            self.devnull.close()
        # Don't suppress the exception
        return False


def silent_cmdj(r2_instance, command: str, default: Any | None = None) -> Any | None:
    """
    Execute r2pipe cmdj command with complete error suppression.

    Args:
        r2_instance: The r2pipe instance
        command: The radare2 command to execute
        default: Default value to return on error

    Returns:
        JSON result or default value on error
    """
    import json

    # Check if r2_instance is still valid
    if not r2_instance:
        return default

    try:
        result = _try_cmdj(r2_instance, command, default)
        if result is not None or result == default:
            return result
    except (json.JSONDecodeError, TypeError):
        pass
    except Exception as exc:
        logger.debug("Suppressed unexpected r2pipe error for %s: %s", command, exc)
        return default

    try:
        return _try_cmd_parse(r2_instance, command, default)
    except (OSError, json.JSONDecodeError, TypeError):
        logger.debug("Suppressed r2pipe command error for %s", command)

    return default


def _try_cmdj(r2_instance, command: str, default: Any | None) -> Any | None:
    with R2PipeErrorSuppressor():
        try:
            result = r2_instance.cmdj(command)
            return result if result is not None else default
        except OSError:
            return default


def _try_cmd_parse(r2_instance, command: str, default: Any | None) -> Any | None:
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
def suppress_r2pipe_errors():
    """Context manager to suppress all r2pipe errors"""
    with R2PipeErrorSuppressor():
        yield
