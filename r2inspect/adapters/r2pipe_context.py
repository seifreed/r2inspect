#!/usr/bin/env python3
"""Context helpers for r2pipe sessions."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from .r2pipe_adapter import R2PipeAdapter

_logger = logging.getLogger(__name__)


@contextmanager
def open_r2pipe(filepath: str, flags: list[str] | None = None) -> Iterator[Any]:
    """Open an r2pipe session with consistent flags."""
    import r2pipe

    r2 = r2pipe.open(filepath, flags=flags or ["-2"])
    try:
        yield r2
    finally:
        _close_r2pipe(r2)


@contextmanager
def open_r2_adapter(filepath: str, flags: list[str] | None = None) -> Iterator[R2PipeAdapter]:
    """Open an r2pipe session and wrap it in an adapter."""
    with open_r2pipe(filepath, flags=flags) as r2:
        yield R2PipeAdapter(r2)


def _close_r2pipe(r2_instance: Any) -> None:
    """Best-effort cleanup for r2pipe backends that leave Popen handles open."""
    try:
        r2_instance.quit()
    except Exception as e:
        _logger.debug("Error closing r2pipe session: %s", e)

    process = getattr(r2_instance, "process", None)
    if process is None:
        return

    for stream_name in ("stdin", "stdout", "stderr"):
        stream = getattr(process, stream_name, None)
        if stream is None:
            continue
        try:
            stream.close()
        except Exception as e:
            _logger.debug("Error closing %s: %s", stream_name, e)

    try:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=1.0)
    except Exception as e:
        _logger.debug("Error terminating process: %s", e)
        try:
            if process.poll() is None:
                process.kill()
        except Exception as kill_error:
            _logger.debug("Error killing process: %s", kill_error)
