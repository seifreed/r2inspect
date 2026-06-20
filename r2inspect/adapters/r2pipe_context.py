#!/usr/bin/env python3
"""Context helpers for r2pipe sessions."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

from ..infrastructure.r2_session_cleanup import force_close_process
from .r2pipe_adapter import R2PipeAdapter

_logger = logging.getLogger(__name__)

DEFAULT_R2_FLAGS = ["-2", "-N"]


@contextmanager
def open_r2pipe(
    filepath: str,
    flags: list[str] | None = None,
    *,
    opener: Callable[..., Any] | None = None,
) -> Iterator[Any]:
    """Open an r2pipe session with consistent flags.

    ``-N`` skips the user/system radare2rc so analysis is deterministic and
    independent of the analyst's environment. It is also a safety guard: an rc
    with ``e cfg.debug=true`` would otherwise make radare2 debug-launch the
    sample on open (executing the malware and hanging the pipe).

    ``opener`` defaults to ``r2pipe.open``; tests inject a deterministic
    opener instead of patching r2pipe.
    """
    if opener is None:
        import r2pipe

        opener = r2pipe.open

    r2 = opener(filepath, flags=flags or list(DEFAULT_R2_FLAGS))
    try:
        yield r2
    finally:
        _close_r2pipe(r2)


@contextmanager
def open_r2_adapter(
    filepath: str,
    flags: list[str] | None = None,
    *,
    opener: Callable[..., Any] | None = None,
) -> Iterator[R2PipeAdapter]:
    """Open an r2pipe session and wrap it in an adapter."""
    with open_r2pipe(filepath, flags=flags, opener=opener) as r2:
        yield R2PipeAdapter(r2)


def _close_r2pipe(r2_instance: Any) -> None:
    """Best-effort cleanup for r2pipe backends that leave Popen handles open."""
    try:
        r2_instance.quit()
    except Exception as e:
        _logger.debug("Error closing r2pipe session: %s", e)

    force_close_process(r2_instance)
