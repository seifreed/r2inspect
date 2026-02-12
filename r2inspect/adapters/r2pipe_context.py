#!/usr/bin/env python3
"""Context helpers for r2pipe sessions."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any


@contextmanager
def open_r2pipe(filepath: str, flags: list[str] | None = None) -> Iterator[Any]:
    """Open an r2pipe session with consistent flags."""
    import r2pipe

    with r2pipe.open(filepath, flags=flags or ["-2"]) as r2:
        yield r2
