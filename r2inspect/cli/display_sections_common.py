#!/usr/bin/env python3
"""Shared helpers for display section renderers."""

from __future__ import annotations

from typing import Any

from rich.console import Console

Results = dict[str, Any]


def _get_console() -> Console:
    from .display_base import _get_console as _base_get_console

    return _base_get_console()
