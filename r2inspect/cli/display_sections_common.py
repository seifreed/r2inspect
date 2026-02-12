#!/usr/bin/env python3
"""Shared helpers for display section renderers."""

from __future__ import annotations

from typing import Any

from rich.console import Console

Results = dict[str, Any]


def _get_console() -> Console:
    from . import display as display_module

    return display_module.console
