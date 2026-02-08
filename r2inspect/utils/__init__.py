#!/usr/bin/env python3
"""
r2inspect Utilities
"""

from typing import Any

from .hashing import calculate_hashes
from .logger import get_logger, setup_logger
from .output import OutputFormatter

__all__ = [
    "get_logger",
    "setup_logger",
    "OutputFormatter",
    "calculate_hashes",
    "safe_cmdj",
    "safe_cmd_list",
    "safe_cmd_dict",
    "safe_cmd",
]


def __getattr__(name: str) -> Any:
    if name in {"safe_cmdj", "safe_cmd_list", "safe_cmd_dict", "safe_cmd"}:
        from . import r2_helpers as _r2_helpers

        return getattr(_r2_helpers, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
