#!/usr/bin/env python3
"""Compatibility wrapper for adapter-aware r2 command helpers."""

from __future__ import annotations

from typing import Any

from .r2_helpers import _handle_bytes, _parse_size
from .r2_helpers import cmd as _cmd
from .r2_helpers import cmd_list as _cmd_list
from .r2_helpers import cmdj as _cmdj


def cmd(adapter: Any, _r2: Any, command: str) -> str:
    return _cmd(adapter, _r2, command)


def cmdj(adapter: Any, _r2: Any, command: str, default: Any) -> Any:
    return _cmdj(adapter, _r2, command, default)


def cmd_list(adapter: Any, _r2: Any, command: str) -> list[Any]:
    return _cmd_list(adapter, _r2, command)
