#!/usr/bin/env python3
"""Canonical adapter-aware command helpers."""

from __future__ import annotations

from typing import Any

from .r2_helpers import (
    _handle_bytes,
    _handle_disasm,
    _handle_search,
    _handle_simple,
    _maybe_use_adapter,
    _parse_address,
    _parse_size,
    cmd as _cmd_impl,
    cmd_list as _cmd_list_impl,
    cmdj as _cmdj_impl,
)


def cmd(*args: Any, **kwargs: Any) -> Any:
    return _cmd_impl(*args, **kwargs)


def cmdj(*args: Any, **kwargs: Any) -> Any:
    return _cmdj_impl(*args, **kwargs)


def cmd_list(*args: Any, **kwargs: Any) -> Any:
    return _cmd_list_impl(*args, **kwargs)


__all__ = [
    "_handle_bytes",
    "_handle_disasm",
    "_handle_search",
    "_handle_simple",
    "_maybe_use_adapter",
    "_parse_address",
    "_parse_size",
    "cmd",
    "cmd_list",
    "cmdj",
]
