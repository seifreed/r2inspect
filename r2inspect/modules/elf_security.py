#!/usr/bin/env python3
"""ELF security feature helpers."""

from __future__ import annotations

from typing import Any

from ..utils.r2_helpers import get_elf_headers
from .elf_security_domain import has_nx, has_relro, has_stack_canary, is_pie, path_features


def get_security_features(adapter: Any, logger: Any) -> dict[str, bool]:
    features = {
        "nx": False,
        "stack_canary": False,
        "relro": False,
        "pie": False,
        "rpath": False,
        "runpath": False,
    }

    try:
        features["nx"] = has_nx(get_elf_headers(adapter))
        features["stack_canary"] = has_stack_canary(adapter.get_symbols())
        dynamic_info = _get_dynamic_info_text(adapter)
        features["relro"] = has_relro(dynamic_info)
        features["pie"] = is_pie(adapter.get_file_info())
        features.update(path_features(dynamic_info))
    except Exception as exc:
        logger.debug(f"Error checking security features: {exc}")

    return features


def _get_dynamic_info_text(adapter: Any) -> str:
    getter = getattr(adapter, "get_dynamic_info_text", None)
    if callable(getter):
        result = getter()
        return result if isinstance(result, str) else str(result)
    from ..utils.command_helpers import cmd as cmd_helper

    return cmd_helper(adapter, None, "id")
