#!/usr/bin/env python3
"""ELF security feature helpers."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ..abstractions.coercion_support import coerce_dict
from ..domain.formats.elf_security import has_nx, has_relro, has_stack_canary, is_pie, path_features


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
        features["nx"] = has_nx(_get_elf_segments(adapter))
        features["stack_canary"] = has_stack_canary(adapter.get_symbols())
        file_info = adapter.get_file_info()
        bin_info = coerce_dict(file_info).get("bin", {})
        features["relro"] = has_relro(bin_info.get("relro"))
        features["pie"] = is_pie(file_info)
        features.update(path_features(_get_dynamic_info_text(adapter)))
    except Exception as exc:
        logger.debug("Error checking security features: %s", exc)

    return features


def _get_elf_segments(adapter: Any) -> list[dict[str, Any]]:
    # NX lives on the GNU_STACK program segment (iSSj), not in the ELF file
    # header (ih/ihj), which is what was being read before — so nx was always
    # False. Fetch the real segment list.
    getter = getattr(adapter, "cmdj", None)
    if not callable(getter):
        return []
    segments = getter("iSSj")
    if isinstance(segments, list):
        return segments
    if isinstance(segments, (dict, str, bytes)) or not isinstance(segments, Iterable):
        return []
    return list(segments)


def _get_dynamic_info_text(adapter: Any) -> str:
    getter = getattr(adapter, "get_dynamic_info_text", None)
    if callable(getter):
        result = getter()
        return result if isinstance(result, str) else str(result)
    from ..infrastructure.command_helpers import cmd as cmd_helper

    return str(cmd_helper(adapter, None, "id"))
