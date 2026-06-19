"""Data access helpers for SimHash analysis."""

from __future__ import annotations

from typing import Any, cast

from .simhash_support import SimHashHost


def get_strings_data(host: SimHashHost) -> list[Any]:
    def _coerce(value: Any) -> list[Any]:
        if isinstance(value, list):
            return value
        try:
            return list(value)
        except TypeError:
            return []

    if host.adapter is not None and hasattr(host.adapter, "get_strings"):
        return _coerce(host.adapter.get_strings())
    return _coerce(host._cmd_list("izzj"))


def get_functions(host: SimHashHost) -> list[dict[str, Any]]:
    def _coerce(value: Any) -> list[dict[str, Any]]:
        if isinstance(value, list):
            return [func for func in value if isinstance(func, dict)]
        try:
            return [func for func in list(value) if isinstance(func, dict)]
        except TypeError:
            return []

    if host.adapter is not None and hasattr(host.adapter, "get_functions"):
        return _coerce(host.adapter.get_functions())
    return _coerce(host._cmd_list("aflj"))


def get_sections(host: SimHashHost) -> list[dict[str, Any]]:
    def _coerce(value: Any) -> list[dict[str, Any]]:
        if isinstance(value, list):
            return [section for section in value if isinstance(section, dict)]
        try:
            return [section for section in list(value) if isinstance(section, dict)]
        except TypeError:
            return []

    if host.adapter is not None and hasattr(host.adapter, "get_sections"):
        return _coerce(host.adapter.get_sections())
    return _coerce(host._cmd_list("iSj"))


def extract_ops_from_disasm(disasm: Any) -> list[Any]:
    if isinstance(disasm, dict) and isinstance(disasm.get("ops"), list):
        return cast(list[Any], disasm["ops"])
    if isinstance(disasm, list):
        return disasm
    if isinstance(disasm, (dict, str, bytes)):
        return []
    try:
        return list(disasm)
    except TypeError:
        return []
