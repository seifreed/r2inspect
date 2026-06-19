"""Data access helpers for SimHash analysis."""

from __future__ import annotations

from typing import Any

from ..abstractions.coercion_support import coerce_dict_iterable, coerce_list
from .simhash_support import SimHashHost


def get_strings_data(host: SimHashHost) -> list[Any]:
    if host.adapter is not None and hasattr(host.adapter, "get_strings"):
        return coerce_list(host.adapter.get_strings())
    return coerce_list(host._cmd_list("izzj"))


def get_functions(host: SimHashHost) -> list[dict[str, Any]]:
    if host.adapter is not None and hasattr(host.adapter, "get_functions"):
        return coerce_dict_iterable(host.adapter.get_functions())
    return coerce_dict_iterable(host._cmd_list("aflj"))


def get_sections(host: SimHashHost) -> list[dict[str, Any]]:
    if host.adapter is not None and hasattr(host.adapter, "get_sections"):
        return coerce_dict_iterable(host.adapter.get_sections())
    return coerce_dict_iterable(host._cmd_list("iSj"))


def extract_ops_from_disasm(disasm: Any) -> list[Any]:
    if isinstance(disasm, dict):
        ops = disasm.get("ops")
        return coerce_list(ops)
    return coerce_list(disasm)
