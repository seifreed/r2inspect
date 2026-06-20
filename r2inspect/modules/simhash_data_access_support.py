"""Data access helpers for SimHash analysis."""

from __future__ import annotations

from typing import Any

from ..abstractions.coercion_support import coerce_dict_iterable, coerce_list
from .simhash_support import SimHashHost


def _get_adapter_or_cmd_list(host: SimHashHost, attr: str, command: str) -> list[Any]:
    if host.adapter is not None and hasattr(host.adapter, attr):
        return coerce_list(getattr(host.adapter, attr)())
    return coerce_list(host._cmd_list(command))


def get_strings_data(host: SimHashHost) -> list[Any]:
    return _get_adapter_or_cmd_list(host, "get_strings", "izzj")


def get_functions(host: SimHashHost) -> list[dict[str, Any]]:
    return coerce_dict_iterable(_get_adapter_or_cmd_list(host, "get_functions", "aflj"))


def get_sections(host: SimHashHost) -> list[dict[str, Any]]:
    return coerce_dict_iterable(_get_adapter_or_cmd_list(host, "get_sections", "iSj"))


def extract_ops_from_disasm(disasm: Any) -> list[Any]:
    if isinstance(disasm, dict):
        ops = disasm.get("ops")
        return coerce_list(ops)
    return coerce_list(disasm)
