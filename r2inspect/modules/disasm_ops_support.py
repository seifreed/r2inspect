"""Shared disassembly-ops extraction for mnemonic analyzers."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Protocol

from ..interfaces.binary_analyzer import BinaryAnalyzerInterface


class PdfjHost(Protocol):
    """Minimal contract for fetching ``pdfj`` disassembly."""

    adapter: BinaryAnalyzerInterface | None

    def _cmdj(self, command: str, default: Any | None = None) -> Any: ...


def extract_pdfj_ops(analyzer: PdfjHost, func_addr: int) -> list[Any]:
    """Fetch ``pdfj`` disassembly for a function and return its ops as a list.

    Returns an empty list when the disassembly is missing or its ``ops`` field
    is not a usable iterable of instruction records.
    """
    disasm = (
        analyzer.adapter.get_disasm(address=func_addr)
        if analyzer.adapter is not None and hasattr(analyzer.adapter, "get_disasm")
        else analyzer._cmdj(f"pdfj @ {func_addr}", {})
    )
    if not isinstance(disasm, dict):
        return []
    return _coerce_ops(disasm.get("ops"))


def normalize_pdj_disasm(disasm_list: Any) -> list[Any]:
    """Normalize a ``pdj`` result into an ops list ([] when unusable).

    ``pdj`` may return either a bare list of instruction records or a dict
    wrapping them under ``ops``; both forms (and anything malformed) collapse
    to a single list here.
    """
    if isinstance(disasm_list, list):
        return disasm_list
    if isinstance(disasm_list, dict):
        return _coerce_ops(disasm_list.get("ops"))
    return _coerce_ops(disasm_list)


def _coerce_ops(ops: Any) -> list[Any]:
    if isinstance(ops, list):
        return ops
    if isinstance(ops, (dict, str, bytes)) or not isinstance(ops, Iterable):
        return []
    return list(ops)
