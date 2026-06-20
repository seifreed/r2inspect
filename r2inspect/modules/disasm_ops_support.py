"""Shared disassembly-ops extraction for mnemonic analyzers."""

from __future__ import annotations

from typing import Any, Protocol

from ..abstractions.coercion_support import coerce_list
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
    return coerce_list(disasm.get("ops"))


def normalize_pdj_disasm(disasm_list: Any) -> list[Any]:
    """Normalize a ``pdj`` result into an ops list ([] when unusable).

    ``pdj`` may return either a bare list of instruction records or a dict
    wrapping them under ``ops``; both forms (and anything malformed) collapse
    to a single list here.
    """
    if isinstance(disasm_list, dict):
        return coerce_list(disasm_list.get("ops"))
    return coerce_list(disasm_list)
