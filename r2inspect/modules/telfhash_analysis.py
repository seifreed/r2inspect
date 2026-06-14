#!/usr/bin/env python3
"""Detailed analysis helpers for telfhash analyzer."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Protocol

from ..interfaces.binary_analyzer import BinaryAnalyzerInterface


class TelfhashHost(Protocol):
    """Overridable collaboration contract the telfhash helpers depend on."""

    filepath: Path
    adapter: BinaryAnalyzerInterface | None

    def _cmdj(self, command: str, default: Any | None = None) -> Any: ...
    def _is_elf_file(self) -> bool: ...
    def _has_elf_symbols(self, info_cmd: dict[str, Any] | None) -> bool: ...
    def _get_elf_symbols(self) -> list[dict[str, Any]]: ...
    def _filter_symbols_for_telfhash(
        self, symbols: list[dict[str, Any]]
    ) -> list[dict[str, Any]]: ...
    def _extract_symbol_names(self, symbols: list[dict[str, Any]]) -> list[str]: ...
    def _normalize_telfhash_value(self, value: Any) -> str | None: ...


def _telfhash_from_result(telfhash_result: Any, analyzer: TelfhashHost) -> tuple[str | None, Any]:
    """Return (telfhash_value, error_msg) from a telfhash() return value."""
    if isinstance(telfhash_result, list) and telfhash_result:
        payload = telfhash_result[0]
    elif isinstance(telfhash_result, dict):
        payload = telfhash_result
    else:
        return analyzer._normalize_telfhash_value(telfhash_result), None
    value = analyzer._normalize_telfhash_value(payload.get("telfhash"))
    error = payload.get("msg") if payload.get("msg") and not value else None
    return value, error


def analyze_symbols(
    analyzer: TelfhashHost, *, telfhash_available: bool, telfhash_fn: Any, logger: logging.Logger
) -> dict[str, Any]:
    logger.debug("Starting detailed telfhash analysis for %s", analyzer.filepath)
    results: dict[str, Any] = {
        "available": telfhash_available,
        "telfhash": None,
        "symbol_count": 0,
        "filtered_symbols": 0,
        "symbols_used": [],
        "error": None,
        "is_elf": False,
    }
    if not telfhash_available:
        results["error"] = "telfhash library not available"
        logger.error("telfhash library not available")
        return results
    try:
        if not analyzer._is_elf_file():
            results["error"] = "File is not an ELF binary"
            logger.warning("File %s is not an ELF binary", analyzer.filepath)
            return results
        results["is_elf"] = True
        symbols = analyzer._get_elf_symbols()
        results["symbol_count"] = len(symbols)
        filtered_symbols = analyzer._filter_symbols_for_telfhash(symbols)
        results["filtered_symbols"] = len(filtered_symbols)
        results["symbols_used"] = analyzer._extract_symbol_names(filtered_symbols)[:20]
        try:
            telfhash_result = telfhash_fn(str(analyzer.filepath))
            logger.debug(
                "Telfhash function returned: %s = %s", type(telfhash_result), telfhash_result
            )
            value, error = _telfhash_from_result(telfhash_result, analyzer)
            results["telfhash"] = value
            if error:
                results["error"] = error
            logger.debug("Telfhash calculated: %s", results["telfhash"])
        except Exception as exc:
            logger.error("Error calling telfhash function: %s", exc)
            results["error"] = f"Telfhash calculation failed: {exc}"
    except Exception as exc:
        logger.error("Telfhash analysis failed: %s", exc)
        results["error"] = str(exc)
    return results


def _magic_rules_out_elf(file_path: Path) -> bool:
    """True when the file exists but its first bytes are not (or cannot be read as) ELF magic."""
    if not file_path.exists():
        return False
    try:
        return file_path.read_bytes()[:4] != b"\x7fELF"
    except OSError:
        return True


def _format_excludes_elf(info_cmd: Any) -> bool:
    """True when bin format/class metadata is present and clearly not ELF."""
    if not isinstance(info_cmd, dict):
        return False
    bin_info = info_cmd.get("bin", {})
    if not isinstance(bin_info, dict):
        return False
    format_text = str(bin_info.get("format", "")).lower()
    class_text = str(bin_info.get("class", "")).lower()
    return bool(
        (format_text or class_text) and "elf" not in format_text and "elf" not in class_text
    )


def is_elf_binary(
    analyzer: TelfhashHost, *, logger: logging.Logger, is_elf_file_fn: Any, is_pe_file_fn: Any
) -> bool:
    try:
        if analyzer.adapter is None:
            return False
        if _magic_rules_out_elf(Path(analyzer.filepath)):
            return False
        if is_elf_file_fn(analyzer.filepath, analyzer.adapter, analyzer.adapter, logger=logger):
            return True
        if is_pe_file_fn(analyzer.filepath, analyzer.adapter, analyzer.adapter, logger=logger):
            return False
        info_cmd = analyzer._cmdj("ij", {})
        if _format_excludes_elf(info_cmd):
            return False
        return bool(analyzer._has_elf_symbols(info_cmd))
    except Exception as exc:
        logger.error("Error checking if file is ELF: %s", exc)
        return False
