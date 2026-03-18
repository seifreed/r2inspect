#!/usr/bin/env python3
"""Detailed analysis helpers for telfhash analyzer."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def analyze_symbols(
    analyzer: Any, *, telfhash_available: bool, telfhash_fn: Any, logger: Any
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
            if isinstance(telfhash_result, list) and telfhash_result:
                result_dict = telfhash_result[0]
                results["telfhash"] = analyzer._normalize_telfhash_value(
                    result_dict.get("telfhash")
                )
                if result_dict.get("msg") and not results["telfhash"]:
                    results["error"] = result_dict.get("msg")
            elif isinstance(telfhash_result, dict):
                results["telfhash"] = analyzer._normalize_telfhash_value(
                    telfhash_result.get("telfhash")
                )
                if telfhash_result.get("msg") and not results["telfhash"]:
                    results["error"] = telfhash_result.get("msg")
            else:
                results["telfhash"] = analyzer._normalize_telfhash_value(telfhash_result)
            logger.debug("Telfhash calculated: %s", results["telfhash"])
        except Exception as exc:
            logger.error("Error calling telfhash function: %s", exc)
            results["error"] = f"Telfhash calculation failed: {exc}"
    except Exception as exc:
        logger.error("Telfhash analysis failed: %s", exc)
        results["error"] = str(exc)
    return results


def is_elf_binary(analyzer: Any, *, logger: Any, is_elf_file_fn: Any, is_pe_file_fn: Any) -> bool:
    try:
        if analyzer.r2 is None:
            return False
        file_path = Path(analyzer.filepath)
        if file_path.exists():
            try:
                if file_path.read_bytes()[:4] != b"\x7fELF":
                    return False
            except OSError:
                return False
        if is_elf_file_fn(analyzer.filepath, analyzer.adapter, analyzer.r2, logger=logger):
            return True
        if is_pe_file_fn(analyzer.filepath, analyzer.adapter, analyzer.r2, logger=logger):
            return False
        info_cmd = analyzer._cmdj("ij", {})
        if isinstance(info_cmd, dict):
            bin_info = info_cmd.get("bin", {})
            if isinstance(bin_info, dict):
                format_text = str(bin_info.get("format", "")).lower()
                class_text = str(bin_info.get("class", "")).lower()
                if (
                    (format_text or class_text)
                    and "elf" not in format_text
                    and "elf" not in class_text
                ):
                    return False
        return bool(analyzer._has_elf_symbols(info_cmd))
    except Exception as exc:
        logger.error("Error checking if file is ELF: %s", exc)
        return False
