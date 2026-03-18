"""Extraction and fallback helpers for function analysis."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, cast

from ..domain.constants import VERY_LARGE_FILE_THRESHOLD_MB
from ..domain.services.function_analysis import extract_mnemonics_from_text


def coerce_positive_int(value: Any) -> int:
    try:
        parsed = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return parsed if parsed > 0 else 0


def get_file_size_mb(filename: str | None) -> float | None:
    if not filename:
        return None
    try:
        return Path(filename).stat().st_size / (1024 * 1024)
    except OSError:
        return None


def should_run_full_analysis(config: Any | None, file_size_mb: float | None) -> bool:
    try:
        if config and getattr(config, "typed_config", None):
            if config.typed_config.analysis.deep_analysis:
                return True
    except (AttributeError, TypeError, ValueError, RuntimeError):
        pass
    if file_size_mb is not None:
        return file_size_mb <= VERY_LARGE_FILE_THRESHOLD_MB
    return True


def extract_function_mnemonics(
    analyzer: Any, func_name: str, func_size: int, func_addr: int
) -> list[str]:
    func_size = coerce_positive_int(func_size)
    mnemonics = analyzer._try_pdfj_extraction(func_name, func_addr)
    if mnemonics:
        return cast(list[str], mnemonics)
    if func_size > 0:
        mnemonics = analyzer._try_pdj_extraction(func_name, func_size, func_addr)
        if mnemonics:
            return cast(list[str], mnemonics)
    mnemonics = analyzer._try_basic_pdj_extraction(func_name, func_addr)
    if mnemonics:
        return cast(list[str], mnemonics)
    return cast(list[str], analyzer._try_pi_extraction(func_name, func_addr))


def try_pdfj_extraction(
    analyzer: Any, func_name: str, func_addr: int, logger: logging.Logger
) -> list[str]:
    try:
        disasm = (
            analyzer.adapter.get_disasm(address=func_addr)
            if analyzer.adapter is not None and hasattr(analyzer.adapter, "get_disasm")
            else analyzer._cmdj(f"pdfj @ {func_addr}", {})
        )
        if isinstance(disasm, dict) and "ops" in disasm:
            logger.debug(
                "pdfj succeeded for %s, got %s instructions", func_name, len(disasm["ops"])
            )
            return cast(list[str], analyzer._extract_mnemonics_from_ops(disasm["ops"]))
    except Exception as exc:
        logger.debug("pdfj failed for %s: %s", func_name, str(exc))
    return []


def try_pdj_extraction(
    analyzer: Any, func_name: str, func_size: int, func_addr: int, logger: logging.Logger
) -> list[str]:
    try:
        max_instructions = min(func_size // 4, 1000)
        disasm_list = (
            analyzer.adapter.get_disasm(address=func_addr, size=max_instructions)
            if analyzer.adapter is not None and hasattr(analyzer.adapter, "get_disasm")
            else analyzer._cmd_list(f"pdj {max_instructions} @ {func_addr}")
        )
        if isinstance(disasm_list, list):
            logger.debug("pdj succeeded for %s, got %s instructions", func_name, len(disasm_list))
            return cast(list[str], analyzer._extract_mnemonics_from_ops(disasm_list))
    except Exception as exc:
        logger.debug("pdj failed for %s: %s", func_name, str(exc))
    return []


def try_basic_pdj_extraction(
    analyzer: Any, func_name: str, func_addr: int, logger: logging.Logger
) -> list[str]:
    try:
        disasm_list = (
            analyzer.adapter.get_disasm(address=func_addr, size=50)
            if analyzer.adapter is not None and hasattr(analyzer.adapter, "get_disasm")
            else analyzer._cmd_list(f"pdj 50 @ {func_addr}")
        )
        if isinstance(disasm_list, list):
            logger.debug(
                "Basic pdj succeeded for %s, got %s instructions",
                func_name,
                len(disasm_list),
            )
            return cast(list[str], analyzer._extract_mnemonics_from_ops(disasm_list))
    except Exception as exc:
        logger.debug("Basic pdj failed for %s: %s", func_name, str(exc))
    return []


def try_pi_extraction(
    analyzer: Any, func_name: str, func_addr: int, logger: logging.Logger
) -> list[str]:
    try:
        instructions_text = analyzer._cmd(f"pi 100 @ {func_addr}")
        if instructions_text and instructions_text.strip():
            logger.debug(
                "pi succeeded for %s, got %s instruction lines",
                func_name,
                len(instructions_text.strip().split("\n")),
            )
            return extract_mnemonics_from_text(instructions_text)
    except Exception as exc:
        logger.debug("pi failed for %s: %s", func_name, str(exc))
    return []
