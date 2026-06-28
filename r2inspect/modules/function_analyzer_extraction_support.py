"""Extraction and fallback helpers for function analysis."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Protocol

from ..abstractions.coercion_support import coerce_int_or_none
from ..domain.constants import HUGE_FILE_THRESHOLD_MB, VERY_LARGE_FILE_THRESHOLD_MB
from ..domain.services.function_analysis import extract_mnemonics_from_text
from ..domain.text_helpers import has_text
from ..interfaces.binary_analyzer import BinaryAnalyzerInterface
from .disasm_ops_support import extract_pdfj_ops, normalize_pdj_disasm

logger = logging.getLogger(__name__)


class FunctionExtractionHost(Protocol):
    """Overridable collaboration contract the extraction helpers depend on."""

    adapter: BinaryAnalyzerInterface | None

    def _cmd(self, command: str) -> str: ...
    def _cmd_list(self, command: str) -> list[Any]: ...
    def _cmdj(self, command: str, default: Any | None = None) -> Any: ...
    def _extract_mnemonics_from_ops(self, ops: list[dict[str, Any]]) -> list[str]: ...
    def _try_pdfj_extraction(self, func_name: str, func_addr: int) -> list[str]: ...
    def _try_pdj_extraction(self, func_name: str, func_size: int, func_addr: int) -> list[str]: ...
    def _try_basic_pdj_extraction(self, func_name: str, func_addr: int) -> list[str]: ...
    def _try_pi_extraction(self, func_name: str, func_addr: int) -> list[str]: ...


def coerce_positive_int(value: Any) -> int:
    try:
        parsed = int(value, 0) if isinstance(value, str) else int(value or 0)
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


def file_size_mb_from_adapter(adapter: Any) -> float | None:
    """File size in MiB from the adapter's ``ij`` core info, or None if unknown."""
    if adapter is None:
        return None
    core = adapter.get_file_info().get("core", {})
    size = coerce_int_or_none(core.get("size")) if isinstance(core, dict) else None
    return size / (1024 * 1024) if size else None


def _deep_analysis_enabled(config: Any | None) -> bool:
    try:
        return bool(
            config
            and getattr(config, "typed_config", None)
            and config.typed_config.analysis.deep_analysis
        )
    except (AttributeError, TypeError, ValueError, RuntimeError) as exc:
        logger.debug("Error checking deep analysis flag: %s", exc)
        return False


def should_run_full_analysis(config: Any | None, file_size_mb: float | None) -> bool:
    if _deep_analysis_enabled(config):
        return True
    if file_size_mb is not None:
        return file_size_mb <= VERY_LARGE_FILE_THRESHOLD_MB
    return True


def should_run_byte_scans(config: Any | None, file_size_mb: float | None) -> bool:
    """Whether to run whole-binary ``/x`` hex scans (crypto constants, packer
    signatures).

    Each such scan walks the entire file once per pattern, so above
    ``HUGE_FILE_THRESHOLD_MB`` they dominate runtime (tens of seconds on a
    100 MB+ binary). Skip them there -- consistent with the >50 MB auto-analysis
    skip -- unless deep analysis is explicitly requested.
    """
    if _deep_analysis_enabled(config):
        return True
    if file_size_mb is not None:
        return file_size_mb <= HUGE_FILE_THRESHOLD_MB
    return True


def extract_function_mnemonics(
    analyzer: FunctionExtractionHost, func_name: str, func_size: int, func_addr: int
) -> list[str]:
    func_size = coerce_positive_int(func_size)
    mnemonics = analyzer._try_pdfj_extraction(func_name, func_addr)
    if mnemonics:
        return mnemonics
    if func_size > 0:
        mnemonics = analyzer._try_pdj_extraction(func_name, func_size, func_addr)
        if mnemonics:
            return mnemonics
    mnemonics = analyzer._try_basic_pdj_extraction(func_name, func_addr)
    if mnemonics:
        return mnemonics
    return analyzer._try_pi_extraction(func_name, func_addr)


def try_pdfj_extraction(
    analyzer: FunctionExtractionHost, func_name: str, func_addr: int, logger: logging.Logger
) -> list[str]:
    try:
        ops_source = extract_pdfj_ops(analyzer, func_addr)
        if ops_source:
            logger.debug("pdfj succeeded for %s, got %s instructions", func_name, len(ops_source))
            return analyzer._extract_mnemonics_from_ops(ops_source)
    except Exception as exc:
        logger.debug("pdfj failed for %s: %s", func_name, str(exc))
    return []


def try_pdj_extraction(
    analyzer: FunctionExtractionHost,
    func_name: str,
    func_size: int,
    func_addr: int,
    logger: logging.Logger,
) -> list[str]:
    try:
        max_instructions = min(func_size // 4, 1000)
        disasm_list = (
            analyzer.adapter.get_disasm(address=func_addr, size=max_instructions)
            if analyzer.adapter is not None and hasattr(analyzer.adapter, "get_disasm")
            else analyzer._cmd_list(f"pdj {max_instructions} @ {func_addr}")
        )
        disasm_source = normalize_pdj_disasm(disasm_list)
        if disasm_source:
            logger.debug("pdj succeeded for %s, got %s instructions", func_name, len(disasm_source))
            return analyzer._extract_mnemonics_from_ops(disasm_source)
    except Exception as exc:
        logger.debug("pdj failed for %s: %s", func_name, str(exc))
    return []


def try_basic_pdj_extraction(
    analyzer: FunctionExtractionHost, func_name: str, func_addr: int, logger: logging.Logger
) -> list[str]:
    try:
        disasm_list = (
            analyzer.adapter.get_disasm(address=func_addr, size=50)
            if analyzer.adapter is not None and hasattr(analyzer.adapter, "get_disasm")
            else analyzer._cmd_list(f"pdj 50 @ {func_addr}")
        )
        disasm_source = normalize_pdj_disasm(disasm_list)
        if disasm_source:
            logger.debug(
                "Basic pdj succeeded for %s, got %s instructions",
                func_name,
                len(disasm_source),
            )
            return analyzer._extract_mnemonics_from_ops(disasm_source)
    except Exception as exc:
        logger.debug("Basic pdj failed for %s: %s", func_name, str(exc))
    return []


def try_pi_extraction(
    analyzer: FunctionExtractionHost, func_name: str, func_addr: int, logger: logging.Logger
) -> list[str]:
    try:
        instructions_text = analyzer._cmd(f"pi 100 @ {func_addr}")
        if has_text(instructions_text):
            logger.debug(
                "pi succeeded for %s, got %s instruction lines",
                func_name,
                len(instructions_text.strip().split("\n")),
            )
            return extract_mnemonics_from_text(instructions_text)
    except Exception as exc:
        logger.debug("pi failed for %s: %s", func_name, str(exc))
    return []
