"""Mnemonic extraction helpers for Binbloom analysis."""

from __future__ import annotations

import logging
from typing import Any, Protocol

from ..interfaces.binary_analyzer import BinaryAnalyzerInterface
from .disasm_ops_support import extract_pdfj_ops, normalize_pdj_disasm


class MnemonicHost(Protocol):
    """Overridable collaboration contract the Binbloom mnemonic helpers depend on."""

    adapter: BinaryAnalyzerInterface | None

    def _cmd(self, command: str) -> str: ...
    def _cmdj(self, command: str, default: Any | None = None) -> Any: ...
    def _cmd_list(self, command: str) -> list[Any]: ...
    def _collect_mnemonics_from_ops(self, ops: list[Any]) -> list[str]: ...
    def _normalize_mnemonic(self, mnemonic: str | None) -> str | None: ...
    def _extract_mnemonics_from_pdfj(self, func_addr: int, func_name: str) -> list[str]: ...
    def _extract_mnemonics_from_pdj(self, func_addr: int, func_name: str) -> list[str]: ...
    def _extract_mnemonics_from_text(self, func_addr: int, func_name: str) -> list[str]: ...


def extract_instruction_mnemonics(
    analyzer: MnemonicHost, func_addr: int, func_name: str, logger: logging.Logger
) -> list[str]:
    try:
        instructions = analyzer._extract_mnemonics_from_pdfj(func_addr, func_name)
        if instructions:
            return instructions

        instructions = analyzer._extract_mnemonics_from_pdj(func_addr, func_name)
        if instructions:
            return instructions

        instructions = analyzer._extract_mnemonics_from_text(func_addr, func_name)
        if instructions:
            return instructions
    except Exception as exc:
        logger.debug("Error extracting mnemonics from %s: %s", func_name, exc)

    return []


def extract_mnemonics_from_pdfj(
    analyzer: MnemonicHost, func_addr: int, func_name: str, logger: logging.Logger
) -> list[str]:
    ops_source = extract_pdfj_ops(analyzer, func_addr)
    if not ops_source:
        return []
    mnemonics = analyzer._collect_mnemonics_from_ops(ops_source)
    if mnemonics:
        logger.debug("Extracted %s mnemonics from %s using pdfj", len(mnemonics), func_name)
    return mnemonics


def extract_mnemonics_from_pdj(
    analyzer: MnemonicHost, func_addr: int, func_name: str, logger: logging.Logger
) -> list[str]:
    disasm_list = (
        analyzer.adapter.get_disasm(address=func_addr, size=200)
        if analyzer.adapter is not None and hasattr(analyzer.adapter, "get_disasm")
        else analyzer._cmd_list(f"pdj 200 @ {func_addr}")
    )
    mnemonics = analyzer._collect_mnemonics_from_ops(normalize_pdj_disasm(disasm_list))
    if mnemonics:
        logger.debug("Extracted %s mnemonics from %s using pdj", len(mnemonics), func_name)
    return mnemonics


def extract_mnemonics_from_text(
    analyzer: MnemonicHost, func_addr: int, func_name: str, logger: logging.Logger
) -> list[str]:
    instructions_text = (
        analyzer.adapter.get_disasm_text(address=func_addr, size=100)
        if analyzer.adapter is not None and hasattr(analyzer.adapter, "get_disasm_text")
        else analyzer._cmd(f"pi 100 @ {func_addr}")
    )
    if not isinstance(instructions_text, str) or not instructions_text.strip():
        return []

    mnemonics: list[str] = []
    for line in instructions_text.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        clean_mnemonic = analyzer._normalize_mnemonic(line.split()[0])
        if clean_mnemonic:
            mnemonics.append(clean_mnemonic)

    if mnemonics:
        logger.debug("Extracted %s mnemonics from %s using pi", len(mnemonics), func_name)
    return mnemonics
