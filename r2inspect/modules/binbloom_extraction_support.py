"""Mnemonic extraction helpers for Binbloom analysis."""

from __future__ import annotations

from typing import Any, cast


def extract_instruction_mnemonics(
    analyzer: Any, func_addr: int, func_name: str, logger: Any
) -> list[str]:
    try:
        instructions = analyzer._extract_mnemonics_from_pdfj(func_addr, func_name)
        if instructions:
            return cast(list[str], instructions)

        instructions = analyzer._extract_mnemonics_from_pdj(func_addr, func_name)
        if instructions:
            return cast(list[str], instructions)

        instructions = analyzer._extract_mnemonics_from_text(func_addr, func_name)
        if instructions:
            return cast(list[str], instructions)
    except Exception as exc:
        logger.debug("Error extracting mnemonics from %s: %s", func_name, exc)

    return []


def extract_mnemonics_from_pdfj(
    analyzer: Any, func_addr: int, func_name: str, logger: Any
) -> list[str]:
    disasm = (
        analyzer.adapter.get_disasm(address=func_addr)
        if analyzer.adapter is not None and hasattr(analyzer.adapter, "get_disasm")
        else analyzer._cmdj("pdfj", {})
    )
    if not disasm or "ops" not in disasm:
        return []
    mnemonics = analyzer._collect_mnemonics_from_ops(disasm["ops"])
    if mnemonics:
        logger.debug("Extracted %s mnemonics from %s using pdfj", len(mnemonics), func_name)
    return cast(list[str], mnemonics)


def extract_mnemonics_from_pdj(
    analyzer: Any, func_addr: int, func_name: str, logger: Any
) -> list[str]:
    disasm_list = (
        analyzer.adapter.get_disasm(address=func_addr, size=200)
        if analyzer.adapter is not None and hasattr(analyzer.adapter, "get_disasm")
        else analyzer._cmd_list("pdj 200")
    )
    if not isinstance(disasm_list, list):
        return []
    mnemonics = analyzer._collect_mnemonics_from_ops(disasm_list)
    if mnemonics:
        logger.debug("Extracted %s mnemonics from %s using pdj", len(mnemonics), func_name)
    return cast(list[str], mnemonics)


def extract_mnemonics_from_text(
    analyzer: Any, func_addr: int, func_name: str, logger: Any
) -> list[str]:
    instructions_text = (
        analyzer.adapter.get_disasm_text(address=func_addr, size=100)
        if analyzer.adapter is not None and hasattr(analyzer.adapter, "get_disasm_text")
        else analyzer._cmd("pi 100")
    )
    if not instructions_text or not instructions_text.strip():
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
