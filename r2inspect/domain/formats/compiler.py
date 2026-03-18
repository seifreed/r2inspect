#!/usr/bin/env python3
"""Compiler detection domain helpers."""

from __future__ import annotations

import re
from typing import Any


def calculate_compiler_score(
    signatures: dict[str, Any],
    strings_data: list[str],
    imports_data: list[str],
    sections_data: list[str],
    symbols_data: list[str],
) -> float:
    string_score, string_max = _check_string_signatures(signatures, strings_data)
    import_score, import_max = _check_import_signatures(signatures, imports_data)
    section_score, section_max = _check_section_signatures(signatures, sections_data)
    symbol_score, symbol_max = _check_symbol_signatures(signatures, symbols_data)

    score = string_score + import_score + section_score + symbol_score
    max_score = string_max + import_max + section_max + symbol_max
    if max_score > 0:
        return min(score / max_score, 1.0)
    return 0.0


def detection_method(compiler: str, score: float) -> str:
    methods = []
    if score > 0.8:
        methods.append("High confidence - Multiple signatures matched")
    elif score > 0.6:
        methods.append("Medium confidence - Some signatures matched")
    else:
        methods.append("Low confidence - Few signatures matched")

    if compiler == "MSVC":
        methods.append("Runtime library analysis")
    elif compiler in ["GCC", "Clang"]:
        methods.append("Symbol and section analysis")
    elif compiler == "DotNet":
        methods.append("CLR metadata analysis")
    elif compiler == "AutoIt":
        methods.append("AU3 signature and string analysis")
    elif compiler in ["NSIS", "InnoSetup"]:
        methods.append("Installer signature analysis")
    elif compiler in ["PyInstaller", "cx_Freeze"]:
        methods.append("Python runtime detection")
    elif compiler == "Nim":
        methods.append("Nim runtime and symbol analysis")
    elif compiler in ["Zig", "Swift", "TinyCC"]:
        methods.append("Modern compiler signature analysis")
    elif compiler == "NodeJS":
        methods.append("Node.js runtime detection")
    elif compiler == "FASM":
        methods.append("Assembly tool signature")

    return " | ".join(methods)


def map_msvc_version_from_rich(compiler_name: str) -> str:
    if "2019" in compiler_name:
        return "Visual Studio 2019"
    if "2022" in compiler_name:
        return "Visual Studio 2022"
    if "1900" in compiler_name:
        return "Visual Studio 2015"
    if "1910" in compiler_name:
        return "Visual Studio 2017"
    return "Visual Studio (version from Rich Header)"


def detect_msvc_version(
    strings_data: list[str], imports_data: list[str], versions: dict[str, str]
) -> str:
    for import_name in imports_data:
        if import_name in versions:
            return versions[import_name]
    for string in strings_data:
        match = re.search(r"Microsoft.*Visual.*C\+\+.*(\d+\.\d+)", string, re.IGNORECASE)
        if match:
            return f"Visual Studio {match.group(1)}"
    return "Unknown"


def detect_gcc_version(strings_data: list[str]) -> str:
    for string in strings_data:
        match = re.search(r"GCC.*(\d+\.\d+\.\d+)", string, re.IGNORECASE)
        if match:
            return f"GCC {match.group(1)}"
        match = re.search(r"GNU.*(\d+\.\d+)", string, re.IGNORECASE)
        if match:
            return f"GCC {match.group(1)}"
    return "Unknown"


def detect_clang_version(strings_data: list[str]) -> str:
    for string in strings_data:
        match = re.search(r"clang.*(\d+\.\d+\.\d+)", string, re.IGNORECASE)
        if match:
            return f"Clang {match.group(1)}"
        match = re.search(r"Apple.*clang.*(\d+\.\d+)", string, re.IGNORECASE)
        if match:
            return f"Apple Clang {match.group(1)}"
    return "Unknown"


def detect_go_version(strings_data: list[str]) -> str:
    for string in strings_data:
        match = re.search(r"go(\d+\.\d+\.\d+)", string, re.IGNORECASE)
        if match:
            return f"Go {match.group(1)}"
    return "Unknown"


def detect_rust_version(strings_data: list[str]) -> str:
    for string in strings_data:
        match = re.search(r"rustc.*(\d+\.\d+\.\d+)", string, re.IGNORECASE)
        if match:
            return f"Rust {match.group(1)}"
    return "Unknown"


def parse_strings_output(strings_output: str) -> list[str]:
    strings = []
    for line in strings_output.split("\n"):
        if line.strip():
            parts = line.split(" ", 4)
            if len(parts) >= 5:
                strings.append(parts[4].strip())
    return strings


def extract_import_names(imports_data: list[dict[str, Any]]) -> list[str]:
    imports: list[str] = []
    for imp in imports_data:
        if "libname" in imp:
            imports.append(imp["libname"])
        if "name" in imp:
            imports.append(imp["name"])
    return imports


def extract_section_names(sections_data: list[dict[str, Any]]) -> list[str]:
    sections: list[str] = []
    for section in sections_data:
        if isinstance(section, dict) and "name" in section:
            sections.append(section["name"])
    return sections


def extract_symbol_names(symbols_data: list[dict[str, Any]]) -> list[str]:
    symbols: list[str] = []
    for symbol in symbols_data:
        if isinstance(symbol, dict) and "name" in symbol:
            symbols.append(symbol["name"])
    return symbols


def _check_string_signatures(
    signatures: dict[str, Any], strings_data: list[str]
) -> tuple[float, float]:
    if "strings" not in signatures:
        return 0.0, 0.0

    score = 0.0
    max_score = 3.0

    for pattern in signatures["strings"]:
        for string in strings_data:
            if re.search(pattern, string, re.IGNORECASE):
                score += 3.0 / len(signatures["strings"])
                break

    return score, max_score


def _check_import_signatures(
    signatures: dict[str, Any], imports_data: list[str]
) -> tuple[float, float]:
    if "imports" not in signatures:
        return 0.0, 0.0

    score = 0.0
    max_score = 2.0

    for import_name in signatures["imports"]:
        if any(import_name.lower() in imp.lower() for imp in imports_data):
            score += 2.0 / len(signatures["imports"])

    return score, max_score


def _check_section_signatures(
    signatures: dict[str, Any], sections_data: list[str]
) -> tuple[float, float]:
    if "sections" not in signatures:
        return 0.0, 0.0

    score = 0.0
    max_score = 1.0

    for section_name in signatures["sections"]:
        if any(section_name.lower() in sec.lower() for sec in sections_data):
            score += 1.0 / len(signatures["sections"])

    return score, max_score


def _check_symbol_signatures(
    signatures: dict[str, Any], symbols_data: list[str]
) -> tuple[float, float]:
    if "symbols" not in signatures:
        return 0.0, 0.0

    score = 0.0
    max_score = 1.0

    for symbol_name in signatures["symbols"]:
        if any(symbol_name.lower() in sym.lower() for sym in symbols_data):
            score += 1.0 / len(signatures["symbols"])

    return score, max_score
