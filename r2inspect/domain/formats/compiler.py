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
    string_haystack: str | None = None,
) -> float:
    string_score, string_max = _check_string_signatures(
        signatures, strings_data, haystack=string_haystack
    )
    import_score, import_max = _check_import_signatures(signatures, imports_data)
    section_score, section_max = _check_section_signatures(signatures, sections_data)
    symbol_score, symbol_max = _check_symbol_signatures(signatures, symbols_data)

    score = string_score + import_score + section_score + symbol_score
    max_score = string_max + import_max + section_max + symbol_max
    if max_score > 0:
        return min(score / max_score, 1.0)
    return 0.0


_COMPILER_METHOD: dict[str, str] = {
    "MSVC": "Runtime library analysis",
    "GCC": "Symbol and section analysis",
    "Clang": "Symbol and section analysis",
    "DotNet": "CLR metadata analysis",
    "AutoIt": "AU3 signature and string analysis",
    "NSIS": "Installer signature analysis",
    "InnoSetup": "Installer signature analysis",
    "PyInstaller": "Python runtime detection",
    "cx_Freeze": "Python runtime detection",
    "Nim": "Nim runtime and symbol analysis",
    "Zig": "Modern compiler signature analysis",
    "Swift": "Modern compiler signature analysis",
    "TinyCC": "Modern compiler signature analysis",
    "NodeJS": "Node.js runtime detection",
    "FASM": "Assembly tool signature",
}


def _confidence_label(score: float) -> str:
    if score > 0.8:
        return "High confidence - Multiple signatures matched"
    if score > 0.6:
        return "Medium confidence - Some signatures matched"
    return "Low confidence - Few signatures matched"


def detection_method(compiler: str, score: float) -> str:
    methods = [_confidence_label(score)]
    compiler_method = _COMPILER_METHOD.get(compiler)
    if compiler_method is not None:
        methods.append(compiler_method)
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
        libname = imp.get("libname")
        name = imp.get("name")
        if isinstance(libname, str):
            imports.append(libname)
        if isinstance(name, str):
            imports.append(name)
    return imports


def extract_section_names(sections_data: list[dict[str, Any]]) -> list[str]:
    sections: list[str] = []
    for section in sections_data:
        if isinstance(section, dict) and isinstance(section.get("name"), str):
            sections.append(section["name"])
    return sections


def extract_symbol_names(symbols_data: list[dict[str, Any]]) -> list[str]:
    symbols: list[str] = []
    for symbol in symbols_data:
        if isinstance(symbol, dict) and isinstance(symbol.get("name"), str):
            symbols.append(symbol["name"])
    return symbols


def _check_string_signatures(
    signatures: dict[str, Any], strings_data: list[str], *, haystack: str | None = None
) -> tuple[float, float]:
    # An empty (or absent) signature list contributes nothing — counting its
    # weight in max_score would dilute the score so that string-only compilers
    # (and any category left as []) could never reach the detection threshold.
    if not signatures.get("strings"):
        return 0.0, 0.0

    score = 0.0
    max_score = 3.0

    # Search the joined string blob once per pattern instead of re-running each
    # pattern against every extracted string: a large binary yields hundreds of
    # thousands of strings, so the per-string loop was the dominant analysis
    # cost. None of the signatures are anchored and the search has no DOTALL, so
    # "pattern matches the newline-joined blob" is equivalent to "pattern
    # matches some individual string". The caller may pass a precomputed
    # haystack so the multi-MB join isn't repeated for every compiler.
    if haystack is None:
        if not strings_data:
            return score, max_score
        haystack = "\n".join(string for string in strings_data if isinstance(string, str))
    for pattern in signatures["strings"]:
        if not isinstance(pattern, str):
            continue
        if re.search(pattern, haystack, re.IGNORECASE):
            score += 3.0 / len(signatures["strings"])

    return score, max_score


def _check_import_signatures(
    signatures: dict[str, Any], imports_data: list[str]
) -> tuple[float, float]:
    if not signatures.get("imports"):
        return 0.0, 0.0

    score = 0.0
    max_score = 2.0

    for import_name in signatures["imports"]:
        if not isinstance(import_name, str):
            continue
        if any(isinstance(imp, str) and import_name.lower() in imp.lower() for imp in imports_data):
            score += 2.0 / len(signatures["imports"])

    return score, max_score


def _check_section_signatures(
    signatures: dict[str, Any], sections_data: list[str]
) -> tuple[float, float]:
    if not signatures.get("sections"):
        return 0.0, 0.0

    score = 0.0
    max_score = 1.0

    for section_name in signatures["sections"]:
        if not isinstance(section_name, str):
            continue
        if any(
            isinstance(sec, str) and section_name.lower() in sec.lower() for sec in sections_data
        ):
            score += 1.0 / len(signatures["sections"])

    return score, max_score


def _check_symbol_signatures(
    signatures: dict[str, Any], symbols_data: list[str]
) -> tuple[float, float]:
    if not signatures.get("symbols"):
        return 0.0, 0.0

    score = 0.0
    max_score = 1.0

    for symbol_name in signatures["symbols"]:
        if not isinstance(symbol_name, str):
            continue
        if any(isinstance(sym, str) and symbol_name.lower() in sym.lower() for sym in symbols_data):
            score += 1.0 / len(signatures["symbols"])

    return score, max_score
