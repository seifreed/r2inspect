#!/usr/bin/env python3
"""Branch-path tests for r2inspect/modules/compiler_detector.py.

Covers missing lines: 88, 102-104, 117-122, 125, 156, 184-189, 197-201,
208-210, 217-219, 226-228, 239, 243, 250-252, 287, 291, 295, 303, 307,
311, 316, 329, 334, 339.
"""

from __future__ import annotations

from typing import Any

import pytest

from r2inspect.modules.compiler_detector import CompilerDetector


# ---------------------------------------------------------------------------
# Adapter helpers (plain Python classes - no mocks)
# ---------------------------------------------------------------------------


class _MinimalAdapter:
    """Adapter that satisfies the expected interface with minimal data."""

    def __init__(
        self,
        file_info: dict | None = None,
        imports: list | None = None,
        sections: list | None = None,
        symbols: list | None = None,
        strings: list | None = None,
    ) -> None:
        self._file_info = file_info or {}
        self._imports = imports or []
        self._sections = sections or []
        self._symbols = symbols or []
        self._strings = strings or []

    def get_file_info(self) -> dict:
        return self._file_info

    def get_imports(self) -> list:
        return self._imports

    def get_sections(self) -> list:
        return self._sections

    def get_symbols(self) -> list:
        return self._symbols

    def get_strings(self) -> list:
        return self._strings


class _RaisingFileInfoAdapter(_MinimalAdapter):
    """Adapter whose get_file_info raises - triggers error in _get_file_format."""

    def get_file_info(self) -> dict:
        raise RuntimeError("simulated file info error")


class _RaisingImportsAdapter(_MinimalAdapter):
    """Adapter whose get_imports raises - triggers error in _get_imports."""

    def get_imports(self) -> list:
        raise RuntimeError("simulated imports error")


class _RaisingSectionsAdapter(_MinimalAdapter):
    """Adapter whose get_sections raises - triggers error in _get_sections."""

    def get_sections(self) -> list:
        raise RuntimeError("simulated sections error")


class _RaisingSymbolsAdapter(_MinimalAdapter):
    """Adapter whose get_symbols raises - triggers error in _get_symbols."""

    def get_symbols(self) -> list:
        raise RuntimeError("simulated symbols error")


class _RaisingStringsAdapter(_MinimalAdapter):
    """Adapter whose get_strings raises - triggers error in _get_strings."""

    def get_strings(self) -> list:
        raise RuntimeError("simulated strings error")


class _AdapterWithoutStrings:
    """Adapter without get_strings - forces fallback to _get_strings_raw."""

    def get_file_info(self) -> dict:
        return {}

    def get_imports(self) -> list:
        return []

    def get_sections(self) -> list:
        return []

    def get_symbols(self) -> list:
        return []


# ---------------------------------------------------------------------------
# Detector subclasses for controlled rich-header paths (no mocks)
# ---------------------------------------------------------------------------


class _MsvcRichHeaderDetector(CompilerDetector):
    """Override _analyze_rich_header to return an MSVC compiler entry."""

    def _analyze_rich_header(self) -> dict[str, Any]:
        return {
            "available": True,
            "compilers": [{"compiler_name": "Utc1900_CPP"}],
        }


class _NonMsvcRichHeaderDetector(CompilerDetector):
    """Override _analyze_rich_header to return a non-MSVC compiler entry."""

    def _analyze_rich_header(self) -> dict[str, Any]:
        return {
            "available": True,
            "compilers": [{"compiler_name": "GCC"}],
        }


class _EmptyRichHeaderDetector(CompilerDetector):
    """Override _analyze_rich_header to return empty/unavailable result."""

    def _analyze_rich_header(self) -> dict[str, Any]:
        return {"available": False}


class _RaisingRichHeaderDetector(CompilerDetector):
    """Override _get_file_format to raise - triggers detect_compiler error handler."""

    def _get_file_format(self) -> str:
        raise RuntimeError("simulated format detection error")


class _RaisingAnalyzeRichDetector(CompilerDetector):
    """Override _get_file_info to raise inside _analyze_rich_header."""

    def _get_file_info(self) -> dict[str, Any]:
        raise RuntimeError("simulated rich header analysis error")


# ---------------------------------------------------------------------------
# detect_compiler - line 88: early return after rich-header hit for PE
# ---------------------------------------------------------------------------


def test_detect_compiler_returns_early_when_rich_header_detects_msvc():
    pe_adapter = _MinimalAdapter(
        file_info={"bin": {"class": "PE32"}},
    )
    detector = _MsvcRichHeaderDetector(pe_adapter)
    result = detector.detect_compiler()
    assert result["detected"] is True
    assert result["compiler"] == "MSVC"
    assert result["confidence"] == 0.95


# ---------------------------------------------------------------------------
# detect_compiler - lines 102-104: exception handler
# ---------------------------------------------------------------------------


def test_detect_compiler_exception_stored_in_result():
    detector = _RaisingRichHeaderDetector(_MinimalAdapter())
    result = detector.detect_compiler()
    assert "error" in result
    assert "simulated format detection error" in result["error"]


# ---------------------------------------------------------------------------
# _apply_rich_header_detection - lines 117-122, 125: MSVC/Utc detection path
# ---------------------------------------------------------------------------


def test_apply_rich_header_detection_msvc_compiler_sets_results():
    detector = _MinimalAdapter()
    cd = CompilerDetector(detector)
    results: dict[str, Any] = {
        "detected": False,
        "compiler": "Unknown",
        "confidence": 0.0,
        "version": "Unknown",
        "details": {},
        "signatures_found": [],
        "rich_header_info": {},
    }
    rich_header = {
        "available": True,
        "compilers": [{"compiler_name": "Utc1900_C"}],
    }
    # Replace _analyze_rich_header via subclass technique on a fresh instance
    class _SubDetector(CompilerDetector):
        def _analyze_rich_header(self) -> dict[str, Any]:
            return rich_header

    sub = _SubDetector(detector)
    returned = sub._apply_rich_header_detection(results)
    assert returned is True
    assert results["detected"] is True
    assert results["compiler"] == "MSVC"


def test_apply_rich_header_detection_utc_name_variant_triggers_msvc():
    class _UtcVariant(CompilerDetector):
        def _analyze_rich_header(self) -> dict[str, Any]:
            return {
                "available": True,
                "compilers": [{"compiler_name": "MSVC_2022_CPP"}],
            }

    cd = _UtcVariant(_MinimalAdapter())
    results: dict[str, Any] = {
        "detected": False, "compiler": "", "confidence": 0.0,
        "version": "", "details": {}, "signatures_found": [], "rich_header_info": {},
    }
    assert cd._apply_rich_header_detection(results) is True


def test_apply_rich_header_detection_non_msvc_compiler_returns_false():
    class _GccRich(CompilerDetector):
        def _analyze_rich_header(self) -> dict[str, Any]:
            return {
                "available": True,
                "compilers": [{"compiler_name": "GCC"}],
            }

    cd = _GccRich(_MinimalAdapter())
    results: dict[str, Any] = {}
    assert cd._apply_rich_header_detection(results) is False


# ---------------------------------------------------------------------------
# _apply_best_compiler - line 156: empty scores early return
# ---------------------------------------------------------------------------


def test_apply_best_compiler_with_empty_scores_does_nothing():
    cd = CompilerDetector(_MinimalAdapter())
    results: dict[str, Any] = {}
    cd._apply_best_compiler(results, {}, [], [], "PE")
    assert "detected" not in results


# ---------------------------------------------------------------------------
# _get_file_format - lines 184-185: Mach-O case; lines 187-189: exception
# ---------------------------------------------------------------------------


def test_get_file_format_returns_macho_for_mach_class():
    adapter = _MinimalAdapter(file_info={"bin": {"class": "MACH064"}})
    cd = CompilerDetector(adapter)
    assert cd._get_file_format() == "Mach-O"


def test_get_file_format_returns_unknown_on_exception():
    adapter = _RaisingFileInfoAdapter()
    cd = CompilerDetector(adapter)
    assert cd._get_file_format() == "Unknown"


# ---------------------------------------------------------------------------
# _get_strings - lines 197-198: fallback path; lines 199-201: exception
# ---------------------------------------------------------------------------


def test_get_strings_falls_back_to_raw_when_no_get_strings_method():
    adapter = _AdapterWithoutStrings()
    cd = CompilerDetector(adapter)
    # With no r2 pipe, raw strings will be empty, but no exception should occur.
    result = cd._get_strings()
    assert isinstance(result, list)


def test_get_strings_returns_empty_list_on_exception():
    adapter = _RaisingStringsAdapter()
    cd = CompilerDetector(adapter)
    result = cd._get_strings()
    assert result == []


# ---------------------------------------------------------------------------
# _get_imports - lines 208-210: exception handler
# ---------------------------------------------------------------------------


def test_get_imports_returns_empty_list_on_exception():
    adapter = _RaisingImportsAdapter()
    cd = CompilerDetector(adapter)
    result = cd._get_imports()
    assert result == []


# ---------------------------------------------------------------------------
# _get_sections - lines 217-219: exception handler
# ---------------------------------------------------------------------------


def test_get_sections_returns_empty_list_on_exception():
    adapter = _RaisingSectionsAdapter()
    cd = CompilerDetector(adapter)
    result = cd._get_sections()
    assert result == []


# ---------------------------------------------------------------------------
# _get_symbols - lines 226-228: exception handler
# ---------------------------------------------------------------------------


def test_get_symbols_returns_empty_list_on_exception():
    adapter = _RaisingSymbolsAdapter()
    cd = CompilerDetector(adapter)
    result = cd._get_symbols()
    assert result == []


# ---------------------------------------------------------------------------
# _analyze_rich_header - line 239: return {} when no file_info/core
# ---------------------------------------------------------------------------


def test_analyze_rich_header_returns_empty_when_no_core_in_file_info():
    adapter = _MinimalAdapter(file_info={"bin": {"class": "PE32"}})
    cd = CompilerDetector(adapter)
    result = cd._analyze_rich_header()
    assert result == {}


# ---------------------------------------------------------------------------
# _analyze_rich_header - line 243: return {} when filepath empty
# ---------------------------------------------------------------------------


def test_analyze_rich_header_returns_empty_when_filepath_is_empty():
    adapter = _MinimalAdapter(file_info={"core": {"file": ""}})
    cd = CompilerDetector(adapter)
    result = cd._analyze_rich_header()
    assert result == {}


# ---------------------------------------------------------------------------
# _analyze_rich_header - lines 250-252: exception handler
# ---------------------------------------------------------------------------


def test_analyze_rich_header_returns_empty_on_exception():
    cd = _RaisingAnalyzeRichDetector(_MinimalAdapter())
    result = cd._analyze_rich_header()
    assert result == {}


# ---------------------------------------------------------------------------
# Version detectors - lines 287, 291, 295, 303, 307, 311
# ---------------------------------------------------------------------------


def test_detect_clang_version_calls_clang_detector():
    cd = CompilerDetector(_MinimalAdapter())
    result = cd._detect_clang_version(["clang version 11.0.0"], [])
    assert isinstance(result, str)


def test_detect_intel_version_returns_unknown():
    cd = CompilerDetector(_MinimalAdapter())
    assert cd._detect_intel_version([], []) == "Unknown"


def test_detect_borland_version_returns_unknown():
    cd = CompilerDetector(_MinimalAdapter())
    assert cd._detect_borland_version([], []) == "Unknown"


def test_detect_go_version_calls_go_detector():
    cd = CompilerDetector(_MinimalAdapter())
    result = cd._detect_go_version(["go1.17"], [])
    assert isinstance(result, str)


def test_detect_rust_version_calls_rust_detector():
    cd = CompilerDetector(_MinimalAdapter())
    result = cd._detect_rust_version(["rustc 1.56.0"], [])
    assert isinstance(result, str)


def test_detect_delphi_version_returns_unknown():
    cd = CompilerDetector(_MinimalAdapter())
    assert cd._detect_delphi_version([], []) == "Unknown"


def test_detect_compiler_version_dispatches_to_clang():
    cd = CompilerDetector(_MinimalAdapter())
    result = cd._detect_compiler_version("Clang", [], [])
    assert isinstance(result, str)


def test_detect_compiler_version_dispatches_to_intel():
    cd = CompilerDetector(_MinimalAdapter())
    assert cd._detect_compiler_version("Intel", [], []) == "Unknown"


def test_detect_compiler_version_dispatches_to_borland():
    cd = CompilerDetector(_MinimalAdapter())
    assert cd._detect_compiler_version("Borland", [], []) == "Unknown"


def test_detect_compiler_version_dispatches_to_go():
    cd = CompilerDetector(_MinimalAdapter())
    result = cd._detect_compiler_version("Go", [], [])
    assert isinstance(result, str)


def test_detect_compiler_version_dispatches_to_rust():
    cd = CompilerDetector(_MinimalAdapter())
    result = cd._detect_compiler_version("Rust", [], [])
    assert isinstance(result, str)


def test_detect_compiler_version_dispatches_to_delphi():
    cd = CompilerDetector(_MinimalAdapter())
    assert cd._detect_compiler_version("Delphi", [], []) == "Unknown"


# ---------------------------------------------------------------------------
# _get_file_info - line 316: return {} when no adapter
# ---------------------------------------------------------------------------


def test_get_file_info_returns_empty_dict_when_adapter_is_none():
    cd = CompilerDetector(adapter=None)
    assert cd._get_file_info() == {}


# ---------------------------------------------------------------------------
# _get_imports_raw - line 329: return [] when no adapter
# ---------------------------------------------------------------------------


def test_get_imports_raw_returns_empty_when_adapter_is_none():
    cd = CompilerDetector(adapter=None)
    assert cd._get_imports_raw() == []


# ---------------------------------------------------------------------------
# _get_sections_raw - line 334: return [] when no adapter
# ---------------------------------------------------------------------------


def test_get_sections_raw_returns_empty_when_adapter_is_none():
    cd = CompilerDetector(adapter=None)
    assert cd._get_sections_raw() == []


# ---------------------------------------------------------------------------
# _get_symbols_raw - line 339: return [] when no adapter
# ---------------------------------------------------------------------------


def test_get_symbols_raw_returns_empty_when_adapter_is_none():
    cd = CompilerDetector(adapter=None)
    assert cd._get_symbols_raw() == []
