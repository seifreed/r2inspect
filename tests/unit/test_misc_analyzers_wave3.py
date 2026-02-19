#!/usr/bin/env python3
"""
Coverage tests – wave 3.

Modules covered:
  r2inspect/modules/anti_analysis.py
  r2inspect/modules/export_analyzer.py
  r2inspect/modules/macho_analyzer.py
  r2inspect/modules/tlsh_analyzer.py

Rules: no mocks, no unittest.mock, no MagicMock, no patch.
       Plain functions only.  Do not import from r2inspect.compat.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import Any

import r2inspect.modules.tlsh_analyzer as tlsh_mod
from r2inspect.modules.anti_analysis import AntiAnalysisDetector
from r2inspect.modules.export_analyzer import ExportAnalyzer
from r2inspect.modules.macho_analyzer import MachOAnalyzer
from r2inspect.modules.tlsh_analyzer import TLSHAnalyzer

# ---------------------------------------------------------------------------
# Shared minimal adapter
# ---------------------------------------------------------------------------


class MinAdapter:
    def get_imports(self) -> list[dict[str, Any]]:
        return []

    def get_strings(self) -> list[dict[str, Any]]:
        return []

    def get_strings_basic(self) -> list[dict[str, Any]]:
        return []

    def get_strings_filtered(self, command: str) -> str:
        return ""

    def search_text(self, pattern: str) -> str:
        return ""

    def search_hex(self, pattern: str) -> str:
        return ""

    def cmd(self, command: str) -> str:
        return ""

    def cmdj(self, command: str) -> Any:
        return []

    def get_sections(self) -> list[dict[str, Any]]:
        return []

    def get_functions(self) -> list[dict[str, Any]]:
        return []

    def get_exports(self) -> list[dict[str, Any]]:
        return []

    def read_bytes(self, addr: int, size: int) -> bytes:
        return b""

    def get_file_info(self) -> dict[str, Any]:
        return {}

    def get_headers_json(self) -> list[dict[str, Any]]:
        return []


# ===========================================================================
# anti_analysis.py – adapters and subclasses
# ===========================================================================


class RaisingImportsAdapter(MinAdapter):
    """get_imports always raises – triggers except paths that call _get_imports."""

    def get_imports(self) -> list[dict[str, Any]]:
        raise RuntimeError("forced imports error")


class RaisingStringsAdapter(MinAdapter):
    """get_strings always raises – triggers except paths that call _get_strings."""

    def get_strings(self) -> list[dict[str, Any]]:
        raise RuntimeError("forced strings error")


class RaisingStringsFilteredAdapter(MinAdapter):
    """get_strings_filtered always raises – triggers iz~ command paths."""

    def get_strings_filtered(self, command: str) -> str:
        raise RuntimeError("forced strings_filtered error")


class NoGetImportsNoGetStringsAdapter:
    """No get_imports / get_strings attributes – exercises _cmd_list fallback."""

    def search_text(self, pattern: str) -> str:
        return ""

    def search_hex(self, pattern: str) -> str:
        return ""

    def cmd(self, command: str) -> str:
        return ""

    def cmdj(self, command: str) -> Any:
        return []

    def get_strings_filtered(self, command: str) -> str:
        return ""


class FailingDetector(AntiAnalysisDetector):
    """Override to make detect() raise before sub-method handles it."""

    def _detect_anti_debug_detailed(self) -> dict[str, Any]:  # type: ignore[override]
        raise RuntimeError("forced detector failure")


# ---------------------------------------------------------------------------
# anti_analysis tests
# ---------------------------------------------------------------------------


def test_detect_exception_handler() -> None:
    """Lines 92,93,94: detect() outer except block."""
    detector = FailingDetector(MinAdapter())
    result = detector.detect()
    assert "error" in result
    assert "forced detector failure" in result["error"]


def test_anti_debug_imports_exception() -> None:
    """Lines 160,161,162: _detect_anti_debug_detailed except block."""
    detector = AntiAnalysisDetector(RaisingImportsAdapter())
    result = detector._detect_anti_debug_detailed()
    assert any(e.get("type") == "Error" for e in result["evidence"])


def test_anti_vm_strings_exception() -> None:
    """Lines 207,208,209: _detect_anti_vm_detailed except block."""
    detector = AntiAnalysisDetector(RaisingStringsAdapter())
    result = detector._detect_anti_vm_detailed()
    assert any(e.get("type") == "Error" for e in result["evidence"])


def test_anti_sandbox_strings_exception() -> None:
    """Lines 246,247,248: _detect_anti_sandbox_detailed except block."""
    detector = AntiAnalysisDetector(RaisingStringsAdapter())
    result = detector._detect_anti_sandbox_detailed()
    assert any(e.get("type") == "Error" for e in result["evidence"])


def test_evasion_techniques_exception() -> None:
    """Lines 262,263: _detect_evasion_techniques except block.

    detect_api_hashing issues an iz~ command which routes through
    get_strings_filtered; the raised error propagates to the except clause.
    """
    detector = AntiAnalysisDetector(RaisingStringsFilteredAdapter())
    result = detector._detect_evasion_techniques()
    assert isinstance(result, list)


def test_find_suspicious_apis_exception() -> None:
    """Lines 280,281: _find_suspicious_apis except block."""
    detector = AntiAnalysisDetector(RaisingImportsAdapter())
    result = detector._find_suspicious_apis()
    assert isinstance(result, list)


def test_timing_checks_exception() -> None:
    """Lines 329,330,331: _detect_timing_checks_detailed except block."""
    detector = AntiAnalysisDetector(RaisingImportsAdapter())
    result = detector._detect_timing_checks_detailed()
    assert any(e.get("type") == "Error" for e in result["evidence"])


def test_environment_checks_exception() -> None:
    """Lines 341,342: _detect_environment_checks except block.

    detect_environment_checks issues iz~ commands routed through
    get_strings_filtered; the raised error propagates to the except clause.
    """
    detector = AntiAnalysisDetector(RaisingStringsFilteredAdapter())
    result = detector._detect_environment_checks()
    assert isinstance(result, list)


def test_get_imports_cmd_list_fallback() -> None:
    """Line 360: _get_imports falls back to _cmd_list when adapter lacks get_imports."""
    detector = AntiAnalysisDetector(NoGetImportsNoGetStringsAdapter())
    imports = detector._get_imports()
    assert isinstance(imports, list)


def test_get_strings_cmd_list_fallback() -> None:
    """Line 365: _get_strings falls back to _cmd_list when adapter lacks get_strings."""
    detector = AntiAnalysisDetector(NoGetImportsNoGetStringsAdapter())
    strings = detector._get_strings()
    assert isinstance(strings, list)


# ===========================================================================
# export_analyzer.py – adapters and subclasses
# ===========================================================================


class ExportsAdapter(MinAdapter):
    """Returns two exports including one with a suspicious name."""

    def get_exports(self) -> list[dict[str, Any]]:
        return [
            {"name": "DllMain", "vaddr": 0x1000, "ordinal": 1, "type": "func", "size": 80},
            {"name": "execute_payload", "vaddr": 0x2000, "ordinal": 2, "type": "func", "size": 120},
        ]

    def cmdj(self, command: str) -> Any:
        if command.startswith("afij"):
            return [{"size": 100, "cc": 2}]
        return []


class BrokenCharacteristicsAnalyzer(ExportAnalyzer):
    """_get_export_characteristics always raises – covers lines 83-85."""

    def _get_export_characteristics(self, exp: dict[str, Any]) -> dict[str, Any]:  # type: ignore[override]
        raise RuntimeError("characteristics error")


class BrokenGetExportsAnalyzer(ExportAnalyzer):
    """get_exports always raises – covers lines 163-164 in get_export_statistics."""

    def get_exports(self) -> list[dict[str, Any]]:  # type: ignore[override]
        raise RuntimeError("get_exports error")


# ---------------------------------------------------------------------------
# export_analyzer tests
# ---------------------------------------------------------------------------


def test_export_get_category() -> None:
    """Line 20: get_category."""
    assert ExportAnalyzer(MinAdapter()).get_category() == "metadata"


def test_export_get_description() -> None:
    """Line 23: get_description."""
    desc = ExportAnalyzer(MinAdapter()).get_description()
    assert len(desc) > 0


def test_export_supports_format() -> None:
    """Line 25-26: supports_format branches."""
    analyzer = ExportAnalyzer(MinAdapter())
    assert analyzer.supports_format("PE") is True
    assert analyzer.supports_format("ELF") is True
    assert analyzer.supports_format("MACH0") is False


def test_export_analyze_full_flow() -> None:
    """Lines 30,32-40,42: analyze() happy path."""
    analyzer = ExportAnalyzer(ExportsAdapter())
    result = analyzer.analyze()
    assert "exports" in result
    assert "statistics" in result
    assert result["total_exports"] >= 0


def test_analyze_export_characteristics_exception() -> None:
    """Lines 83,84,85: _analyze_export except when _get_export_characteristics raises."""
    analyzer = BrokenCharacteristicsAnalyzer(ExportsAdapter())
    result = analyzer._analyze_export({"name": "test", "vaddr": 0x1000, "ordinal": 1})
    assert "error" in result
    assert "characteristics error" in result["error"]


def test_export_statistics_with_exports() -> None:
    """Lines 158,160,161: get_export_statistics iterates over a non-empty list."""
    analyzer = ExportAnalyzer(ExportsAdapter())
    stats = analyzer.get_export_statistics()
    assert stats["total_exports"] > 0
    assert len(stats["export_names"]) > 0


def test_export_statistics_exception() -> None:
    """Lines 163,164: get_export_statistics except block."""
    analyzer = BrokenGetExportsAnalyzer(MinAdapter())
    stats = analyzer.get_export_statistics()
    assert stats["total_exports"] == 0


# ===========================================================================
# macho_analyzer.py – adapters and subclasses
# ===========================================================================


class BrokenBinInfoAdapter(MinAdapter):
    """get_file_info returns {"bin": None} causing AttributeError in _get_macho_headers."""

    def get_file_info(self) -> dict[str, Any]:
        return {"bin": None}


class NullHeadersAdapter(MinAdapter):
    """get_headers_json returns [None] causing AttributeError in header loops."""

    def get_headers_json(self) -> list[Any]:  # type: ignore[override]
        return [None]


class DylibHeaderAdapter(MinAdapter):
    """Provides an LC_ID_DYLIB header so _extract_dylib_info returns non-empty."""

    def get_headers_json(self) -> list[dict[str, Any]]:
        return [
            {
                "type": "LC_ID_DYLIB",
                "name": "libfoo.dylib",
                "version": "1.0",
                "compatibility": "1.0",
                "timestamp": 1234567890,
            }
        ]


class NullSectionsAdapter(MinAdapter):
    """get_sections returns [None] causing AttributeError in build_sections."""

    def get_sections(self) -> list[Any]:  # type: ignore[override]
        return [None]


class BrokenBuildVersionAnalyzer(MachOAnalyzer):
    """_extract_build_version raises – covers lines 129,130 in _get_compilation_info."""

    def _extract_build_version(self) -> dict[str, Any]:  # type: ignore[override]
        raise RuntimeError("forced build-version error")


# ---------------------------------------------------------------------------
# macho_analyzer tests
# ---------------------------------------------------------------------------


def test_macho_get_headers_exception() -> None:
    """Lines 95,96: _get_macho_headers except block (bin_info is None)."""
    analyzer = MachOAnalyzer(BrokenBinInfoAdapter())
    result = analyzer._get_macho_headers()
    assert isinstance(result, dict)


def test_macho_compilation_info_dylib_branch() -> None:
    """Line 118: _get_compilation_info reaches info.update(dylib_info)."""
    analyzer = MachOAnalyzer(DylibHeaderAdapter())
    result = analyzer._get_compilation_info()
    assert isinstance(result, dict)
    assert "dylib_name" in result or "compile_time" in result


def test_macho_compilation_info_exception() -> None:
    """Lines 129,130: _get_compilation_info except block."""
    analyzer = BrokenBuildVersionAnalyzer(MinAdapter())
    result = analyzer._get_compilation_info()
    assert isinstance(result, dict)


def test_macho_extract_build_version_exception() -> None:
    """Lines 159,160: _extract_build_version except block (None header item)."""
    analyzer = MachOAnalyzer(NullHeadersAdapter())
    result = analyzer._extract_build_version()
    assert isinstance(result, dict)


def test_macho_extract_version_min_exception() -> None:
    """Lines 186,187: _extract_version_min except block."""
    analyzer = MachOAnalyzer(NullHeadersAdapter())
    result = analyzer._extract_version_min()
    assert isinstance(result, dict)


def test_macho_extract_dylib_info_exception() -> None:
    """Lines 215,216: _extract_dylib_info except block."""
    analyzer = MachOAnalyzer(NullHeadersAdapter())
    result = analyzer._extract_dylib_info()
    assert isinstance(result, dict)


def test_macho_extract_uuid_exception() -> None:
    """Lines 233,234: _extract_uuid except block."""
    analyzer = MachOAnalyzer(NullHeadersAdapter())
    result = analyzer._extract_uuid()
    assert result is None


def test_macho_estimate_from_sdk_version_exception() -> None:
    """Lines 243,244,246: _estimate_from_sdk_version except block (non-string input)."""
    analyzer = MachOAnalyzer(MinAdapter())
    result = analyzer._estimate_from_sdk_version(99999)  # type: ignore[arg-type]
    assert result is None


def test_macho_get_load_commands_exception() -> None:
    """Lines 261,262: _get_load_commands except block."""
    analyzer = MachOAnalyzer(NullHeadersAdapter())
    result = analyzer._get_load_commands()
    assert result == []


def test_macho_get_section_info_exception() -> None:
    """Lines 277,278: _get_section_info except block (None item in sections list)."""
    analyzer = MachOAnalyzer(NullSectionsAdapter())
    result = analyzer._get_section_info()
    assert result == []


# ===========================================================================
# tlsh_analyzer.py – adapters and subclasses
# ===========================================================================


class TLSHRichAdapter:
    """Adapter providing sections and functions with valid data."""

    def get_sections(self) -> list[dict[str, Any]]:
        return [{"name": ".text", "vaddr": 0x1000, "size": 1024}]

    def get_functions(self) -> list[dict[str, Any]]:
        return [{"name": "main", "addr": 0x1000, "size": 100}]

    def read_bytes(self, addr: int, size: int) -> bytes:
        return (bytes(range(256)) * ((size // 256) + 1))[:size]


class TLSHNoMethodsAdapter:
    """Adapter with none of the optional methods."""

    pass


class TLSHRaisingCalcAnalyzer(TLSHAnalyzer):
    """Override _calculate_tlsh_from_hex to raise – hits inner except in section/function loops."""

    def _calculate_tlsh_from_hex(self, hex_data: str | None) -> str | None:  # type: ignore[override]
        raise RuntimeError("forced TLSH calc error")


# ---------------------------------------------------------------------------
# tlsh_analyzer tests
# ---------------------------------------------------------------------------


def test_tlsh_import_failure() -> None:
    """Lines 10,11: TLSH_AVAILABLE=False when the tlsh import fails.

    Uses sys.modules to block the tlsh import, then reimports the module
    to exercise the except ImportError branch.
    """
    orig_tlsh = sys.modules.get("tlsh", "MISSING")
    cached_module = sys.modules.pop("r2inspect.modules.tlsh_analyzer", None)

    sys.modules["tlsh"] = None  # type: ignore[assignment]  # blocks import
    try:
        fresh = importlib.import_module("r2inspect.modules.tlsh_analyzer")
        assert fresh.TLSH_AVAILABLE is False  # type: ignore[attr-defined]
    finally:
        if orig_tlsh == "MISSING":
            sys.modules.pop("tlsh", None)
        else:
            sys.modules["tlsh"] = orig_tlsh  # type: ignore[assignment]
        sys.modules.pop("r2inspect.modules.tlsh_analyzer", None)
        if cached_module is not None:
            sys.modules["r2inspect.modules.tlsh_analyzer"] = cached_module
        importlib.import_module("r2inspect.modules.tlsh_analyzer")


def test_tlsh_check_library_unavailable() -> None:
    """Line 42: _check_library_availability returns (False, msg) when TLSH unavailable."""
    orig = tlsh_mod.TLSH_AVAILABLE
    tlsh_mod.TLSH_AVAILABLE = False
    try:
        analyzer = TLSHAnalyzer(TLSHRichAdapter(), str(Path(__file__)))
        available, error_msg = analyzer._check_library_availability()
        assert available is False
        assert error_msg is not None
    finally:
        tlsh_mod.TLSH_AVAILABLE = orig


def test_tlsh_analyze_sections_unavailable() -> None:
    """Line 94: analyze_sections returns early dict when TLSH not available."""
    orig = tlsh_mod.TLSH_AVAILABLE
    tlsh_mod.TLSH_AVAILABLE = False
    try:
        analyzer = TLSHAnalyzer(TLSHRichAdapter(), str(Path(__file__)))
        result = analyzer.analyze_sections()
        assert result["available"] is False
        assert "error" in result
    finally:
        tlsh_mod.TLSH_AVAILABLE = orig


def test_tlsh_calculate_from_hex_invalid_input() -> None:
    """Lines 160,161: _calculate_tlsh_from_hex except block with invalid hex."""
    analyzer = TLSHAnalyzer(TLSHRichAdapter(), str(Path(__file__)))
    result = analyzer._calculate_tlsh_from_hex("GGGG not valid hex!")
    assert result is None


def test_tlsh_calculate_binary_tlsh_bad_path() -> None:
    """Lines 172,173,174: _calculate_binary_tlsh except block when file is missing."""
    analyzer = TLSHAnalyzer(TLSHRichAdapter(), "/nonexistent/__wave3_test_file__.bin")
    result = analyzer._calculate_binary_tlsh()
    assert result is None


def test_tlsh_section_inner_except() -> None:
    """Lines 200,201,202: inner except in _calculate_section_tlsh loop."""
    analyzer = TLSHRaisingCalcAnalyzer(TLSHRichAdapter(), str(Path(__file__)))
    result = analyzer._calculate_section_tlsh()
    assert isinstance(result, dict)
    assert ".text" in result
    assert result[".text"] is None


def test_tlsh_function_inner_except() -> None:
    """Lines 242,243,244: inner except in _calculate_function_tlsh loop."""
    analyzer = TLSHRaisingCalcAnalyzer(TLSHRichAdapter(), str(Path(__file__)))
    result = analyzer._calculate_function_tlsh()
    assert isinstance(result, dict)
    assert result.get("main") is None


def test_tlsh_get_sections_no_method() -> None:
    """Line 254: _get_sections returns [] when adapter has no get_sections."""
    analyzer = TLSHAnalyzer(TLSHNoMethodsAdapter(), str(Path(__file__)))
    assert analyzer._get_sections() == []


def test_tlsh_get_functions_no_method() -> None:
    """Line 259: _get_functions returns [] when adapter has no get_functions."""
    analyzer = TLSHAnalyzer(TLSHNoMethodsAdapter(), str(Path(__file__)))
    assert analyzer._get_functions() == []


def test_tlsh_read_bytes_hex_no_adapter() -> None:
    """Line 268: _read_bytes_hex returns None when adapter has no read_bytes."""
    analyzer = TLSHAnalyzer(TLSHNoMethodsAdapter(), str(Path(__file__)))
    assert analyzer._read_bytes_hex(0x1000, 128) is None


def test_tlsh_compare_hashes_unavailable() -> None:
    """Line 345: compare_hashes returns None when TLSH library is unavailable."""
    orig = tlsh_mod.TLSH_AVAILABLE
    tlsh_mod.TLSH_AVAILABLE = False
    try:
        result = TLSHAnalyzer.compare_hashes("T1234abcd", "T5678efgh")
        assert result is None
    finally:
        tlsh_mod.TLSH_AVAILABLE = orig
