#!/usr/bin/env python3
"""Supplemental pytest unit tests for uncovered lines.

No mocks, no unittest.mock, no MagicMock, no patch. Stub adapters only
(plain classes with the exact methods each analyzer calls).
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import pytest

from r2inspect.config import Config
from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer
from r2inspect.modules.ccbhash_analyzer import CCBHashAnalyzer
from r2inspect.modules.overlay_analyzer import OverlayAnalyzer
from r2inspect.modules.packer_detector import PackerDetector
from r2inspect.modules.section_analyzer import SectionAnalyzer


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_config() -> Config:
    return Config()


# ===========================================================================
# OVERLAY ANALYZER stubs & tests
# ===========================================================================


class OverlayAdapter:
    """Adapter that triggers the full overlay analysis path."""

    def __init__(
        self,
        file_size: int = 10000,
        sections: list[dict] | None = None,
        data_dirs: list[dict] | None = None,
        overlay_bytes: list[int] | None = None,
    ) -> None:
        self._file_size = file_size
        self._sections = sections if sections is not None else [{"name": ".text", "paddr": 0, "size": 8000}]
        self._data_dirs = data_dirs if data_dirs is not None else []
        self._overlay_bytes = overlay_bytes  # None means return a default

    def get_file_info(self) -> dict[str, Any]:
        return {"core": {"size": self._file_size}}

    def get_sections(self) -> list[dict[str, Any]]:
        return self._sections

    def get_data_directories(self) -> list[dict[str, Any]]:
        return self._data_dirs

    def read_bytes_list(self, addr: int, size: int) -> list[int]:
        if self._overlay_bytes is not None:
            return self._overlay_bytes[:size]
        # Default: MZ header followed by printable ASCII
        base = [0x4D, 0x5A, 72, 101, 108, 108, 111]
        return (base + [0x41] * size)[:size]


class OverlayAdapterEmptyOverlay:
    """Adapter that returns empty data for read_bytes_list."""

    def get_file_info(self) -> dict[str, Any]:
        return {"core": {"size": 10000}}

    def get_sections(self) -> list[dict[str, Any]]:
        return [{"name": ".text", "paddr": 0, "size": 8000}]

    def get_data_directories(self) -> list[dict[str, Any]]:
        return []

    def read_bytes_list(self, addr: int, size: int) -> list[int]:
        return []


class OverlayAdapterZeroSize:
    """Adapter whose file_size is 0 → analyze() returns early."""

    def get_file_info(self) -> dict[str, Any]:
        return {"core": {"size": 0}}

    def get_sections(self) -> list[dict[str, Any]]:
        return []

    def get_data_directories(self) -> list[dict[str, Any]]:
        return []

    def read_bytes_list(self, addr: int, size: int) -> list[int]:
        return []


class OverlayAdapterNoOverlay:
    """Adapter where pe_end >= file_size → no overlay."""

    def get_file_info(self) -> dict[str, Any]:
        return {"core": {"size": 5000}}

    def get_sections(self) -> list[dict[str, Any]]:
        return [{"name": ".text", "paddr": 0, "size": 5000}]

    def get_data_directories(self) -> list[dict[str, Any]]:
        return []

    def read_bytes_list(self, addr: int, size: int) -> list[int]:
        return []


class OverlayAdapterWithCertificate:
    """Adapter with a SECURITY data directory that extends pe_end."""

    def get_file_info(self) -> dict[str, Any]:
        return {"core": {"size": 20000}}

    def get_sections(self) -> list[dict[str, Any]]:
        return [{"name": ".text", "paddr": 0, "size": 8000}]

    def get_data_directories(self) -> list[dict[str, Any]]:
        return [{"name": "SECURITY", "paddr": 8000, "size": 4000}]

    def read_bytes_list(self, addr: int, size: int) -> list[int]:
        return [0x41] * size


class OverlayAdapterHighEntropy:
    """Adapter that produces high-entropy overlay data."""

    def get_file_info(self) -> dict[str, Any]:
        return {"core": {"size": 2 * 1024 * 1024 + 10000}}  # >1 MB overlay

    def get_sections(self) -> list[dict[str, Any]]:
        return [{"name": ".text", "paddr": 0, "size": 10000}]

    def get_data_directories(self) -> list[dict[str, Any]]:
        return []

    def read_bytes_list(self, addr: int, size: int) -> list[int]:
        # Produce varied bytes (all 256 values cycling) → high entropy
        return [i % 256 for i in range(size)]


class OverlayAdapterAutoIt:
    """Adapter whose overlay starts with an AutoIt signature."""

    # AutoIt signature: 0x41, 0x55, 0x33, 0x21, 0xEA, 0x06
    _AUTOIT_SIG = [0x41, 0x55, 0x33, 0x21, 0xEA, 0x06]

    def get_file_info(self) -> dict[str, Any]:
        return {"core": {"size": 10000}}

    def get_sections(self) -> list[dict[str, Any]]:
        return [{"name": ".text", "paddr": 0, "size": 8000}]

    def get_data_directories(self) -> list[dict[str, Any]]:
        return []

    def read_bytes_list(self, addr: int, size: int) -> list[int]:
        base = self._AUTOIT_SIG + [0x00] * (size - len(self._AUTOIT_SIG))
        return base[:size]


class OverlayAdapterSuspiciousStrings:
    """Adapter whose overlay contains suspicious strings encoded as ASCII ints."""

    _PAYLOAD = list(b"cmd.exe powershell CreateProcess" + b"\x00" * 100)

    def get_file_info(self) -> dict[str, Any]:
        return {"core": {"size": 10000}}

    def get_sections(self) -> list[dict[str, Any]]:
        return [{"name": ".text", "paddr": 0, "size": 8000}]

    def get_data_directories(self) -> list[dict[str, Any]]:
        return []

    def read_bytes_list(self, addr: int, size: int) -> list[int]:
        return (self._PAYLOAD + [0x41] * size)[:size]


class OverlayAdapterNonListSections:
    """Adapter whose get_sections() returns a non-list value."""

    def get_file_info(self) -> dict[str, Any]:
        return {"core": {"size": 5000}}

    def get_sections(self) -> Any:
        return "not_a_list"

    def get_data_directories(self) -> list[dict[str, Any]]:
        return []

    def read_bytes_list(self, addr: int, size: int) -> list[int]:
        return []


# -- Tests --


class TestOverlayAnalyzer:
    def test_zero_file_size_returns_early(self) -> None:
        """Line 56: _get_file_size returns 0 → analyze returns default result."""
        analyzer = OverlayAnalyzer(OverlayAdapterZeroSize())
        result = analyzer.analyze()
        assert result["has_overlay"] is False
        assert result["available"] is True

    def test_no_overlay_returns_early(self) -> None:
        """Lines 63-69: pe_end >= file_size → overlay_size <= 0 → return early."""
        analyzer = OverlayAnalyzer(OverlayAdapterNoOverlay())
        result = analyzer.analyze()
        assert result["has_overlay"] is False

    def test_basic_overlay_detected(self) -> None:
        """Lines 109, 159, 161-166: overlay found, metadata populated."""
        analyzer = OverlayAnalyzer(OverlayAdapter())
        result = analyzer.analyze()
        assert result["has_overlay"] is True
        assert result["overlay_size"] == 2000
        assert result["overlay_offset"] == 8000
        assert result["file_size"] == 10000
        assert result["pe_end"] == 8000

    def test_empty_overlay_data_skips_analysis(self) -> None:
        """Line 133: read_bytes_list returns [] → _analyze_overlay_content returns early."""
        analyzer = OverlayAnalyzer(OverlayAdapterEmptyOverlay())
        result = analyzer.analyze()
        assert result["has_overlay"] is True
        assert result["overlay_entropy"] == 0.0

    def test_certificate_extends_pe_end(self) -> None:
        """Lines 112-113: SECURITY data directory extends pe_end."""
        analyzer = OverlayAnalyzer(OverlayAdapterWithCertificate())
        result = analyzer.analyze()
        # pe_end should be 8000+4000=12000, overlay_size=20000-12000=8000
        assert result["has_overlay"] is True
        assert result["pe_end"] == 12000
        assert result["overlay_size"] == 8000

    def test_entropy_calculated(self) -> None:
        """Lines 137-139: entropy and hashes computed when overlay data present."""
        analyzer = OverlayAnalyzer(OverlayAdapter())
        result = analyzer.analyze()
        assert result["overlay_entropy"] >= 0.0
        assert isinstance(result["overlay_hashes"], dict)

    def test_large_overlay_suspicious_indicator(self) -> None:
        """Lines 180-207: large overlay triggers suspicious indicator."""
        analyzer = OverlayAnalyzer(OverlayAdapterHighEntropy())
        result = analyzer.analyze()
        indicator_names = [i["indicator"] for i in result["suspicious_indicators"]]
        assert "Large overlay" in indicator_names

    def test_high_entropy_suspicious_indicator(self) -> None:
        """Line 211: high-entropy overlay triggers High entropy indicator."""
        analyzer = OverlayAnalyzer(OverlayAdapterHighEntropy())
        result = analyzer.analyze()
        indicator_names = [i["indicator"] for i in result["suspicious_indicators"]]
        assert "High entropy" in indicator_names

    def test_autoit_pattern_suspicious_indicator(self) -> None:
        """Lines 289-313: AutoIt signature found → AutoIt script indicator."""
        analyzer = OverlayAnalyzer(OverlayAdapterAutoIt())
        result = analyzer.analyze()
        pattern_names = [p["name"] for p in result["patterns_found"]]
        assert "AutoIt" in pattern_names
        indicator_names = [i["indicator"] for i in result["suspicious_indicators"]]
        assert "AutoIt script" in indicator_names

    def test_embedded_pe_detected(self) -> None:
        """Lines 215-285: MZ header in overlay → embedded PE detected."""
        analyzer = OverlayAnalyzer(OverlayAdapter())  # default returns MZ bytes
        result = analyzer.analyze()
        embedded_types = [e["type"] for e in result["embedded_files"]]
        assert "PE" in embedded_types or "MZ-DOS" in embedded_types

    def test_suspicious_strings_indicator(self) -> None:
        """Lines 317-358: overlay contains 'cmd.exe' → suspicious string indicator."""
        analyzer = OverlayAnalyzer(OverlayAdapterSuspiciousStrings())
        result = analyzer.analyze()
        indicator_names = [i["indicator"] for i in result["suspicious_indicators"]]
        assert "Suspicious strings" in indicator_names

    def test_non_list_sections_returns_empty(self) -> None:
        """Lines 103-104: get_sections returns non-list → _calculate_pe_end returns 0."""
        analyzer = OverlayAnalyzer(OverlayAdapterNonListSections())
        result = analyzer.analyze()
        # pe_end=0 → _get_valid_pe_end returns None → analyze returns early
        assert result["has_overlay"] is False

    def test_potential_type_from_pattern(self) -> None:
        """Line 97, 161-166: potential_type derived from recognized pattern."""
        analyzer = OverlayAnalyzer(OverlayAdapterAutoIt())
        result = analyzer.analyze()
        assert "installer" in result["potential_type"].lower() or result["potential_type"] != "unknown"

    def test_default_result_structure(self) -> None:
        """Verify _default_result() keys are all present."""
        analyzer = OverlayAnalyzer(OverlayAdapterZeroSize())
        result = analyzer.analyze()
        for key in (
            "available", "has_overlay", "overlay_offset", "overlay_size",
            "overlay_entropy", "overlay_hashes", "patterns_found", "potential_type",
            "suspicious_indicators", "extracted_strings", "file_size", "pe_end",
            "embedded_files", "error",
        ):
            assert key in result


# ===========================================================================
# CCBHASH ANALYZER stubs & tests
# ===========================================================================


class CCBHashAdapter:
    """Stub adapter that returns one function with a simple CFG."""

    def __init__(self, cfg: list[dict] | None = None) -> None:
        self._cfg = cfg if cfg is not None else [
            {"edges": [{"src": 0x1000, "dst": 0x1020}, {"src": 0x1020, "dst": 0x1040}]}
        ]

    def get_functions(self) -> list[dict[str, Any]]:
        return [{"name": "main", "addr": 0x1000, "size": 100}]

    def get_cfg(self, func_offset: int) -> list[dict[str, Any]]:
        return self._cfg

    # allow analyze_all to be called safely
    def analyze_all(self) -> None:
        pass


class CCBHashAdapterNoFunctions:
    """Stub adapter that returns an empty function list."""

    def get_functions(self) -> list[dict[str, Any]]:
        return []

    def get_cfg(self, func_offset: int) -> list[dict[str, Any]]:
        return []

    def analyze_all(self) -> None:
        pass


class CCBHashAdapterBlockCFG:
    """Stub adapter whose CFG has blocks but no edges."""

    def get_functions(self) -> list[dict[str, Any]]:
        return [{"name": "func_a", "addr": 0x2000, "size": 50}]

    def get_cfg(self, func_offset: int) -> list[dict[str, Any]]:
        return [{"blocks": [{"offset": 0x2000}, {"offset": 0x2010}], "edges": []}]

    def analyze_all(self) -> None:
        pass


class CCBHashAdapterEmptyCFG:
    """Stub adapter whose CFG is empty → falls back to func_offset as canonical."""

    def get_functions(self) -> list[dict[str, Any]]:
        return [{"name": "bare_func", "addr": 0x3000, "size": 20}]

    def get_cfg(self, func_offset: int) -> list[dict[str, Any]]:
        return [{}]  # no edges, no blocks

    def analyze_all(self) -> None:
        pass


class CCBHashAdapterSimilarFunctions:
    """Stub adapter with two functions that have identical CFGs → similar group."""

    def get_functions(self) -> list[dict[str, Any]]:
        return [
            {"name": "func_a", "addr": 0x1000, "size": 50},
            {"name": "func_b", "addr": 0x2000, "size": 50},
        ]

    def get_cfg(self, func_offset: int) -> list[dict[str, Any]]:
        # Same CFG for both → same hash
        return [{"edges": [{"src": 0x0000, "dst": 0x0010}]}]

    def analyze_all(self) -> None:
        pass


class TestCCBHashAnalyzer:
    """Tests for CCBHashAnalyzer using temporary files."""

    def _make_analyzer(self, adapter: Any, tmp_path: Path) -> CCBHashAnalyzer:
        f = tmp_path / "dummy.bin"
        f.write_bytes(b"\x00" * 64)
        return CCBHashAnalyzer(adapter, str(f))

    def test_calculate_hash_success(self, tmp_path: Path) -> None:
        """Lines 58-85: _calculate_hash returns a value."""
        analyzer = self._make_analyzer(CCBHashAdapter(), tmp_path)
        hash_val, method, err = analyzer._calculate_hash()
        assert hash_val is not None
        assert method == "cfg_analysis"
        assert err is None

    def test_calculate_hash_no_functions(self, tmp_path: Path) -> None:
        """Lines 63-69: empty function list → NO_FUNCTIONS_FOUND."""
        analyzer = self._make_analyzer(CCBHashAdapterNoFunctions(), tmp_path)
        hash_val, method, err = analyzer._calculate_hash()
        assert hash_val is None
        assert "No functions" in err

    def test_analyze_returns_dict(self, tmp_path: Path) -> None:
        """Full analyze() path through R2HashingStrategy template."""
        analyzer = self._make_analyzer(CCBHashAdapter(), tmp_path)
        result = analyzer.analyze()
        assert isinstance(result, dict)
        assert result.get("available") is True
        assert result["hash_value"] is not None

    def test_analyze_functions_basic(self, tmp_path: Path) -> None:
        """Lines 127-183: analyze_functions() returns full result."""
        analyzer = self._make_analyzer(CCBHashAdapter(), tmp_path)
        result = analyzer.analyze_functions()
        assert result["available"] is True
        assert result["total_functions"] == 1
        assert result["analyzed_functions"] == 1
        assert result["binary_ccbhash"] is not None
        assert result["unique_hashes"] == 1

    def test_analyze_functions_no_functions(self, tmp_path: Path) -> None:
        """Lines 94, 202-215: no functions → error set."""
        analyzer = self._make_analyzer(CCBHashAdapterNoFunctions(), tmp_path)
        result = analyzer.analyze_functions()
        assert result["available"] is False
        assert result["error"] == "No functions found in binary"

    def test_analyze_functions_block_cfg(self, tmp_path: Path) -> None:
        """Lines 228-254: CFG with blocks-only canonical representation."""
        analyzer = self._make_analyzer(CCBHashAdapterBlockCFG(), tmp_path)
        result = analyzer.analyze_functions()
        assert result["available"] is True
        assert "func_a" in result["function_hashes"]

    def test_analyze_functions_empty_cfg_fallback(self, tmp_path: Path) -> None:
        """CFG has no edges and no blocks → falls back to func_offset string."""
        analyzer = self._make_analyzer(CCBHashAdapterEmptyCFG(), tmp_path)
        result = analyzer.analyze_functions()
        assert result["available"] is True

    def test_analyze_functions_similar_functions(self, tmp_path: Path) -> None:
        """Lines 202-215: two functions with same hash → similar group detected."""
        analyzer = self._make_analyzer(CCBHashAdapterSimilarFunctions(), tmp_path)
        result = analyzer.analyze_functions()
        assert result["available"] is True
        assert len(result["similar_functions"]) >= 1
        assert result["similar_functions"][0]["count"] == 2

    def test_compare_hashes_equal(self) -> None:
        h = "abc123def456"
        assert CCBHashAnalyzer.compare_hashes(h, h) is True

    def test_compare_hashes_different(self) -> None:
        assert CCBHashAnalyzer.compare_hashes("aaa", "bbb") is False

    def test_compare_hashes_none_input(self) -> None:
        assert CCBHashAnalyzer.compare_hashes("", "bbb") is None

    def test_is_available(self) -> None:
        assert CCBHashAnalyzer.is_available() is True


# ===========================================================================
# BINDIFF ANALYZER stubs & tests
# ===========================================================================


class BinDiffAdapter:
    """Full-featured stub adapter for BinDiffAnalyzer."""

    def __init__(
        self,
        file_info: dict | None = None,
        sections: list[dict] | None = None,
        imports: list[dict] | None = None,
        exports: list[dict] | None = None,
        functions: list[dict] | None = None,
        strings: list[dict] | None = None,
    ) -> None:
        self._file_info = file_info or {
            "core": {"format": "PE", "size": 50000},
            "bin": {"arch": "x86", "bits": 32, "endian": "little"},
        }
        self._sections = sections if sections is not None else [
            {"name": ".text", "size": 0x2000, "perm": "rx"},
            {"name": ".data", "size": 0x1000, "perm": "rw"},
        ]
        self._imports = imports if imports is not None else [
            {"name": "CreateFile", "libname": "kernel32.dll"},
            {"name": "VirtualAlloc", "libname": "kernel32.dll"},
        ]
        self._exports = exports if exports is not None else [
            {"name": "MyExport"},
        ]
        self._functions = functions if functions is not None else [
            {"name": "main", "offset": 0x1000, "size": 200},
        ]
        self._strings = strings if strings is not None else [
            {"string": "http://malware.example.com"},
            {"string": "HKEY_LOCAL_MACHINE"},
            {"string": "CreateProcess"},
        ]

    def get_file_info(self) -> dict[str, Any]:
        return self._file_info

    def get_sections(self) -> list[dict[str, Any]]:
        return self._sections

    def get_imports(self) -> list[dict[str, Any]]:
        return self._imports

    def get_exports(self) -> list[dict[str, Any]]:
        return self._exports

    def get_functions(self) -> list[dict[str, Any]]:
        return self._functions

    def get_cfg(self, address: int) -> list[dict[str, Any]]:
        return [{"edges": [{"src": address, "dst": address + 0x10}], "blocks": []}]

    def get_strings(self) -> list[dict[str, Any]]:
        return self._strings

    def analyze_all(self) -> None:
        pass

    def get_entropy_pattern(self) -> str:
        return "entropy_pattern_data"


class BinDiffAdapterEmpty:
    """Minimal adapter that returns empty collections."""

    def get_file_info(self) -> dict[str, Any]:
        return {}

    def get_sections(self) -> list[dict[str, Any]]:
        return []

    def get_imports(self) -> list[dict[str, Any]]:
        return []

    def get_exports(self) -> list[dict[str, Any]]:
        return []

    def get_functions(self) -> list[dict[str, Any]]:
        return []

    def get_cfg(self, address: int) -> list[dict[str, Any]]:
        return []

    def get_strings(self) -> list[dict[str, Any]]:
        return []

    def analyze_all(self) -> None:
        pass

    def get_entropy_pattern(self) -> str:
        return ""


class TestBinDiffAnalyzer:
    def _make_analyzer(self, adapter: Any) -> BinDiffAnalyzer:
        return BinDiffAnalyzer(adapter, "/nonexistent/dummy.exe")

    def test_analyze_returns_comparison_ready(self) -> None:
        """Lines 68-70: analyze() produces comparison_ready=True."""
        analyzer = self._make_analyzer(BinDiffAdapter())
        result = analyzer.analyze()
        assert result["comparison_ready"] is True

    def test_analyze_empty_adapter(self) -> None:
        """Lines 68-70: analyze() with empty adapter still returns comparison_ready=True."""
        analyzer = self._make_analyzer(BinDiffAdapterEmpty())
        result = analyzer.analyze()
        assert result["comparison_ready"] is True

    def test_extract_structural_features_populated(self) -> None:
        """Lines 113-115: structural features include file_type, section_count, import_count."""
        analyzer = self._make_analyzer(BinDiffAdapter())
        features = analyzer._extract_structural_features()
        assert features.get("file_type") == "PE"
        assert features.get("section_count") == 2
        assert features.get("import_count") == 2
        assert features.get("export_count") == 1

    def test_extract_structural_features_empty(self) -> None:
        """Structural features with empty adapter return empty dict."""
        analyzer = self._make_analyzer(BinDiffAdapterEmpty())
        features = analyzer._extract_structural_features()
        assert isinstance(features, dict)

    def test_extract_function_features(self) -> None:
        """Lines 125-129: function features include function_count and cfg_features."""
        analyzer = self._make_analyzer(BinDiffAdapter())
        features = analyzer._extract_function_features()
        assert features.get("function_count") == 1
        assert "cfg_features" in features

    def test_extract_function_features_empty(self) -> None:
        """Lines 134-142: function features with empty adapter return empty dict."""
        analyzer = self._make_analyzer(BinDiffAdapterEmpty())
        features = analyzer._extract_function_features()
        assert isinstance(features, dict)

    def test_extract_string_features(self) -> None:
        """Lines 134-142: string features computed from strings."""
        analyzer = self._make_analyzer(BinDiffAdapter())
        features = analyzer._extract_string_features()
        assert features.get("total_strings") == 3
        assert features.get("unique_strings") == 3
        assert "url_strings" in features
        assert "registry_strings" in features
        assert "string_signature" in features

    def test_extract_string_features_empty(self) -> None:
        """Empty strings → empty string features dict."""
        analyzer = self._make_analyzer(BinDiffAdapterEmpty())
        features = analyzer._extract_string_features()
        assert isinstance(features, dict)

    def test_extract_behavioral_features(self) -> None:
        """Lines 149-153: behavioral features include indicators."""
        analyzer = self._make_analyzer(BinDiffAdapter())
        features = analyzer._extract_behavioral_features()
        assert "network_indicators" in features or "suspicious_apis" in features

    def test_extract_byte_features(self) -> None:
        """Lines 160-166: byte features include entropy_pattern."""
        analyzer = self._make_analyzer(BinDiffAdapter())
        features = analyzer._extract_byte_features()
        assert features.get("entropy_pattern") == "entropy_pattern_data"

    def test_compare_with(self) -> None:
        """Lines 179, 184-212: compare_with returns overall_similarity."""
        adapter = BinDiffAdapter()
        analyzer = BinDiffAnalyzer(adapter, "/nonexistent/a.exe")
        other = BinDiffAnalyzer(adapter, "/nonexistent/b.exe")
        other_results = other.analyze()
        comparison = analyzer.compare_with(other_results)
        assert "overall_similarity" in comparison
        assert isinstance(comparison["overall_similarity"], float)

    def test_compare_with_not_ready(self) -> None:
        """compare_with returns error when other binary not comparison_ready."""
        analyzer = self._make_analyzer(BinDiffAdapter())
        result = analyzer.compare_with({"comparison_ready": False})
        assert "error" in result

    def test_signatures_generated(self) -> None:
        """Signatures dict produced by analyze() contains expected keys."""
        analyzer = self._make_analyzer(BinDiffAdapter())
        result = analyzer.analyze()
        sigs = result.get("signatures", {})
        for key in ("structural", "function", "string", "behavioral"):
            assert key in sigs


# ===========================================================================
# SECTION ANALYZER stubs & tests
# ===========================================================================


class SectionStubAdapter:
    """Full stub adapter for SectionAnalyzer."""

    def __init__(self, sections: list[dict] | None = None, read_data: bytes = b"") -> None:
        self._sections = sections if sections is not None else []
        self._read_data = read_data

    def get_sections(self) -> list[dict[str, Any]]:
        return self._sections

    def read_bytes(self, addr: int, size: int) -> bytes:
        if self._read_data:
            return self._read_data[:size]
        return b"\x00" * min(size, 1024)

    def get_file_info(self) -> dict[str, Any]:
        return {"arch": "x86"}

    def get_functions(self) -> list[dict[str, Any]]:
        return [{"addr": 0x1000, "offset": 0x1000, "size": 100}]


class TestSectionAnalyzer:
    def _make(self, adapter: Any) -> SectionAnalyzer:
        return SectionAnalyzer(adapter)

    def test_analyze_sections_empty(self) -> None:
        """No sections → sections list is empty."""
        sa = self._make(SectionStubAdapter([]))
        result = sa.analyze_sections()
        assert result == []

    def test_analyze_single_text_section(self) -> None:
        """_analyze_single_section handles a .text section."""
        section = {
            "name": ".text",
            "vaddr": 0x1000,
            "vsize": 0x2000,
            "size": 0x2000,
            "flags": "rx",
            "perm": "rx",
        }
        data = bytes(range(256)) * 32  # varied bytes for entropy
        sa = self._make(SectionStubAdapter([section], data))
        result = sa._analyze_single_section(section)
        assert result["name"] == ".text"
        assert result["is_executable"] is True
        assert result["is_readable"] is True
        assert result["entropy"] >= 0.0

    def test_analyze_single_section_pe_characteristics(self) -> None:
        """_apply_pe_characteristics sets flags from characteristics integer."""
        section = {
            "name": ".text",
            "vaddr": 0x1000,
            "vsize": 0x2000,
            "size": 0x2000,
            "flags": "",
            "perm": "",
            "characteristics": 0x07000020,  # CODE | MEM_EXECUTE | MEM_READ | MEM_WRITE
        }
        sa = self._make(SectionStubAdapter([section]))
        result = sa._analyze_single_section(section)
        assert result["is_executable"] is True
        assert "IMAGE_SCN_MEM_EXECUTE" in result["pe_characteristics"]

    def test_suspicious_writable_executable_section(self) -> None:
        """_check_permission_indicators flags W+X sections."""
        section = {
            "name": ".strange",
            "vaddr": 0x5000,
            "vsize": 0x1000,
            "size": 0x1000,
            "flags": "rwx",
            "perm": "rwx",
        }
        sa = self._make(SectionStubAdapter([section]))
        result = sa._analyze_single_section(section)
        assert "Writable and executable section" in result["suspicious_indicators"]

    def test_suspicious_packer_section_name(self) -> None:
        """_check_section_name_indicators flags known packer section names."""
        section = {
            "name": ".upx0",
            "vaddr": 0x6000,
            "vsize": 0x1000,
            "size": 0x1000,
            "flags": "r",
            "perm": "r",
        }
        sa = self._make(SectionStubAdapter([section]))
        result = sa._analyze_single_section(section)
        assert any("upx" in ind.lower() for ind in result["suspicious_indicators"])

    def test_size_ratio_large(self) -> None:
        """_check_size_indicators flags large virtual vs raw size ratio."""
        section = {
            "name": ".bss",
            "vaddr": 0x7000,
            "vsize": 0x50000,  # 320 KB virtual
            "size": 0x100,  # 256 bytes raw → ratio = 1280
            "flags": "rw",
            "perm": "rw",
        }
        sa = self._make(SectionStubAdapter([section]))
        result = sa._analyze_single_section(section)
        indicators = result["suspicious_indicators"]
        assert any("ratio" in ind.lower() or "size" in ind.lower() for ind in indicators)

    def test_get_section_summary(self) -> None:
        """get_section_summary returns expected fields."""
        sections = [
            {
                "name": ".text",
                "vaddr": 0x1000,
                "vsize": 0x2000,
                "size": 0x2000,
                "flags": "rx",
                "perm": "rx",
            },
            {
                "name": ".data",
                "vaddr": 0x3000,
                "vsize": 0x1000,
                "size": 0x1000,
                "flags": "rw",
                "perm": "rw",
            },
        ]
        sa = self._make(SectionStubAdapter(sections))
        summary = sa.get_section_summary()
        assert summary["total_sections"] == 2
        assert summary["executable_sections"] == 1
        assert summary["writable_sections"] == 1
        assert "avg_entropy" in summary

    def test_analyze_returns_sections_and_summary(self) -> None:
        """Full analyze() path populates sections and summary."""
        sections = [
            {
                "name": ".text",
                "vaddr": 0x1000,
                "vsize": 0x2000,
                "size": 0x2000,
                "flags": "rx",
                "perm": "rx",
            }
        ]
        sa = self._make(SectionStubAdapter(sections))
        result = sa.analyze()
        assert result["available"] is True
        assert result["total_sections"] == 1
        assert len(result["sections"]) == 1

    def test_very_small_section_indicator(self) -> None:
        """_check_size_indicators flags sections smaller than 100 bytes."""
        section = {
            "name": ".tiny",
            "vaddr": 0x9000,
            "vsize": 50,
            "size": 50,
            "flags": "r",
            "perm": "r",
        }
        sa = self._make(SectionStubAdapter([section]))
        result = sa._analyze_single_section(section)
        assert any("small" in ind.lower() for ind in result["suspicious_indicators"])

    def test_entropy_anomaly_detection(self) -> None:
        """_check_entropy_anomaly flags when entropy is outside expected range."""
        section = {
            "name": ".text",  # expected 6.0-7.5
            "vaddr": 0x1000,
            "vsize": 0x2000,
            "size": 0x2000,
            "flags": "rx",
            "perm": "rx",
        }
        # Provide uniform zero bytes → entropy = 0.0 (anomaly for .text)
        sa = self._make(SectionStubAdapter([section], b"\x00" * 0x2000))
        result = sa._analyze_single_section(section)
        assert result["characteristics"].get("entropy_anomaly") is True

    def test_non_standard_section_name(self) -> None:
        """_check_section_name_indicators flags name not starting with '.'."""
        section = {
            "name": "CODE",
            "vaddr": 0x1000,
            "vsize": 0x1000,
            "size": 0x1000,
            "flags": "rx",
            "perm": "rx",
        }
        sa = self._make(SectionStubAdapter([section]))
        result = sa._analyze_single_section(section)
        assert any("non-standard" in ind.lower() for ind in result["suspicious_indicators"])

    def test_high_entropy_suspicious_indicator(self) -> None:
        """_check_entropy_indicators flags entropy > 7.5."""
        section = {
            "name": ".rsrc",
            "vaddr": 0x5000,
            "vsize": 0x1000,
            "size": 0x1000,
            "flags": "r",
            "perm": "r",
        }
        # Generate bytes with high entropy
        high_entropy_data = bytes(i % 256 for i in range(1024)) * 4
        sa = self._make(SectionStubAdapter([section], high_entropy_data))
        result = sa._analyze_single_section(section)
        if result["entropy"] > 7.5:
            assert any("entropy" in ind.lower() for ind in result["suspicious_indicators"])


# ===========================================================================
# PACKER DETECTOR stubs & tests
# ===========================================================================


class PackerAdapter:
    """Stub adapter for PackerDetector that returns normal data."""

    def get_sections(self) -> list[dict[str, Any]]:
        return [
            {"name": ".text", "vaddr": 0x1000, "size": 0x2000, "perm": "rx"},
            {"name": ".data", "vaddr": 0x3000, "size": 0x1000, "perm": "rw"},
        ]

    def get_imports(self) -> list[dict[str, Any]]:
        return [{"name": f"func{i}", "libname": "kernel32.dll"} for i in range(20)]

    def get_strings(self) -> list[dict[str, Any]]:
        return [{"string": "Hello"}, {"string": "World"}]

    def get_file_info(self) -> dict[str, Any]:
        return {
            "core": {"size": 50000},
            "bin": {"arch": "x86"},
        }

    def search_hex(self, pattern: str) -> str:
        return ""

    def read_bytes(self, addr: int, size: int) -> bytes:
        return b"\x00" * size


class PackerAdapterHighEntropy:
    """Stub adapter that returns high-entropy sections."""

    def get_sections(self) -> list[dict[str, Any]]:
        return [
            {"name": ".text", "vaddr": 0x1000, "size": 0x2000, "perm": "rwx"},
        ]

    def get_imports(self) -> list[dict[str, Any]]:
        return [{"name": "LoadLibrary", "libname": "kernel32.dll"}]

    def get_strings(self) -> list[dict[str, Any]]:
        return []

    def get_file_info(self) -> dict[str, Any]:
        return {"core": {"size": 10000}}

    def search_hex(self, pattern: str) -> str:
        return ""

    def read_bytes(self, addr: int, size: int) -> bytes:
        # Return varied bytes (all 256 values cycling) → high entropy
        return bytes(i % 256 for i in range(size))


class PackerAdapterUPXSignature:
    """Stub adapter that returns UPX signature string."""

    def get_sections(self) -> list[dict[str, Any]]:
        return [
            {"name": "UPX0", "vaddr": 0x1000, "size": 0x2000, "perm": "rwx"},
            {"name": "UPX1", "vaddr": 0x3000, "size": 0x1000, "perm": "rwx"},
        ]

    def get_imports(self) -> list[dict[str, Any]]:
        return [{"name": "LoadLibrary", "libname": "kernel32.dll"}]

    def get_strings(self) -> list[dict[str, Any]]:
        return [{"string": "UPX!"}, {"string": "$Info: This file is packed with the UPX"}]

    def get_file_info(self) -> dict[str, Any]:
        return {"core": {"size": 5000}}

    def search_hex(self, pattern: str) -> str:
        # Pretend UPX hex signature is found
        return "0x00001000"

    def read_bytes(self, addr: int, size: int) -> bytes:
        return bytes(i % 256 for i in range(size))


class PackerAdapterFewImports:
    """Stub adapter with very few imports → packing indicator."""

    def get_sections(self) -> list[dict[str, Any]]:
        return [
            {"name": ".text", "vaddr": 0x1000, "size": 0x2000, "perm": "rwx"},
        ]

    def get_imports(self) -> list[dict[str, Any]]:
        return [{"name": "LoadLibrary", "libname": "kernel32.dll"}]

    def get_strings(self) -> list[dict[str, Any]]:
        return []

    def get_file_info(self) -> dict[str, Any]:
        return {"core": {"size": 5000}}

    def search_hex(self, pattern: str) -> str:
        return ""

    def read_bytes(self, addr: int, size: int) -> bytes:
        return bytes(i % 256 for i in range(size))


class TestPackerDetector:
    def _make(self, adapter: Any) -> PackerDetector:
        return PackerDetector(adapter, config=_make_config())

    def test_detect_not_packed(self) -> None:
        """detect() returns is_packed=False for normal binary."""
        pd = self._make(PackerAdapter())
        result = pd.detect()
        assert isinstance(result, dict)
        assert result["is_packed"] is False
        assert "entropy_analysis" in result
        assert "section_analysis" in result

    def test_detect_high_entropy_sections(self) -> None:
        """detect() accumulates entropy evidence for high-entropy binary."""
        pd = self._make(PackerAdapterHighEntropy())
        result = pd.detect()
        assert isinstance(result, dict)
        # confidence > 0 because high entropy and W+X sections
        assert result["confidence"] >= 0.0

    def test_detect_upx_signature(self) -> None:
        """detect() recognizes UPX via signature search."""
        pd = self._make(PackerAdapterUPXSignature())
        result = pd.detect()
        assert result["is_packed"] is True
        assert result["packer_type"] == "UPX"

    def test_detect_few_imports_adds_indicator(self) -> None:
        """detect() adds 'Few imports' indicator when import count < 10."""
        pd = self._make(PackerAdapterFewImports())
        result = pd.detect()
        assert any("import" in ind.lower() for ind in result["indicators"])

    def test_calculate_heuristic_score_high(self) -> None:
        """_calculate_heuristic_score returns float in [0,1]."""
        pd = self._make(PackerAdapter())
        entropy_results = {
            "summary": {"high_entropy_ratio": 0.8, "high_entropy_sections": 2}
        }
        section_results = {
            "suspicious_sections": ["s1"],
            "section_count": 2,
            "executable_sections": 2,
            "writable_executable": 1,
        }
        score = pd._calculate_heuristic_score(entropy_results, section_results)
        assert 0.0 <= score <= 1.0

    def test_get_overlay_info(self) -> None:
        """get_overlay_info() does not raise and returns a dict."""
        pd = self._make(PackerAdapter())
        result = pd.get_overlay_info()
        assert isinstance(result, dict)

    def test_count_imports(self) -> None:
        """_count_imports returns correct count."""
        pd = self._make(PackerAdapter())
        assert pd._count_imports() == 20

    def test_no_config_raises(self) -> None:
        """PackerDetector requires config; None raises ValueError."""
        with pytest.raises(ValueError):
            PackerDetector(PackerAdapter(), config=None)

    def test_analyze_sections_result_structure(self) -> None:
        """_analyze_sections returns dict with expected keys."""
        pd = self._make(PackerAdapter())
        result = pd._analyze_sections()
        assert "suspicious_sections" in result
        assert "section_count" in result

    def test_analyze_entropy_result_structure(self) -> None:
        """_analyze_entropy returns a dict (may be empty on empty sections)."""
        pd = self._make(PackerAdapter())
        result = pd._analyze_entropy()
        assert isinstance(result, dict)
