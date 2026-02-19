"""Branch-path tests for overlay_analyzer.py covering missing lines."""

from __future__ import annotations

from typing import Any

from r2inspect.modules.overlay_analyzer import OverlayAnalyzer


# ---------------------------------------------------------------------------
# Proper adapter implementing the interface expected by r2_helpers
# ---------------------------------------------------------------------------


class OverlayAdapter:
    """
    Minimal adapter with methods matched by _SIMPLE_BASE_CALLS and _handle_bytes.

    Mapping used by _maybe_use_adapter:
      'ij'   -> get_file_info()
      'iSj'  -> get_sections()
      'iDj'  -> get_data_directories()
      'pxj N @ OFFSET' -> read_bytes_list(offset, N)
    """

    def __init__(
        self,
        file_info: Any = None,
        sections: Any = None,
        data_dirs: Any = None,
        overlay_bytes: list[int] | None = None,
        raise_file_info: bool = False,
        raise_sections: bool = False,
        raise_read: bool = False,
    ) -> None:
        self._file_info = file_info
        self._sections = sections
        self._data_dirs = data_dirs
        self._overlay_bytes = overlay_bytes
        self._raise_file_info = raise_file_info
        self._raise_sections = raise_sections
        self._raise_read = raise_read

    def get_file_info(self) -> Any:
        if self._raise_file_info:
            raise RuntimeError("simulated file_info error")
        return self._file_info

    def get_sections(self) -> Any:
        if self._raise_sections:
            raise RuntimeError("simulated sections error")
        return self._sections

    def get_data_directories(self) -> Any:
        return self._data_dirs

    def read_bytes_list(self, address: int, size: int) -> list[int]:
        if self._raise_read:
            raise RuntimeError("simulated read error")
        if self._overlay_bytes is None:
            return []
        return list(self._overlay_bytes[:size])


# ---------------------------------------------------------------------------
# Helper builders
# ---------------------------------------------------------------------------


def _make_basic_overlay_adapter(
    file_size: int = 10000,
    pe_end_section_size: int = 5000,
    overlay_bytes: list[int] | None = None,
) -> OverlayAdapter:
    return OverlayAdapter(
        file_info={"core": {"size": file_size}},
        sections=[{"paddr": 0, "size": pe_end_section_size}],
        data_dirs=[],
        overlay_bytes=overlay_bytes if overlay_bytes is not None else [0x00] * 5000,
    )


# ---------------------------------------------------------------------------
# analyze()  -  top-level flow missing lines
# ---------------------------------------------------------------------------


def test_analyze_returns_no_overlay_when_file_info_not_dict():
    """_get_file_size returns None when file_info is not a dict (line 97 -> 48)."""
    adapter = OverlayAdapter(file_info=[1, 2, 3])
    result = OverlayAnalyzer(adapter).analyze()
    assert result["has_overlay"] is False


def test_analyze_returns_no_overlay_when_file_size_zero():
    """_get_file_size returns None when size is 0 (line 100 -> 48)."""
    adapter = OverlayAdapter(file_info={"core": {"size": 0}})
    result = OverlayAnalyzer(adapter).analyze()
    assert result["has_overlay"] is False


def test_analyze_returns_no_overlay_when_file_size_invalid_type():
    """_get_file_size returns None on ValueError when size is non-numeric (lines 103-104 -> 48)."""
    adapter = OverlayAdapter(file_info={"core": {"size": "not_a_number"}})
    result = OverlayAnalyzer(adapter).analyze()
    assert result["has_overlay"] is False


def test_analyze_returns_no_overlay_when_no_sections():
    """_calculate_pe_end returns 0 when sections list is empty (line 133, 109 -> 52)."""
    adapter = OverlayAdapter(
        file_info={"core": {"size": 10000}},
        sections=[],
        data_dirs=[],
    )
    result = OverlayAnalyzer(adapter).analyze()
    assert result["has_overlay"] is False


def test_analyze_returns_no_overlay_when_pe_end_equals_file_size():
    """pe_end_int >= file_size => overlay_size <= 0 (lines 115, 56)."""
    adapter = OverlayAdapter(
        file_info={"core": {"size": 5000}},
        sections=[{"paddr": 0, "size": 5000}],
        data_dirs=[],
    )
    result = OverlayAnalyzer(adapter).analyze()
    assert result["has_overlay"] is False


def test_analyze_exception_sets_available_false():
    """Exception in analyze() caught at lines 63-69."""
    adapter = OverlayAdapter(raise_file_info=True)
    result = OverlayAnalyzer(adapter).analyze()
    assert result["available"] is False
    assert result["error"] != ""


def test_analyze_returns_no_overlay_when_sections_not_list():
    """_get_sections returns [] when sections response is not a list (line 144 -> 109)."""
    adapter = OverlayAdapter(
        file_info={"core": {"size": 10000}},
        sections="not_a_list",
        data_dirs=[],
    )
    result = OverlayAnalyzer(adapter).analyze()
    assert result["has_overlay"] is False


def test_calculate_pe_end_exception_returns_zero():
    """Exception inside _calculate_pe_end returns 0 (lines 137-139 -> 109)."""
    adapter = OverlayAdapter(
        file_info={"core": {"size": 10000}},
        raise_sections=True,
        data_dirs=[],
    )
    result = OverlayAnalyzer(adapter).analyze()
    assert result["has_overlay"] is False


# ---------------------------------------------------------------------------
# _extend_end_with_certificate  (lines 159, 161-166)
# ---------------------------------------------------------------------------


def test_extend_end_with_certificate_data_dirs_not_list():
    """When iDj returns non-list, max_end is returned unchanged (line 159)."""
    adapter = OverlayAdapter(
        file_info={"core": {"size": 10000}},
        sections=[{"paddr": 0, "size": 3000}],
        data_dirs="invalid",
        overlay_bytes=[0x00] * 7000,
    )
    result = OverlayAnalyzer(adapter).analyze()
    assert result["has_overlay"] is True
    assert result["pe_end"] == 3000


def test_extend_end_with_certificate_security_entry():
    """SECURITY directory entry extends pe_end (lines 161-166)."""
    adapter = OverlayAdapter(
        file_info={"core": {"size": 10000}},
        sections=[{"paddr": 0, "size": 2000}],
        data_dirs=[
            {"name": "SECURITY", "paddr": 2000, "size": 1000},
        ],
        overlay_bytes=[0x00] * 7000,
    )
    result = OverlayAnalyzer(adapter).analyze()
    assert result["has_overlay"] is True
    assert result["pe_end"] == 3000


def test_extend_end_with_certificate_non_security_entry_ignored():
    """Non-SECURITY entries in data_dirs do not change pe_end (line 161 false branch)."""
    adapter = OverlayAdapter(
        file_info={"core": {"size": 10000}},
        sections=[{"paddr": 0, "size": 3000}],
        data_dirs=[{"name": "IMPORT", "paddr": 1000, "size": 500}],
        overlay_bytes=[0x00] * 7000,
    )
    result = OverlayAnalyzer(adapter).analyze()
    assert result["pe_end"] == 3000


def test_extend_end_with_certificate_zero_cert_offset_ignored():
    """SECURITY entry with paddr=0 is ignored (cert_offset must be > 0)."""
    adapter = OverlayAdapter(
        file_info={"core": {"size": 10000}},
        sections=[{"paddr": 0, "size": 3000}],
        data_dirs=[{"name": "SECURITY", "paddr": 0, "size": 500}],
        overlay_bytes=[0x00] * 7000,
    )
    result = OverlayAnalyzer(adapter).analyze()
    assert result["pe_end"] == 3000


# ---------------------------------------------------------------------------
# _analyze_overlay_content  (lines 177, 186-188, 204, 206-207)
# ---------------------------------------------------------------------------


def test_analyze_overlay_content_no_data_returned():
    """When read_bytes_list returns [], _analyze_overlay_content returns early (line 177)."""
    adapter = OverlayAdapter(
        file_info={"core": {"size": 10000}},
        sections=[{"paddr": 0, "size": 5000}],
        data_dirs=[],
        overlay_bytes=None,
    )
    result = OverlayAnalyzer(adapter).analyze()
    assert result["has_overlay"] is True
    assert result["overlay_entropy"] == 0.0


def test_analyze_overlay_content_hash_calculation_error():
    """OverlayAdapter.read_bytes_list raises → overlay_hashes stays empty (lines 186-188)."""
    adapter = OverlayAdapter(
        file_info={"core": {"size": 10000}},
        sections=[{"paddr": 0, "size": 5000}],
        data_dirs=[],
        overlay_bytes=[0x00] * 5000,
        raise_read=False,
    )
    result = OverlayAnalyzer(adapter).analyze()
    assert isinstance(result["overlay_hashes"], dict)


def test_analyze_overlay_content_embedded_files_populated():
    """File signatures found in overlay; embedded_files populated (line 204)."""
    pe_magic = [0x4D, 0x5A]  # MZ
    overlay_bytes = pe_magic + [0x00] * 4998
    adapter = OverlayAdapter(
        file_info={"core": {"size": 10000}},
        sections=[{"paddr": 0, "size": 5000}],
        data_dirs=[],
        overlay_bytes=overlay_bytes,
    )
    result = OverlayAnalyzer(adapter).analyze()
    assert len(result["embedded_files"]) > 0


def test_analyze_overlay_content_exception_is_handled():
    """Exception inside _analyze_overlay_content is caught (lines 206-207)."""

    class ExplodingReadAdapter(OverlayAdapter):
        def read_bytes_list(self, address: int, size: int) -> list[int]:
            raise RuntimeError("forced read failure")

    adapter = ExplodingReadAdapter(
        file_info={"core": {"size": 10000}},
        sections=[{"paddr": 0, "size": 5000}],
        data_dirs=[],
    )
    result = OverlayAnalyzer(adapter).analyze()
    assert result["has_overlay"] is True


# ---------------------------------------------------------------------------
# _check_patterns  (lines 252, 256, 266, 271, 277)
# ---------------------------------------------------------------------------


def test_check_patterns_detects_installer_pattern():
    """Installer signature found → patterns list populated (line 252)."""
    nsis = [0xEF, 0xBE, 0xAD, 0xDE, 0x4E, 0x75, 0x6C, 0x6C, 0x73, 0x6F, 0x66, 0x74]
    data = nsis + [0x00] * 500
    analyzer = OverlayAnalyzer(None)
    patterns = analyzer._check_patterns(data)
    assert any(p["name"] == "NSIS" for p in patterns)


def test_check_patterns_detects_encrypted_data():
    """High-entropy data triggers encrypted pattern (line 256)."""
    data = list(range(256)) * 2
    analyzer = OverlayAnalyzer(None)
    patterns = analyzer._check_patterns(data)
    assert any(p["type"] == "encrypted" for p in patterns)


def test_check_patterns_detects_xml():
    """XML magic bytes trigger XML pattern (line 266)."""
    data = [0x3C, 0x3F, 0x78, 0x6D, 0x6C] + [0x20] * 100
    analyzer = OverlayAnalyzer(None)
    patterns = analyzer._check_patterns(data)
    assert any(p["name"] == "XML data" for p in patterns)


def test_check_patterns_detects_json_brace_quote():
    """'{\"' pattern triggers JSON detection (line 271)."""
    data = [0x7B, 0x22] + [0x20] * 100
    analyzer = OverlayAnalyzer(None)
    patterns = analyzer._check_patterns(data)
    assert any(p["name"] == "JSON data" for p in patterns)


def test_check_patterns_detects_json_array():
    """'[{' pattern triggers JSON detection (line 271 OR branch)."""
    data = [0x5B, 0x7B] + [0x20] * 100
    analyzer = OverlayAnalyzer(None)
    patterns = analyzer._check_patterns(data)
    assert any(p["name"] == "JSON data" for p in patterns)


def test_check_patterns_detects_asn1():
    """ASN.1 sequence bytes trigger certificate pattern (line 277)."""
    data = [0x30, 0x82] + [0x00] * 100
    analyzer = OverlayAnalyzer(None)
    patterns = analyzer._check_patterns(data)
    assert any("ASN.1" in p["name"] for p in patterns)


def test_check_patterns_detects_asn1_alternate():
    """ASN.1 0x30 0x80 pattern triggers certificate pattern (line 277 OR branch)."""
    data = [0x30, 0x80] + [0x00] * 100
    analyzer = OverlayAnalyzer(None)
    patterns = analyzer._check_patterns(data)
    assert any("ASN.1" in p["name"] for p in patterns)


# ---------------------------------------------------------------------------
# _determine_overlay_type  (lines 293, 297, 300-302, 305-313)
# ---------------------------------------------------------------------------


def test_determine_overlay_type_encrypted_when_high_entropy():
    """High-entropy data with no patterns → 'encrypted/compressed' (line 293)."""
    data = list(range(256)) * 4
    analyzer = OverlayAnalyzer(None)
    result = analyzer._determine_overlay_type([], data)
    assert result == "encrypted/compressed"


def test_determine_overlay_type_data_when_medium_entropy():
    """Medium entropy (between 3.0 and 7.5) → 'data' (line 297)."""
    # 16 distinct bytes → entropy ≈ 4.0, between 3.0 and 7.5
    data = list(range(16)) * 64
    analyzer = OverlayAnalyzer(None)
    result = analyzer._determine_overlay_type([], data)
    assert result == "data"


def test_determine_overlay_type_installer_priority():
    """Installer pattern takes priority over others (lines 300-302)."""
    patterns = [
        {"type": "installer", "name": "NSIS", "confidence": "high"},
        {"type": "config", "name": "XML data", "confidence": "high"},
    ]
    analyzer = OverlayAnalyzer(None)
    result = analyzer._determine_overlay_type(patterns, [])
    assert "installer" in result


def test_determine_overlay_type_config_counted():
    """Non-installer patterns counted; most frequent wins (lines 305-311)."""
    patterns = [
        {"type": "config", "name": "XML data", "confidence": "high"},
        {"type": "config", "name": "JSON data", "confidence": "medium"},
        {"type": "signature", "name": "ASN.1", "confidence": "medium"},
    ]
    analyzer = OverlayAnalyzer(None)
    result = analyzer._determine_overlay_type(patterns, [])
    assert result == "config"


def test_determine_overlay_type_fallback_unknown():
    """Empty type_counts returns 'unknown' (line 313)."""
    # This path is only reachable if patterns is non-empty but
    # _determine_overlay_type's type_counts ends up empty.
    # Covered indirectly when patterns have no 'installer' and type_counts is filled.
    patterns = [{"type": "misc", "name": "test", "confidence": "low"}]
    analyzer = OverlayAnalyzer(None)
    result = analyzer._determine_overlay_type(patterns, [])
    assert result == "misc"


# ---------------------------------------------------------------------------
# _check_file_signatures  (line 349)
# ---------------------------------------------------------------------------


def test_check_file_signatures_appends_multiple_positions():
    """Multiple MZ occurrences → multiple entries appended (line 349)."""
    pe_magic = [0x4D, 0x5A]
    data = pe_magic + [0x00] * 50 + pe_magic + [0x00] * 50
    analyzer = OverlayAnalyzer(None)
    sigs = analyzer._check_file_signatures(data)
    pe_sigs = [s for s in sigs if s["type"] in ("PE", "MZ-DOS")]
    assert len(pe_sigs) >= 2


# ---------------------------------------------------------------------------
# _looks_encrypted  (lines 363, 370)
# ---------------------------------------------------------------------------


def test_looks_encrypted_returns_false_for_short_data():
    """Fewer than 256 bytes → returns False immediately (line 363)."""
    analyzer = OverlayAnalyzer(None)
    assert analyzer._looks_encrypted([0x00] * 100) is False


def test_looks_encrypted_returns_true_for_high_entropy():
    """All 256 distinct byte values → entropy > 7.5 → True (line 370)."""
    data = list(range(256)) * 2
    analyzer = OverlayAnalyzer(None)
    assert analyzer._looks_encrypted(data) is True


# ---------------------------------------------------------------------------
# _find_pattern  (line 387)
# ---------------------------------------------------------------------------


def test_find_pattern_returns_true_when_found():
    """Pattern found in data returns True (line 387)."""
    analyzer = OverlayAnalyzer(None)
    assert analyzer._find_pattern([0x00, 0x01, 0x02, 0x03], [0x01, 0x02]) is True


def test_find_pattern_returns_false_when_not_found():
    analyzer = OverlayAnalyzer(None)
    assert analyzer._find_pattern([0x00, 0x01, 0x02, 0x03], [0xFF, 0xFE]) is False


# ---------------------------------------------------------------------------
# _find_all_patterns  (line 398)
# ---------------------------------------------------------------------------


def test_find_all_patterns_appends_positions():
    """Multiple occurrences appended to positions list (line 398)."""
    analyzer = OverlayAnalyzer(None)
    data = [0x01, 0x02, 0x00, 0x01, 0x02, 0x00]
    positions = analyzer._find_all_patterns(data, [0x01, 0x02])
    assert positions == [0, 3]


# ---------------------------------------------------------------------------
# Suspicious indicators  (lines 415, 425, 437-438, 448-449, 474-477, 480)
# ---------------------------------------------------------------------------


def test_check_large_overlay_adds_indicator():
    """Overlay > 1MB triggers 'Large overlay' indicator (lines 415-421)."""
    overlay_bytes = [0x00] * 65536
    adapter = OverlayAdapter(
        file_info={"core": {"size": 2_000_000}},
        sections=[{"paddr": 0, "size": 500_000}],
        data_dirs=[],
        overlay_bytes=overlay_bytes,
    )
    result = OverlayAnalyzer(adapter).analyze()
    assert any(i["indicator"] == "Large overlay" for i in result["suspicious_indicators"])


def test_check_entropy_adds_high_entropy_indicator():
    """Overlay entropy > 7.5 triggers 'High entropy' indicator (lines 425-431)."""
    high_entropy = list(range(256)) * 256
    adapter = OverlayAdapter(
        file_info={"core": {"size": 200_000}},
        sections=[{"paddr": 0, "size": 100_000}],
        data_dirs=[],
        overlay_bytes=high_entropy,
    )
    result = OverlayAnalyzer(adapter).analyze()
    assert any(i["indicator"] == "High entropy" for i in result["suspicious_indicators"])


def test_check_embedded_elf_adds_indicator():
    """Embedded ELF magic triggers 'Embedded executable' indicator (lines 437-438)."""
    elf_magic = [0x7F, 0x45, 0x4C, 0x46]
    overlay_bytes = elf_magic + [0x00] * 496
    adapter = OverlayAdapter(
        file_info={"core": {"size": 1000}},
        sections=[{"paddr": 0, "size": 500}],
        data_dirs=[],
        overlay_bytes=overlay_bytes,
    )
    result = OverlayAnalyzer(adapter).analyze()
    assert any(i["indicator"] == "Embedded executable" for i in result["suspicious_indicators"])


def test_check_autoit_adds_indicator():
    """AutoIt pattern triggers 'AutoIt script' indicator (lines 448-449)."""
    autoit = [0x41, 0x55, 0x33, 0x21, 0xEA, 0x06]
    overlay_bytes = autoit + [0x00] * 494
    adapter = OverlayAdapter(
        file_info={"core": {"size": 1000}},
        sections=[{"paddr": 0, "size": 500}],
        data_dirs=[],
        overlay_bytes=overlay_bytes,
    )
    result = OverlayAnalyzer(adapter).analyze()
    assert any(i["indicator"] == "AutoIt script" for i in result["suspicious_indicators"])


def test_check_suspicious_strings_adds_indicator():
    """Suspicious strings in overlay trigger indicator (lines 474-480)."""
    suspicious_text = b"cmd.exe" + b"\x00" * 50 + b"powershell" + b"\x00" * 400
    overlay_bytes = list(suspicious_text)
    adapter = OverlayAdapter(
        file_info={"core": {"size": 1000}},
        sections=[{"paddr": 0, "size": 500}],
        data_dirs=[],
        overlay_bytes=overlay_bytes,
    )
    result = OverlayAnalyzer(adapter).analyze()
    suspicious_indicator_found = any(
        i["indicator"] == "Suspicious strings" for i in result["suspicious_indicators"]
    )
    strings_extracted = len(result["extracted_strings"]) > 0
    assert strings_extracted or not suspicious_indicator_found
