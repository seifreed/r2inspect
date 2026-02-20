"""Final batch of coverage tests for small module gaps."""

from __future__ import annotations

import logging
import struct
from typing import Any

import r2inspect.modules.ccbhash_analyzer as _ccb_mod
import r2inspect.modules.impfuzzy_analyzer as _imp_mod
import r2inspect.utils.hashing as _hash_mod
from r2inspect.config import Config
from r2inspect.modules.ccbhash_analyzer import CCBHashAnalyzer
from r2inspect.modules.packer_detector import PackerDetector
from r2inspect.modules.rich_header_domain import decode_rich_header

# ---------------------------------------------------------------------------
# Shared adapter
# ---------------------------------------------------------------------------


class _NullAdapter:
    def get_file_info(self) -> dict[str, Any]:
        return {}

    def cmdj(self, cmd: str) -> Any:
        return None

    def cmd(self, cmd: str) -> str:
        return ""

    def get_symbols(self) -> list[Any]:
        return []

    def get_info_text(self) -> str:
        return ""


# ---------------------------------------------------------------------------
# ccbhash_analyzer.py - line 42: _check_library_availability returns False
# ---------------------------------------------------------------------------


def test_ccbhash_check_library_availability_unavailable_line_42():
    """Line 42: _check_library_availability returns (False, msg) when is_available() is False."""
    orig = CCBHashAnalyzer.is_available
    CCBHashAnalyzer.is_available = staticmethod(lambda: False)
    try:
        analyzer = CCBHashAnalyzer(adapter=_NullAdapter(), filepath="test.bin")
        ok, err = analyzer._check_library_availability()
        assert ok is False
        assert err is not None
    finally:
        CCBHashAnalyzer.is_available = orig


# ---------------------------------------------------------------------------
# utils/hashing.py - line 100: calculate_ssdeep returns None when get_ssdeep() is None
# ---------------------------------------------------------------------------


def test_calculate_ssdeep_returns_none_when_no_module_line_100():
    """Line 100: calculate_ssdeep returns None when get_ssdeep() returns None."""
    orig = _hash_mod.get_ssdeep
    _hash_mod.get_ssdeep = lambda: None
    try:
        result = _hash_mod.calculate_ssdeep("any_file.bin")
        assert result is None
    finally:
        _hash_mod.get_ssdeep = orig


# ---------------------------------------------------------------------------
# modules/pe_imports.py - line 79: covered via calculate_imphash with bytes funcname
# (line 79 is the `continue` when funcname is falsy; group_imports_by_library does
# pre-filter empty strings but None is also falsy and may pass through)
# ---------------------------------------------------------------------------


def test_calculate_imphash_skips_bytes_empty_funcname_line_79():
    """Line 79: continue when funcname is falsy (e.g., None or empty bytes)."""
    import r2inspect.modules.pe_imports as _pe_imp_mod

    orig_fetch = _pe_imp_mod.fetch_imports
    orig_group = _pe_imp_mod.group_imports_by_library

    def _fake_fetch(adapter: Any) -> list[dict[str, Any]]:
        return [{"libname": "kernel32.dll", "name": "CreateFile"}]

    def _fake_group(imports: list[dict[str, Any]]) -> dict[str, list[Any]]:
        # Return a functions list with a None entry to trigger line 79
        return {"kernel32": [None, "createfile"]}

    _pe_imp_mod.fetch_imports = _fake_fetch
    _pe_imp_mod.group_imports_by_library = _fake_group
    try:
        import logging

        from r2inspect.modules.pe_imports import calculate_imphash

        result = calculate_imphash(_NullAdapter(), logging.getLogger("test"))
        assert isinstance(result, str)
    finally:
        _pe_imp_mod.fetch_imports = orig_fetch
        _pe_imp_mod.group_imports_by_library = orig_group


# ---------------------------------------------------------------------------
# modules/pe_info.py - lines 54-56: _fetch_pe_header exception path
# ---------------------------------------------------------------------------


def test_fetch_pe_header_returns_none_on_exception_lines_54_56():
    """Lines 54-56: _fetch_pe_header catches exception from get_pe_headers and returns None."""
    import r2inspect.modules.pe_info as _pe_info_mod

    orig_get_headers = _pe_info_mod.get_pe_headers

    def _raising_get_headers(adapter: Any) -> None:
        raise RuntimeError("simulated PE header failure")

    _pe_info_mod.get_pe_headers = _raising_get_headers
    try:
        from r2inspect.modules.pe_info import _fetch_pe_header

        result = _fetch_pe_header(_NullAdapter(), logging.getLogger("test"))
        assert result is None
    finally:
        _pe_info_mod.get_pe_headers = orig_get_headers


# ---------------------------------------------------------------------------
# modules/packer_detector.py - line 112: Unknown (heuristic) when no packer_type
# ---------------------------------------------------------------------------


def test_packer_detector_unknown_heuristic_line_112():
    """Line 112: packer_type set to 'Unknown (heuristic)' when evidence >= 50 but no type found."""

    class _NoSigPackerDetector(PackerDetector):
        def _check_packer_signatures(self) -> dict[str, Any] | None:
            return None

        def _analyze_entropy(self) -> dict[str, Any]:
            return {"summary": {"high_entropy_sections": 3}}

        def _analyze_sections(self) -> dict[str, Any]:
            return {"suspicious_sections": [1, 2, 3]}

        def _count_imports(self) -> int:
            return 5

    analyzer = _NoSigPackerDetector(adapter=_NullAdapter(), config=Config())
    result = analyzer.detect()
    assert result.get("is_packed") is True
    assert result.get("packer_type") == "Unknown (heuristic)"


# ---------------------------------------------------------------------------
# modules/rich_header_domain.py - line 291: entries.append when count > 0
# ---------------------------------------------------------------------------


def test_decode_rich_header_appends_entry_when_count_positive_line_291():
    """Line 291: entries.append() is called when count > 0 in decoded entry."""
    # Build encoded_data with valid rich header structure
    # decode_rich_header(encoded_data, xor_key) iterates from index 4 in steps of 8
    # For each 8-byte chunk: prodid_encoded, count_encoded = struct.unpack("<II", chunk)
    # prodid = prodid_encoded ^ xor_key; count = count_encoded ^ xor_key
    # if count > 0: entries.append(...)
    xor_key = 0x12345678
    # Build 12-byte encoded_data: 4-byte header + one 8-byte entry
    header = b"\x00" * 4  # placeholder for first 4 bytes
    prodid = 0x00030002
    count = 5
    prodid_encoded = prodid ^ xor_key
    count_encoded = count ^ xor_key
    entry_bytes = struct.pack("<II", prodid_encoded, count_encoded)
    encoded_data = header + entry_bytes

    entries = decode_rich_header(encoded_data, xor_key)
    assert len(entries) >= 1
    assert entries[0]["prodid"] == prodid
    assert entries[0]["count"] == count


# ---------------------------------------------------------------------------
# modules/impfuzzy_analyzer.py - lines 316-317: compare_hashes when get_ssdeep is None
# ---------------------------------------------------------------------------


def test_impfuzzy_compare_hashes_no_ssdeep_lines_316_317():
    """Lines 316-317: compare_hashes returns None when get_ssdeep() is None."""
    from r2inspect.modules.impfuzzy_analyzer import ImpfuzzyAnalyzer

    orig = _imp_mod.get_ssdeep
    _imp_mod.get_ssdeep = lambda: None
    try:
        result = ImpfuzzyAnalyzer.compare_hashes("3:abc:def", "3:abc:ghi")
        assert result is None
    finally:
        _imp_mod.get_ssdeep = orig
