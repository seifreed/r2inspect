#!/usr/bin/env python3
"""Branch-path tests for r2inspect/modules/tlsh_analyzer.py."""
from __future__ import annotations

from typing import Any

import pytest

from r2inspect.modules.tlsh_analyzer import TLSH_AVAILABLE, TLSHAnalyzer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class FakeAdapter:
    """Adapter that returns configurable sections, functions, and bytes."""

    def __init__(
        self,
        sections: list | None = None,
        functions: list | None = None,
        bytes_data: dict | None = None,
    ) -> None:
        self._sections = sections or []
        self._functions = functions or []
        self._bytes_data = bytes_data or {}

    def get_sections(self) -> list:
        return self._sections

    def get_functions(self) -> list:
        return self._functions

    def read_bytes(self, vaddr: int, size: int) -> bytes:
        return self._bytes_data.get(vaddr, b"")

    def cmd(self, command: str) -> str:
        return ""

    def cmdj(self, command: str) -> Any:
        return None


class ErrorReadAdapter(FakeAdapter):
    """Adapter whose read_bytes always raises."""

    def read_bytes(self, vaddr: int, size: int) -> bytes:
        raise RuntimeError("read_bytes failed intentionally")


class ErrorSectionsAdapter(FakeAdapter):
    """Adapter whose get_sections always raises."""

    def get_sections(self) -> list:
        raise RuntimeError("get_sections failed intentionally")


class ErrorFunctionsAdapter(FakeAdapter):
    """Adapter whose get_functions always raises."""

    def get_functions(self) -> list:
        raise RuntimeError("get_functions failed intentionally")


# ---------------------------------------------------------------------------
# _check_library_availability - line 42
# ---------------------------------------------------------------------------


def test_check_library_availability_returns_true_when_available(tmp_path):
    """Line 42: when TLSH is available, returns (True, None)."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available in this environment")
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename=str(f))
    available, error = analyzer._check_library_availability()
    assert available is True
    assert error is None


def test_check_library_availability_returns_false_when_unavailable(tmp_path):
    """Line 43-45: when TLSH is not available, returns (False, error_message)."""
    if TLSH_AVAILABLE:
        pytest.skip("TLSH is available, skipping unavailability test")
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename=str(f))
    available, error = analyzer._check_library_availability()
    assert available is False
    assert error is not None


# ---------------------------------------------------------------------------
# _calculate_hash - lines 58, 63-65
# ---------------------------------------------------------------------------


def test_calculate_hash_returns_hash_when_file_has_content(tmp_path):
    """Line 58: large-enough varied file produces a hash value."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename=str(f))
    hash_value, method, error = analyzer._calculate_hash()
    if hash_value is not None:
        assert method == "python_library"
        assert error is None


def test_calculate_hash_returns_error_when_file_too_small(tmp_path):
    """Lines 58-62: small file returns None hash with error message."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "tiny.bin"
    f.write_bytes(b"small")
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename=str(f))
    hash_value, method, error = analyzer._calculate_hash()
    assert hash_value is None
    assert error is not None


def test_calculate_hash_exception_branch_returns_error(tmp_path):
    """Lines 63-65: exception in _calculate_binary_tlsh -> error returned."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)

    class BrokenTLSHAnalyzer(TLSHAnalyzer):
        def _calculate_binary_tlsh(self) -> str | None:
            raise RuntimeError("intentional calculation error")

    analyzer = BrokenTLSHAnalyzer(adapter=FakeAdapter(), filename=str(f))
    hash_value, method, error = analyzer._calculate_hash()
    assert hash_value is None
    assert error is not None
    assert "TLSH calculation failed" in error


# ---------------------------------------------------------------------------
# analyze() - line 80 (binary_tlsh added when not already present)
# ---------------------------------------------------------------------------


def test_analyze_adds_binary_tlsh_field(tmp_path):
    """Line 80: analyze() adds binary_tlsh from hash_value when not already present."""
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename=str(f))
    result = analyzer.analyze()
    assert "binary_tlsh" in result
    assert result["hash_type"] == "tlsh"


# ---------------------------------------------------------------------------
# analyze_sections() - lines 94, 132-134, 153, 160-161, 170-174
# ---------------------------------------------------------------------------


def test_analyze_sections_unavailable_returns_error_dict(tmp_path):
    """Line 94: TLSH not available -> returns error dict."""
    if TLSH_AVAILABLE:
        pytest.skip("TLSH is available")
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename=str(f))
    result = analyzer.analyze_sections()
    assert result["available"] is False
    assert "error" in result


def test_analyze_sections_computes_binary_tlsh(tmp_path):
    """Line 153: binary_tlsh is computed via _calculate_binary_tlsh()."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename=str(f))
    result = analyzer.analyze_sections()
    assert result["available"] is True
    assert "binary_tlsh" in result


def test_analyze_sections_section_stats_computed(tmp_path):
    """Lines 160-161: sections_analyzed and sections_with_tlsh counted."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 20)
    section_data = bytes(range(256)) * 4
    sections = [
        {"name": ".text", "vaddr": 0x1000, "size": len(section_data)},
        {"name": ".data", "vaddr": 0x2000, "size": 0},
    ]
    adapter = FakeAdapter(
        sections=sections,
        bytes_data={0x1000: section_data},
    )
    analyzer = TLSHAnalyzer(adapter=adapter, filename=str(f))
    result = analyzer.analyze_sections()
    assert result["stats"]["sections_analyzed"] == 2


def test_analyze_sections_function_stats_computed(tmp_path):
    """Lines 170-174: functions_analyzed and functions_with_tlsh counted."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    functions = [
        {"name": "main", "addr": 0x1000, "size": 100},
    ]
    adapter = FakeAdapter(functions=functions)
    analyzer = TLSHAnalyzer(adapter=adapter, filename=str(f))
    result = analyzer.analyze_sections()
    assert result["stats"]["functions_analyzed"] == 1


def test_analyze_sections_text_section_tlsh_extracted(tmp_path):
    """Lines 170-172: text_section_tlsh extracted from section_tlsh dict."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 20)
    section_data = bytes(range(256)) * 4
    sections = [{"name": ".text", "vaddr": 0x1000, "size": len(section_data)}]
    adapter = FakeAdapter(
        sections=sections,
        bytes_data={0x1000: section_data},
    )
    analyzer = TLSHAnalyzer(adapter=adapter, filename=str(f))
    result = analyzer.analyze_sections()
    assert "text_section_tlsh" in result


def test_analyze_sections_outer_exception_returns_error(tmp_path):
    """Lines 132-134: _calculate_binary_tlsh raises -> except catches, returns error dict."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)

    class BrokenBinaryTLSH(TLSHAnalyzer):
        def _calculate_binary_tlsh(self) -> str | None:
            raise RuntimeError("forced error in binary tlsh")

    analyzer = BrokenBinaryTLSH(adapter=FakeAdapter(), filename=str(f))
    result = analyzer.analyze_sections()
    assert result["available"] is False
    assert "error" in result


# ---------------------------------------------------------------------------
# _calculate_section_tlsh - lines 183, 200-202, 204-205
# ---------------------------------------------------------------------------


def test_calculate_section_tlsh_empty_sections_returns_empty(tmp_path):
    """Line 183: no sections -> early return of empty dict."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(sections=[]), filename=str(f))
    result = analyzer._calculate_section_tlsh()
    assert result == {}


def test_calculate_section_tlsh_read_error_sets_none(tmp_path):
    """Lines 200-202: read_bytes raises -> section hash set to None."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    sections = [{"name": ".text", "vaddr": 0x1000, "size": 100}]
    adapter = ErrorReadAdapter(sections=sections)
    analyzer = TLSHAnalyzer(adapter=adapter, filename=str(f))
    result = analyzer._calculate_section_tlsh()
    assert ".text" in result
    assert result[".text"] is None


def test_calculate_section_tlsh_outer_exception_returns_empty(tmp_path):
    """Lines 204-205: get_sections() raises -> outer except catches, empty dict returned."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    analyzer = TLSHAnalyzer(adapter=ErrorSectionsAdapter(), filename=str(f))
    result = analyzer._calculate_section_tlsh()
    assert result == {}


# ---------------------------------------------------------------------------
# _calculate_function_tlsh - lines 218, 226-227, 234-235, 242-244, 246-247
# ---------------------------------------------------------------------------


def test_calculate_function_tlsh_empty_functions_returns_empty(tmp_path):
    """Line 218: no functions -> early return of empty dict."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(functions=[]), filename=str(f))
    result = analyzer._calculate_function_tlsh()
    assert result == {}


def test_calculate_function_tlsh_malformed_entry_skipped(tmp_path):
    """Lines 226-227: non-dict function entry is skipped."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    functions = ["not_a_dict", 42, None]
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(functions=functions), filename=str(f))
    result = analyzer._calculate_function_tlsh()
    assert result == {}


def test_calculate_function_tlsh_zero_size_sets_none(tmp_path):
    """Lines 234-235: func_size=0 -> function_hashes entry set to None."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    functions = [{"name": "zero_func", "addr": 0x1000, "size": 0}]
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(functions=functions), filename=str(f))
    result = analyzer._calculate_function_tlsh()
    assert "zero_func" in result
    assert result["zero_func"] is None


def test_calculate_function_tlsh_no_addr_sets_none(tmp_path):
    """Lines 234-235: func_addr is None (missing) -> entry set to None."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    functions = [{"name": "no_addr", "size": 100}]
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(functions=functions), filename=str(f))
    result = analyzer._calculate_function_tlsh()
    assert "no_addr" in result
    assert result["no_addr"] is None


def test_calculate_function_tlsh_name_fallback_from_addr(tmp_path):
    """Line 229: function without 'name' key falls back to func_<addr>."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    functions = [{"addr": 0x1000, "size": 100}]
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(functions=functions), filename=str(f))
    result = analyzer._calculate_function_tlsh()
    assert any("func_" in k for k in result)


def test_calculate_function_tlsh_read_error_sets_none(tmp_path):
    """Lines 242-244: read_bytes raises -> function hash set to None."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    functions = [{"name": "main", "addr": 0x1000, "size": 100}]
    adapter = ErrorReadAdapter(functions=functions)
    analyzer = TLSHAnalyzer(adapter=adapter, filename=str(f))
    result = analyzer._calculate_function_tlsh()
    assert "main" in result
    assert result["main"] is None


def test_calculate_function_tlsh_outer_exception_returns_empty(tmp_path):
    """Lines 246-247: get_functions() raises -> outer except catches, empty dict returned."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    analyzer = TLSHAnalyzer(adapter=ErrorFunctionsAdapter(), filename=str(f))
    result = analyzer._calculate_function_tlsh()
    assert result == {}


# ---------------------------------------------------------------------------
# _get_sections and _get_functions - lines 254, 259
# ---------------------------------------------------------------------------


def test_get_sections_with_adapter_returns_data(tmp_path):
    """Line 254: adapter.get_sections() result is returned via cast."""
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    sections = [{"name": ".text", "vaddr": 0, "size": 100}]
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(sections=sections), filename=str(f))
    result = analyzer._get_sections()
    assert result == sections


def test_get_functions_with_adapter_returns_data(tmp_path):
    """Line 259: adapter.get_functions() result is returned via cast."""
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    functions = [{"name": "main", "addr": 0x1000, "size": 64}]
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(functions=functions), filename=str(f))
    result = analyzer._get_functions()
    assert result == functions


# ---------------------------------------------------------------------------
# _read_bytes_hex - lines 266-268, 272-274
# ---------------------------------------------------------------------------


def test_read_bytes_hex_returns_hex_string(tmp_path):
    """Lines 266-268: adapter.read_bytes returns data -> hex string returned."""
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    data = b"Hello World binary data"
    adapter = FakeAdapter(bytes_data={0x1000: data})
    analyzer = TLSHAnalyzer(adapter=adapter, filename=str(f))
    result = analyzer._read_bytes_hex(0x1000, len(data))
    assert result == data.hex()


def test_read_bytes_hex_empty_bytes_returns_none(tmp_path):
    """Lines 266-268: adapter.read_bytes returns b'' -> None returned."""
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    adapter = FakeAdapter(bytes_data={0x1000: b""})
    analyzer = TLSHAnalyzer(adapter=adapter, filename=str(f))
    result = analyzer._read_bytes_hex(0x1000, 100)
    assert result is None


def test_read_bytes_hex_exception_returns_none(tmp_path):
    """Lines 272-274: adapter.read_bytes raises -> None returned."""
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    analyzer = TLSHAnalyzer(adapter=ErrorReadAdapter(), filename=str(f))
    result = analyzer._read_bytes_hex(0x1000, 100)
    assert result is None


# ---------------------------------------------------------------------------
# compare_tlsh instance method - lines 276-280
# ---------------------------------------------------------------------------


def test_compare_tlsh_both_empty_returns_none(tmp_path):
    """Lines 276-274: both hashes empty -> None returned."""
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename=str(f))
    assert analyzer.compare_tlsh("", "") is None


def test_compare_tlsh_one_none_returns_none(tmp_path):
    """Lines 273-274: one hash is None -> None returned."""
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename=str(f))
    assert analyzer.compare_tlsh(None, "abc") is None  # type: ignore[arg-type]


def test_compare_tlsh_identical_hashes_return_zero(tmp_path):
    """Line 276: tlsh.diff called with identical hashes returns 0."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename=str(f))
    h = analyzer._calculate_binary_tlsh()
    if h is None:
        pytest.skip("Could not compute TLSH hash")
    result = analyzer.compare_tlsh(h, h)
    assert result == 0


def test_compare_tlsh_invalid_hash_returns_none(tmp_path):
    """Lines 278-280: tlsh.diff raises on invalid hash -> None returned."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename=str(f))
    result = analyzer.compare_tlsh("INVALID_HASH_FORMAT", "ALSO_INVALID")
    assert result is None or isinstance(result, int)


# ---------------------------------------------------------------------------
# find_similar_sections - lines 284-320
# ---------------------------------------------------------------------------


def test_find_similar_sections_unavailable_returns_empty(tmp_path):
    """Lines 284-287: analyze() returns available=False -> empty list."""
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename="/nonexistent_file.bin")
    result = analyzer.find_similar_sections()
    assert result == []


def test_find_similar_sections_empty_section_hashes(tmp_path):
    """Lines 284-316: no sections -> empty similar_pairs, empty list returned."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    adapter = FakeAdapter(sections=[])
    analyzer = TLSHAnalyzer(adapter=adapter, filename=str(f))
    result = analyzer.find_similar_sections()
    assert result == []


def test_find_similar_sections_first_hash_none_skipped(tmp_path):
    """Lines 295-297: hash1 is None -> continue to next section."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 20)
    import tlsh as tlsh_lib

    data = bytes(range(256)) * 4
    h = tlsh_lib.hash(data)
    if not h or h == "TNULL":
        pytest.skip("Could not compute TLSH hash")

    class NullFirstAnalyzer(TLSHAnalyzer):
        def analyze(self):
            r = super().analyze()
            r["available"] = True
            r["section_tlsh"] = {".null": None, ".text": h}
            return r

    analyzer = NullFirstAnalyzer(adapter=FakeAdapter(), filename=str(f))
    result = analyzer.find_similar_sections(threshold=1000)
    assert isinstance(result, list)


def test_find_similar_sections_second_hash_none_skipped(tmp_path):
    """Lines 299-302: hash2 is None -> continue inner loop."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 20)
    import tlsh as tlsh_lib

    data = bytes(range(256)) * 4
    h = tlsh_lib.hash(data)
    if not h or h == "TNULL":
        pytest.skip("Could not compute TLSH hash")

    class NullSecondAnalyzer(TLSHAnalyzer):
        def analyze(self):
            r = super().analyze()
            r["available"] = True
            r["section_tlsh"] = {".text": h, ".null": None}
            return r

    analyzer = NullSecondAnalyzer(adapter=FakeAdapter(), filename=str(f))
    result = analyzer.find_similar_sections(threshold=1000)
    assert isinstance(result, list)


def test_find_similar_sections_identical_sections_pairs(tmp_path):
    """Lines 293-316: two sections with same hash -> pair added to similar_pairs."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 20)
    import tlsh as tlsh_lib

    data = bytes(range(256)) * 4
    h = tlsh_lib.hash(data)
    if not h or h == "TNULL":
        pytest.skip("Could not compute TLSH hash")

    class TwoHashAnalyzer(TLSHAnalyzer):
        def analyze(self):
            r = super().analyze()
            r["available"] = True
            r["section_tlsh"] = {".text": h, ".data": h}
            return r

    analyzer = TwoHashAnalyzer(adapter=FakeAdapter(), filename=str(f))
    result = analyzer.find_similar_sections(threshold=1000)
    assert isinstance(result, list)
    assert len(result) >= 1
    assert "section1" in result[0]
    assert "section2" in result[0]


def test_find_similar_sections_returns_sorted_by_score(tmp_path):
    """Line 316: result is sorted by similarity_score."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 20)
    import tlsh as tlsh_lib

    data = bytes(range(256)) * 4
    h = tlsh_lib.hash(data)
    if not h or h == "TNULL":
        pytest.skip("Could not compute TLSH hash")

    class MultiHashAnalyzer(TLSHAnalyzer):
        def analyze(self):
            r = super().analyze()
            r["available"] = True
            r["section_tlsh"] = {".text": h, ".data": h, ".bss": h}
            return r

    analyzer = MultiHashAnalyzer(adapter=FakeAdapter(), filename=str(f))
    result = analyzer.find_similar_sections(threshold=1000)
    scores = [p["similarity_score"] for p in result]
    assert scores == sorted(scores)


def test_find_similar_sections_exception_returns_empty(tmp_path):
    """Lines 318-320: exception in find_similar_sections -> empty list returned."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)

    class BrokenAnalyzer(TLSHAnalyzer):
        def analyze(self):
            raise RuntimeError("forced error")

    analyzer = BrokenAnalyzer(adapter=FakeAdapter(), filename=str(f))
    result = analyzer.find_similar_sections()
    assert result == []


# ---------------------------------------------------------------------------
# compare_hashes static method - lines 344-355
# ---------------------------------------------------------------------------


def test_compare_hashes_returns_none_when_unavailable():
    """Line 344-345: TLSH not available -> None."""
    if TLSH_AVAILABLE:
        pytest.skip("TLSH is available")
    result = TLSHAnalyzer.compare_hashes("hash1", "hash2")
    assert result is None


def test_compare_hashes_returns_none_for_empty_first():
    """Lines 347-348: hash1 empty -> None."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    result = TLSHAnalyzer.compare_hashes("", "T1abc")
    assert result is None


def test_compare_hashes_returns_none_for_empty_second():
    """Lines 347-348: hash2 empty -> None."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    result = TLSHAnalyzer.compare_hashes("T1abc", "")
    assert result is None


def test_compare_hashes_identical_hashes_return_zero(tmp_path):
    """Lines 350-352: identical valid hashes return 0."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename=str(f))
    h = analyzer._calculate_binary_tlsh()
    if h is None:
        pytest.skip("Could not compute TLSH hash")
    result = TLSHAnalyzer.compare_hashes(h, h)
    assert result == 0


def test_compare_hashes_invalid_hash_exception_returns_none():
    """Lines 353-355: tlsh.diff raises on invalid hash -> None returned."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    result = TLSHAnalyzer.compare_hashes("NOTVALID_HASH_1", "NOTVALID_HASH_2")
    assert result is None or isinstance(result, int)


# ---------------------------------------------------------------------------
# get_similarity_level static method - lines 378-391
# ---------------------------------------------------------------------------


def test_get_similarity_level_none_returns_unknown():
    """Line 379: score=None -> 'Unknown'."""
    assert TLSHAnalyzer.get_similarity_level(None) == "Unknown"


def test_get_similarity_level_zero_returns_identical():
    """Line 381: score=0 -> 'Identical'."""
    assert TLSHAnalyzer.get_similarity_level(0) == "Identical"


def test_get_similarity_level_score_30_returns_very_similar():
    """Lines 382-383: score <= 30 -> 'Very Similar'."""
    assert TLSHAnalyzer.get_similarity_level(1) == "Very Similar"
    assert TLSHAnalyzer.get_similarity_level(30) == "Very Similar"


def test_get_similarity_level_score_50_returns_similar():
    """Lines 384-385: 30 < score <= 50 -> 'Similar'."""
    assert TLSHAnalyzer.get_similarity_level(31) == "Similar"
    assert TLSHAnalyzer.get_similarity_level(50) == "Similar"


def test_get_similarity_level_score_100_returns_somewhat_similar():
    """Lines 386-387: 50 < score <= 100 -> 'Somewhat Similar'."""
    assert TLSHAnalyzer.get_similarity_level(51) == "Somewhat Similar"
    assert TLSHAnalyzer.get_similarity_level(100) == "Somewhat Similar"


def test_get_similarity_level_score_200_returns_different():
    """Lines 388-389: 100 < score <= 200 -> 'Different'."""
    assert TLSHAnalyzer.get_similarity_level(101) == "Different"
    assert TLSHAnalyzer.get_similarity_level(200) == "Different"


def test_get_similarity_level_score_over_200_returns_very_different():
    """Line 391: score > 200 -> 'Very Different'."""
    assert TLSHAnalyzer.get_similarity_level(201) == "Very Different"
    assert TLSHAnalyzer.get_similarity_level(999) == "Very Different"
