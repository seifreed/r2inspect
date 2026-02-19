# Copyright (c) 2025 Marc Rivero Lopez
# Licensed under GPLv3. See LICENSE file for details.
"""Tests targeting uncovered lines in simhash_analyzer.py."""

from __future__ import annotations

import tempfile
import os
from typing import Any

import pytest

from r2inspect.modules.simhash_analyzer import SIMHASH_AVAILABLE, SimHashAnalyzer


# ---------------------------------------------------------------------------
# Helpers: temporary binary file and adapter stubs
# ---------------------------------------------------------------------------

def _tmp_binary(size: int = 100) -> str:
    """Create a temporary binary file and return its path."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(b"x" * size)
        return f.name


class _BasicStubAdapter:
    """Minimal stub adapter returning empty results."""

    def get_strings(self) -> list:
        return []

    def get_functions(self) -> list:
        return []

    def get_sections(self) -> list:
        return []


class _StringsStubAdapter(_BasicStubAdapter):
    """Returns a set of strings that exercise all classification paths."""

    def get_strings(self) -> list:
        return [
            {"string": "http://example.com", "length": 18},   # url type
            {"string": "HKEY_LOCAL_MACHINE", "length": 18},   # registry type
            {"string": "LoadLibraryA", "length": 11},          # api type
            {"string": "C:\\Windows\\System32", "length": 18}, # path type
            {"string": "hello world this is a longer string that qualifies", "length": 50},
            {"string": "short"},                                 # too short, may be skipped
        ]


class _RaisingStringsAdapter(_BasicStubAdapter):
    """Adapter whose get_strings() raises, triggering exception handler."""

    def get_strings(self) -> list:
        raise RuntimeError("get_strings failed intentionally")


class _DataSectionAdapter(_BasicStubAdapter):
    """Adapter with get_sections() and read_bytes() for data section coverage."""

    def get_sections(self) -> list:
        return [
            {"name": ".data", "vaddr": 0x1000, "size": 256},
        ]

    def read_bytes(self, address: int, size: int) -> bytes:
        return b"Hello\x00World\x00TestString\x00" + b"\x00" * 50


class _FunctionAdapter(_BasicStubAdapter):
    """Adapter returning functions with disassembly."""

    def get_functions(self) -> list:
        return [
            {"name": "func_a", "offset": 0x1000, "size": 30},
            {"name": "func_b", "offset": 0x2000, "size": 30},
        ]

    def get_disasm(self, address: int = 0, size: int | None = None) -> list:
        return [
            {"mnemonic": "mov", "offset": address},
            {"mnemonic": "add", "offset": address + 2},
            {"mnemonic": "ret", "offset": address + 4},
        ]


class _RaisingFunctionAdapter(_BasicStubAdapter):
    """Adapter whose get_functions() raises an exception."""

    def get_functions(self) -> list:
        raise RuntimeError("get_functions failed intentionally")


# ---------------------------------------------------------------------------
# _calculate_hash – exception path (lines 64-66)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not installed")
def test_calculate_hash_exception_when_adapter_raises() -> None:
    """Lines 64-66: exception propagated from _extract_string_features is caught."""
    path = _tmp_binary()
    try:
        class _ExceptionStringFeatures(SimHashAnalyzer):
            """Subclass where _extract_string_features raises directly."""

            def _extract_string_features(self) -> list[str]:
                raise RuntimeError("string features exploded")

            def _extract_opcodes_features(self) -> list[str]:
                # Returns non-empty to trigger Simhash creation (which then succeeds)
                # but _extract_string_features raises first so this is moot
                return []

        analyzer = _ExceptionStringFeatures(adapter=_BasicStubAdapter(), filepath=path)
        hash_val, method, error = analyzer._calculate_hash()
        assert hash_val is None
        assert method is None
        assert error is not None
        assert "SimHash calculation failed" in error
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# _add_string_feature_set – STRTYPE: feature (line 127)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not installed")
def test_add_string_feature_set_appends_strtype_for_classified_string() -> None:
    """Line 127: STRTYPE: feature appended when string_type is not None."""
    path = _tmp_binary()
    try:
        analyzer = SimHashAnalyzer(adapter=_BasicStubAdapter(), filepath=path)
        features: list[str] = []
        analyzer._add_string_feature_set(features, "http://example.com")
        # Should have STR:, STRLEN:, and STRTYPE: features
        assert any(f.startswith("STRTYPE:") for f in features)
        assert any(f.startswith("STR:") for f in features)
        assert any(f.startswith("STRLEN:") for f in features)
    finally:
        os.unlink(path)


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not installed")
def test_add_string_feature_set_no_strtype_for_plain_string() -> None:
    """No STRTYPE: when string has no recognizable type."""
    path = _tmp_binary()
    try:
        analyzer = SimHashAnalyzer(adapter=_BasicStubAdapter(), filepath=path)
        features: list[str] = []
        analyzer._add_string_feature_set(features, "just a plain text string here")
        # STR: and STRLEN: should be present; STRTYPE: should NOT
        assert any(f.startswith("STR:") for f in features)
        assert not any(f.startswith("STRTYPE:") for f in features)
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# _extract_function_features – exception paths (lines 212-214, 219-221)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not installed")
def test_extract_function_features_skips_bad_simhash_entry() -> None:
    """Lines 212-214: exception creating Simhash for a function is caught."""
    path = _tmp_binary()
    try:
        class _NoneOpcodeAdapter(_BasicStubAdapter):
            """Returns function with opcodes list that causes Simhash to raise."""

            def get_functions(self) -> list:
                return [{"name": "bad_func", "offset": 0x1000, "size": 10}]

        class _NoneOpcodesAnalyzer(SimHashAnalyzer):
            """Override opcode extraction to return [None] which causes Simhash to raise."""

            def _extract_function_opcodes(self, func_addr: int, func_name: str) -> list:
                return [None]  # Simhash([None]) raises TypeError

        analyzer = _NoneOpcodesAnalyzer(adapter=_NoneOpcodeAdapter(), filepath=path)
        result = analyzer._extract_function_features()
        # Should complete without raising; the bad function is skipped
        assert isinstance(result, dict)
        # The bad function should NOT be in result (was skipped)
        assert "bad_func" not in result
    finally:
        os.unlink(path)


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not installed")
def test_extract_function_features_outer_exception_returns_empty() -> None:
    """Lines 219-221: outer exception in get_functions() propagates and returns {}."""
    path = _tmp_binary()
    try:
        analyzer = SimHashAnalyzer(adapter=_RaisingFunctionAdapter(), filepath=path)
        result = analyzer._extract_function_features()
        assert result == {}
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# _append_data_section_string – read_bytes path (lines 281-282)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not installed")
def test_append_data_section_string_reads_bytes_from_data_section() -> None:
    """Lines 281-282: read_bytes is called and printable strings are extracted."""
    path = _tmp_binary()
    try:
        data_strings: list[str] = []
        analyzer = SimHashAnalyzer(adapter=_DataSectionAdapter(), filepath=path)
        section = {"name": ".data", "vaddr": 0x1000, "size": 256}
        analyzer._append_data_section_string(section, data_strings)
        # Printable strings from the bytes should be extracted
        assert len(data_strings) >= 1
        assert all(s.startswith("DATASTR:") for s in data_strings)
    finally:
        os.unlink(path)


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not installed")
def test_append_data_section_string_skips_non_data_sections() -> None:
    """Lines 289-291: non-.data sections are skipped early."""
    path = _tmp_binary()
    try:
        data_strings: list[str] = []
        analyzer = SimHashAnalyzer(adapter=_DataSectionAdapter(), filepath=path)
        section = {"name": ".text", "vaddr": 0x400000, "size": 4096}
        analyzer._append_data_section_string(section, data_strings)
        assert data_strings == []
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# _find_similar_functions – happy path (lines 427, 438, 447-448, 452)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not installed")
def test_find_similar_functions_groups_identical_hashes() -> None:
    """Lines 427, 438, 447-448, 452: similar functions are grouped and sorted.

    Two functions with identical simhash values will always have distance=0 <= max_distance.
    """
    from simhash import Simhash

    path = _tmp_binary()
    try:
        analyzer = SimHashAnalyzer(adapter=_BasicStubAdapter(), filepath=path)

        shared_hash = Simhash(["OP:mov", "OP:add", "OP:ret"]).value
        different_hash = Simhash(["OP:push", "OP:call", "OP:pop"]).value

        func_features = {
            "func_a": {
                "addr": 0x1000,
                "size": 20,
                "simhash": shared_hash,
                "feature_count": 3,
                "unique_opcodes": 3,
            },
            "func_b": {
                "addr": 0x1100,
                "size": 20,
                "simhash": shared_hash,  # identical to func_a
                "feature_count": 3,
                "unique_opcodes": 3,
            },
            "func_c": {
                "addr": 0x1200,
                "size": 20,
                "simhash": different_hash,  # different from a/b
                "feature_count": 3,
                "unique_opcodes": 3,
            },
        }

        groups = analyzer._find_similar_functions(func_features, max_distance=5)

        assert len(groups) >= 1
        assert groups[0]["count"] == 2  # func_a and func_b grouped together
        # Lines 447-448: func_b was appended to similar_funcs; 452: sort was called
    finally:
        os.unlink(path)


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not installed")
def test_find_similar_functions_skips_already_processed() -> None:
    """Line 438: inner loop skips functions already added to a group."""
    from simhash import Simhash

    path = _tmp_binary()
    try:
        analyzer = SimHashAnalyzer(adapter=_BasicStubAdapter(), filepath=path)

        shared_hash = Simhash(["OP:mov", "OP:add"]).value

        func_features = {
            "fa": {"addr": 0x1000, "size": 10, "simhash": shared_hash, "feature_count": 2, "unique_opcodes": 2},
            "fb": {"addr": 0x1100, "size": 10, "simhash": shared_hash, "feature_count": 2, "unique_opcodes": 2},
            "fc": {"addr": 0x1200, "size": 10, "simhash": shared_hash, "feature_count": 2, "unique_opcodes": 2},
        }

        groups = analyzer._find_similar_functions(func_features, max_distance=5)
        # All three share the same hash -> one group with 3 members
        assert groups[0]["count"] == 3
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# calculate_similarity – full flow (lines 485-524)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not installed")
def test_calculate_similarity_returns_error_when_hash_type_not_in_results() -> None:
    """Lines 478-494: returns error dict when no matching hash type in results."""
    path = _tmp_binary()
    try:
        analyzer = SimHashAnalyzer(adapter=_StringsStubAdapter(), filepath=path)
        result = analyzer.calculate_similarity(12345678, hash_type="combined")
        assert "error" in result
        assert "combined" in result["error"]
    finally:
        os.unlink(path)


class _SimHashAnalyzerWithFullResults(SimHashAnalyzer):
    """Subclass providing combined_simhash in analyze() to exercise the full similarity path."""

    _hash_val: int | None = None

    def analyze(self) -> dict[str, Any]:
        from simhash import Simhash as _Simhash

        h = _Simhash(["OP:mov", "OP:add", "OP:ret", "OP:nop"]).value
        self._hash_val = h
        return {
            "available": True,
            "hash_value": hex(h),
            "hash_type": "simhash",
            "combined_simhash": {"hash": h},
            "strings_simhash": {"hash": h},
            "opcodes_simhash": {"hash": h},
        }


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not installed")
def test_calculate_similarity_identical_hash_returns_identical_level() -> None:
    """Lines 496-520: distance=0 returns similarity_level='identical'."""
    from simhash import Simhash

    path = _tmp_binary()
    try:
        analyzer = _SimHashAnalyzerWithFullResults(
            adapter=_BasicStubAdapter(), filepath=path
        )
        analyzer.analyze()  # prime the hash value
        same_hash = Simhash(["OP:mov", "OP:add", "OP:ret", "OP:nop"]).value

        result = analyzer.calculate_similarity(same_hash, hash_type="combined")
        assert result["similarity_level"] == "identical"
        assert result["distance"] == 0
    finally:
        os.unlink(path)


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not installed")
def test_calculate_similarity_very_similar() -> None:
    """Lines 505-506: distance <= 5 -> similarity_level='very_similar'."""
    from simhash import Simhash

    path = _tmp_binary()
    try:
        analyzer = _SimHashAnalyzerWithFullResults(
            adapter=_BasicStubAdapter(), filepath=path
        )
        base_hash = Simhash(["OP:mov", "OP:add", "OP:ret", "OP:nop"]).value

        # Use a slightly different hash (flip 1-2 bits) to get small distance
        slightly_different = base_hash ^ 0b01  # flip 1 bit

        result = analyzer.calculate_similarity(slightly_different, hash_type="combined")
        # distance is either 0 or very small
        assert result["distance"] <= 5
        assert result["similarity_level"] in ("identical", "very_similar")
    finally:
        os.unlink(path)


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not installed")
def test_calculate_similarity_similar_level() -> None:
    """Line 508: distance 6-15 -> similarity_level='similar'."""
    from simhash import Simhash

    path = _tmp_binary()
    try:
        analyzer = _SimHashAnalyzerWithFullResults(
            adapter=_BasicStubAdapter(), filepath=path
        )
        base_hash = Simhash(["OP:mov", "OP:add", "OP:ret", "OP:nop"]).value
        # XOR 8 bits → distance = 8, in range [6, 15] → "similar"
        eight_bits_different = base_hash ^ 0xFF

        result = analyzer.calculate_similarity(eight_bits_different, hash_type="combined")
        assert result.get("distance") == 8
        assert result.get("similarity_level") == "similar"
    finally:
        os.unlink(path)


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not installed")
def test_calculate_similarity_different_level() -> None:
    """Line 512: distance > 25 -> similarity_level='different'."""
    from simhash import Simhash

    path = _tmp_binary()
    try:
        analyzer = _SimHashAnalyzerWithFullResults(
            adapter=_BasicStubAdapter(), filepath=path
        )
        base_hash = Simhash(["OP:mov", "OP:add", "OP:ret", "OP:nop"]).value
        # XOR 30 bits → distance = 30, > 25 → "different"
        thirty_bits_different = base_hash ^ 0x3FFFFFFF

        result = analyzer.calculate_similarity(thirty_bits_different, hash_type="combined")
        assert result.get("distance") == 30
        assert result.get("similarity_level") == "different"
    finally:
        os.unlink(path)


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not installed")
def test_calculate_similarity_somewhat_similar_level() -> None:
    """Line 510: distance 16-25 -> similarity_level='somewhat_similar'."""
    from simhash import Simhash

    path = _tmp_binary()
    try:
        analyzer = _SimHashAnalyzerWithFullResults(
            adapter=_BasicStubAdapter(), filepath=path
        )
        base_hash = Simhash(["OP:mov", "OP:add", "OP:ret", "OP:nop"]).value
        # XOR 20 bits → distance = 20, in range [16, 25] → "somewhat_similar"
        twenty_bits_different = base_hash ^ 0xFFFFF  # 20 bits

        result = analyzer.calculate_similarity(twenty_bits_different, hash_type="combined")
        assert result.get("distance") == 20
        assert result.get("similarity_level") == "somewhat_similar"
    finally:
        os.unlink(path)


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not installed")
def test_calculate_similarity_strings_hash_type() -> None:
    """Lines 488-489: strings hash type path exercises the elif branch."""
    from simhash import Simhash

    path = _tmp_binary()
    try:
        analyzer = _SimHashAnalyzerWithFullResults(
            adapter=_BasicStubAdapter(), filepath=path
        )
        h = Simhash(["OP:mov", "OP:add", "OP:ret", "OP:nop"]).value
        result = analyzer.calculate_similarity(h, hash_type="strings")
        assert "distance" in result
        assert result["hash_type"] == "strings"
    finally:
        os.unlink(path)


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not installed")
def test_calculate_similarity_opcodes_hash_type() -> None:
    """Lines 490-491: opcodes hash type path exercises the second elif branch."""
    from simhash import Simhash

    path = _tmp_binary()
    try:
        analyzer = _SimHashAnalyzerWithFullResults(
            adapter=_BasicStubAdapter(), filepath=path
        )
        h = Simhash(["OP:mov", "OP:add", "OP:ret", "OP:nop"]).value
        result = analyzer.calculate_similarity(h, hash_type="opcodes")
        assert "distance" in result
        assert result["hash_type"] == "opcodes"
    finally:
        os.unlink(path)


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not installed")
def test_calculate_similarity_exception_in_analysis() -> None:
    """Lines 522-524: exception in analyze() is caught and returned as error dict."""

    class _RaisingAnalyzer(SimHashAnalyzer):
        def analyze(self) -> dict[str, Any]:
            raise RuntimeError("analysis exploded")

    path = _tmp_binary()
    try:
        analyzer = _RaisingAnalyzer(adapter=_BasicStubAdapter(), filepath=path)
        result = analyzer.calculate_similarity(12345678)
        assert "error" in result
        assert "analysis exploded" in result["error"]
    finally:
        os.unlink(path)


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not installed")
def test_calculate_similarity_returns_error_when_not_available() -> None:
    """Lines 474-475: returns error when analyze() says not available."""
    path = _tmp_binary()
    try:
        analyzer = SimHashAnalyzer(adapter=_RaisingStringsAdapter(), filepath=path)
        result = analyzer.calculate_similarity(12345678)
        # _RaisingStringsAdapter makes analyze() fail -> available=False
        assert "error" in result
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# compare_hashes – exception path (line 547-549)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not installed")
def test_compare_hashes_exception_returns_none() -> None:
    """Lines 547-549: exception during hash comparison returns None."""
    # Non-hex string will raise ValueError in int(hash1, 16)
    result = SimHashAnalyzer.compare_hashes("not_hex_at_all", "0x12345678")
    assert result is None


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not installed")
def test_compare_hashes_same_value_returns_zero() -> None:
    """Lines 535-545: comparing same hash returns distance of 0."""
    h = "0xdeadbeef"
    result = SimHashAnalyzer.compare_hashes(h, h)
    assert result == 0


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not installed")
def test_compare_hashes_integer_inputs() -> None:
    """Lines 537-539: integer inputs are handled directly without conversion."""
    result = SimHashAnalyzer.compare_hashes(0xDEADBEEF, 0xDEADBEEF)
    assert result == 0


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not installed")
def test_compare_hashes_returns_none_for_empty() -> None:
    """Lines 532-533: empty hash inputs return None."""
    assert SimHashAnalyzer.compare_hashes("", "0x1234") is None
    assert SimHashAnalyzer.compare_hashes("0x1234", "") is None


# ---------------------------------------------------------------------------
# Full analyze() flow with strings (covers main paths)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not installed")
def test_analyze_with_classified_strings() -> None:
    """Exercises the full analyze path including STRTYPE features."""
    path = _tmp_binary()
    try:
        analyzer = SimHashAnalyzer(adapter=_StringsStubAdapter(), filepath=path)
        result = analyzer.analyze()
        assert result["available"] is True
        assert result["hash_value"] is not None
    finally:
        os.unlink(path)


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not installed")
def test_analyze_with_data_section_adapter() -> None:
    """Exercises data section string extraction path."""
    path = _tmp_binary()
    try:
        analyzer = SimHashAnalyzer(adapter=_DataSectionAdapter(), filepath=path)
        result = analyzer.analyze()
        assert "available" in result
    finally:
        os.unlink(path)


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not installed")
def test_analyze_with_functions_provides_opcodes() -> None:
    """Exercises opcode extraction via get_disasm adapter method."""
    path = _tmp_binary()
    try:
        analyzer = SimHashAnalyzer(adapter=_FunctionAdapter(), filepath=path)
        result = analyzer.analyze()
        assert "available" in result
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# is_available static method
# ---------------------------------------------------------------------------

def test_is_available_matches_constant() -> None:
    """SimHashAnalyzer.is_available() mirrors the SIMHASH_AVAILABLE constant."""
    assert SimHashAnalyzer.is_available() == SIMHASH_AVAILABLE
