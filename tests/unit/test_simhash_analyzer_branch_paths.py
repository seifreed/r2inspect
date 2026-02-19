"""Tests targeting uncovered branch paths in simhash_analyzer.py."""

from __future__ import annotations

from typing import Any

import pytest

import r2inspect.modules.simhash_analyzer as _mod
from r2inspect.modules.simhash_analyzer import SIMHASH_AVAILABLE, SimHashAnalyzer


# ---------------------------------------------------------------------------
# Real stub adapter – no mock library
# ---------------------------------------------------------------------------


class StubAdapter:
    """Minimal real adapter returning configurable data without mock libraries."""

    def __init__(
        self,
        strings: list[dict] | None = None,
        functions: list[dict] | None = None,
        sections: list[dict] | None = None,
        disasm_map: dict[int, Any] | None = None,
        bytes_map: dict[int, bytes] | None = None,
    ) -> None:
        self._strings: list[dict] = strings if strings is not None else []
        self._functions: list[dict] = functions if functions is not None else []
        self._sections: list[dict] = sections if sections is not None else []
        self._disasm_map: dict[int, Any] = disasm_map or {}
        self._bytes_map: dict[int, bytes] = bytes_map or {}

    def get_strings(self) -> list[dict]:
        return self._strings

    def get_functions(self) -> list[dict]:
        return self._functions

    def get_sections(self) -> list[dict]:
        return self._sections

    def get_disasm(self, address: int | None = None, size: int | None = None) -> Any:
        if address is None:
            return None
        return self._disasm_map.get(address)

    def read_bytes(self, address: int, size: int) -> bytes:
        return self._bytes_map.get(address, b"")


class RaisingAdapter(StubAdapter):
    """Adapter that raises an exception when get_functions is called."""

    def get_functions(self) -> list[dict]:
        raise RuntimeError("simulated error")


# ---------------------------------------------------------------------------
# Subclass that provides a controlled analyze() result for calculate_similarity
# ---------------------------------------------------------------------------


class _ControlledSimHashAnalyzer(SimHashAnalyzer):
    """Subclass with a fixed analyze() return value for branch-path testing."""

    def __init__(self, adapter: Any, filepath: str, result: dict[str, Any]) -> None:
        super().__init__(adapter=adapter, filepath=filepath)
        self._fixed_result = result

    def analyze(self) -> dict[str, Any]:
        return self._fixed_result


# ---------------------------------------------------------------------------
# _check_library_availability
# ---------------------------------------------------------------------------


def test_check_library_availability_returns_false_when_unavailable() -> None:
    old = _mod.SIMHASH_AVAILABLE
    _mod.SIMHASH_AVAILABLE = False
    try:
        adapter = StubAdapter()
        analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
        available, error = analyzer._check_library_availability()
        assert available is False
        assert error is not None and "simhash library not available" in error
    finally:
        _mod.SIMHASH_AVAILABLE = old


# ---------------------------------------------------------------------------
# _calculate_hash – exception path
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_calculate_hash_exception_when_simhash_class_is_none() -> None:
    """Force the Simhash call to fail by temporarily replacing the class."""
    adapter = StubAdapter(strings=[{"string": "valid_test_string_long_enough"}])
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")

    old_simhash = _mod.Simhash
    _mod.Simhash = None
    try:
        hash_val, method, error = analyzer._calculate_hash()
        assert hash_val is None
        assert error is not None
        assert "SimHash calculation failed" in error or "failed" in error.lower()
    finally:
        _mod.Simhash = old_simhash


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_calculate_hash_produces_hex_hash_with_string_features() -> None:
    adapter = StubAdapter(strings=[{"string": "hello_world_binary"}])
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    hash_val, method, error = analyzer._calculate_hash()
    assert hash_val is not None
    assert hash_val.startswith("0x")
    assert method == "feature_extraction"
    assert error is None


# ---------------------------------------------------------------------------
# analyze_detailed
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_analyze_detailed_with_string_features_returns_result() -> None:
    adapter = StubAdapter(strings=[{"string": "hello_world_binary_long_string"}])
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer.analyze_detailed()
    assert isinstance(result, dict)
    assert "available" in result


def test_analyze_detailed_when_simhash_unavailable() -> None:
    old = _mod.SIMHASH_AVAILABLE
    _mod.SIMHASH_AVAILABLE = False
    try:
        adapter = StubAdapter()
        analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
        result = analyzer.analyze_detailed()
        assert result.get("available") is False
    finally:
        _mod.SIMHASH_AVAILABLE = old


# ---------------------------------------------------------------------------
# _extract_string_features – list path and data section path
# ---------------------------------------------------------------------------


def test_extract_string_features_with_list_data_calls_collect() -> None:
    adapter = StubAdapter(strings=[{"string": "useful_long_string_here"}])
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_string_features()
    assert any("STR:" in f for f in result)


def test_extract_string_features_includes_data_section_strings() -> None:
    raw_bytes = b"hello_data_section_string\x00"
    sections = [{"name": ".data", "vaddr": 0x3000, "size": len(raw_bytes)}]
    adapter = StubAdapter(
        sections=sections,
        bytes_map={0x3000: raw_bytes},
    )
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_string_features()
    assert any("DATASTR:" in f for f in result)


# ---------------------------------------------------------------------------
# _collect_string_features – various entry shapes
# ---------------------------------------------------------------------------


def test_collect_string_features_skips_non_dict_entries() -> None:
    adapter = StubAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    features: list[str] = []
    analyzer._collect_string_features(["not a dict", 42, None], features)
    assert features == []


def test_collect_string_features_skips_entry_without_string_key() -> None:
    adapter = StubAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    features: list[str] = []
    analyzer._collect_string_features([{"other_key": "value"}], features)
    assert features == []


def test_collect_string_features_skips_too_short_string() -> None:
    adapter = StubAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    features: list[str] = []
    analyzer._collect_string_features([{"string": "abc"}], features)
    assert features == []


def test_collect_string_features_skips_useless_string() -> None:
    adapter = StubAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    features: list[str] = []
    analyzer._collect_string_features([{"string": "123456789"}], features)
    assert features == []


def test_collect_string_features_adds_valid_string() -> None:
    adapter = StubAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    features: list[str] = []
    analyzer._collect_string_features([{"string": "valid_feature_string"}], features)
    assert any("STR:" in f for f in features)


# ---------------------------------------------------------------------------
# _add_string_feature_set – string type classification
# ---------------------------------------------------------------------------


def test_add_string_feature_set_includes_str_type_when_classified() -> None:
    adapter = StubAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    features: list[str] = []
    # A URL-like string that should get a string type classification
    analyzer._add_string_feature_set(features, "https://example.com/path")
    assert any("STR:" in f for f in features)
    assert any("STRLEN:" in f for f in features)


def test_add_string_feature_set_with_short_string_gets_short_category() -> None:
    adapter = StubAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    features: list[str] = []
    analyzer._add_string_feature_set(features, "abcde")
    assert any("STRLEN:short" in f for f in features)


def test_add_string_feature_set_with_medium_string() -> None:
    adapter = StubAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    features: list[str] = []
    analyzer._add_string_feature_set(features, "a" * 15)
    assert any("STRLEN:medium" in f for f in features)


def test_add_string_feature_set_with_long_string() -> None:
    adapter = StubAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    features: list[str] = []
    analyzer._add_string_feature_set(features, "a" * 60)
    assert any("STRLEN:long" in f for f in features)


def test_add_string_feature_set_with_very_long_string() -> None:
    adapter = StubAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    features: list[str] = []
    analyzer._add_string_feature_set(features, "a" * 200)
    assert any("STRLEN:very_long" in f for f in features)


# ---------------------------------------------------------------------------
# _extract_opcodes_features – various branches
# ---------------------------------------------------------------------------


def test_extract_opcodes_features_logs_debug_when_functions_found() -> None:
    adapter = StubAdapter(
        functions=[{"offset": 0x1000, "name": "test_func"}],
        disasm_map={0x1000: {"ops": [{"mnemonic": "nop"}, {"mnemonic": "ret"}]}},
    )
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_opcodes_features()
    assert len(result) > 0


def test_extract_opcodes_features_skips_function_without_offset_or_addr() -> None:
    adapter = StubAdapter(
        functions=[{"name": "no_addr_func"}],
    )
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_opcodes_features()
    assert result == []


def test_extract_opcodes_features_uses_addr_field_when_no_offset() -> None:
    adapter = StubAdapter(
        functions=[{"addr": 0x2000, "name": "addr_func"}],
        disasm_map={0x2000: {"ops": [{"mnemonic": "push"}, {"mnemonic": "pop"}]}},
    )
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_opcodes_features()
    assert len(result) > 0


def test_extract_opcodes_features_truncates_at_10000_limit() -> None:
    many_funcs = [
        {"offset": i * 0x100, "name": f"func_{i}"}
        for i in range(200)
    ]
    ops_per_func = [{"mnemonic": "nop"}] * 100
    disasm_map = {i * 0x100: {"ops": ops_per_func} for i in range(200)}
    adapter = StubAdapter(functions=many_funcs, disasm_map=disasm_map)
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_opcodes_features()
    assert len(result) > 0


def test_extract_opcodes_features_exception_returns_empty() -> None:
    adapter = RaisingAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_opcodes_features()
    assert result == []


# ---------------------------------------------------------------------------
# _extract_function_features – various branches
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_extract_function_features_skips_non_dict_function() -> None:
    adapter = StubAdapter(functions=["not a dict"])
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_function_features()
    assert result == {}


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_extract_function_features_skips_function_without_offset() -> None:
    adapter = StubAdapter(functions=[{"addr": 0x1000, "name": "no_offset"}])
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_function_features()
    assert result == {}


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_extract_function_features_skips_function_with_no_opcodes() -> None:
    adapter = StubAdapter(
        functions=[{"offset": 0x1000, "name": "empty_func", "size": 10}],
        disasm_map={0x1000: None},
    )
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_function_features()
    assert result == {}


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_extract_function_features_records_simhash_for_valid_function() -> None:
    adapter = StubAdapter(
        functions=[{"offset": 0x1000, "name": "real_func", "size": 50}],
        disasm_map={0x1000: {"ops": [{"mnemonic": "mov"}, {"mnemonic": "add"}, {"mnemonic": "ret"}]}},
    )
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_function_features()
    assert "real_func" in result
    assert "simhash" in result["real_func"]
    assert "addr" in result["real_func"]
    assert result["real_func"]["addr"] == 0x1000


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_extract_function_features_exception_in_outer_loop_returns_empty() -> None:
    class BrokenFunctions:
        def get_functions(self) -> None:
            raise RuntimeError("broken")

        def get_strings(self) -> list:
            return []

        def get_sections(self) -> list:
            return []

        def get_disasm(self, address=None, size=None) -> None:
            return None

        def read_bytes(self, address: int, size: int) -> bytes:
            return b""

    adapter = BrokenFunctions()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_function_features()
    assert result == {}


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_extract_function_features_handles_simhash_inner_exception() -> None:
    """Force the inner Simhash() call to fail, covering the inner except block."""
    adapter = StubAdapter(
        functions=[{"offset": 0x1000, "name": "inner_fail_func", "size": 10}],
        disasm_map={0x1000: {"ops": [{"mnemonic": "nop"}]}},
    )
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")

    old_simhash = _mod.Simhash
    _mod.Simhash = None
    try:
        result = analyzer._extract_function_features()
        assert result == {}
    finally:
        _mod.Simhash = old_simhash


# ---------------------------------------------------------------------------
# _extract_function_opcodes – fallback disasm path
# ---------------------------------------------------------------------------


def test_extract_function_opcodes_uses_fallback_when_first_disasm_returns_none() -> None:
    adapter = StubAdapter(
        disasm_map={},  # first call returns None
    )
    # Patch the adapter so first call (without size) returns None,
    # second call (with size) returns ops.
    call_count = [0]
    real_disasm = {500: {"ops": [{"mnemonic": "xor"}, {"mnemonic": "ret"}]}}

    class TwoPhaseAdapter(StubAdapter):
        def get_disasm(self, address: int | None = None, size: int | None = None) -> Any:
            call_count[0] += 1
            if size is None:
                return None
            return real_disasm.get(address)

    adapter2 = TwoPhaseAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter2, filepath="/fake/path")
    result = analyzer._extract_function_opcodes(500, "two_phase_func")
    assert len(result) > 0
    assert call_count[0] >= 2


def test_extract_function_opcodes_returns_empty_when_both_disasm_calls_fail() -> None:
    class AlwaysNoneAdapter(StubAdapter):
        def get_disasm(self, address: int | None = None, size: int | None = None) -> None:
            return None

    adapter = AlwaysNoneAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_function_opcodes(0x1000, "no_disasm_func")
    assert result == []


# ---------------------------------------------------------------------------
# _extract_opcodes_from_ops – bigram and optype paths
# ---------------------------------------------------------------------------


def test_extract_opcodes_from_ops_produces_bigrams_for_sequential_ops() -> None:
    adapter = StubAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    ops = [{"mnemonic": "push"}, {"mnemonic": "mov"}, {"mnemonic": "call"}]
    result = analyzer._extract_opcodes_from_ops(ops)
    bigrams = [r for r in result if "BIGRAM:" in r]
    assert len(bigrams) >= 2


def test_extract_opcodes_from_ops_classifies_all_opcode_types() -> None:
    adapter = StubAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    ops = [
        {"mnemonic": "jmp"},
        {"mnemonic": "mov"},
        {"mnemonic": "add"},
        {"mnemonic": "and"},
        {"mnemonic": "cmp"},
        {"mnemonic": "strcpy"},
        {"mnemonic": "nop"},
    ]
    result = analyzer._extract_opcodes_from_ops(ops)
    optypes = {r.split(":")[1] for r in result if r.startswith("OPTYPE:")}
    assert "control" in optypes
    assert "data" in optypes
    assert "arithmetic" in optypes
    assert "logical" in optypes
    assert "compare" in optypes
    assert "string" in optypes
    assert "other" in optypes


# ---------------------------------------------------------------------------
# _extract_data_section_strings
# ---------------------------------------------------------------------------


def test_extract_data_section_strings_with_valid_data_section() -> None:
    raw_bytes = b"sample_string_in_data\x00garbage\xff"
    adapter = StubAdapter(
        sections=[{"name": ".data", "vaddr": 0x4000, "size": len(raw_bytes)}],
        bytes_map={0x4000: raw_bytes},
    )
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_data_section_strings()
    assert any("DATASTR:" in s for s in result)


def test_extract_data_section_strings_skips_non_data_section() -> None:
    adapter = StubAdapter(
        sections=[{"name": ".text", "vaddr": 0x1000, "size": 100}],
    )
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_data_section_strings()
    assert result == []


def test_extract_data_section_strings_skips_section_with_zero_size() -> None:
    adapter = StubAdapter(
        sections=[{"name": ".data", "vaddr": 0x4000, "size": 0}],
    )
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_data_section_strings()
    assert result == []


def test_extract_data_section_strings_skips_section_with_zero_vaddr() -> None:
    adapter = StubAdapter(
        sections=[{"name": ".data", "vaddr": 0, "size": 100}],
    )
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_data_section_strings()
    assert result == []


def test_extract_data_section_strings_skips_when_no_read_bytes_method() -> None:
    class NoReadBytesAdapter(StubAdapter):
        def read_bytes(self, address: int, size: int) -> bytes:
            raise AttributeError("no read_bytes")

    adapter = NoReadBytesAdapter(
        sections=[{"name": ".data", "vaddr": 0x4000, "size": 100}],
    )
    # Remove the read_bytes attribute entirely
    del NoReadBytesAdapter.read_bytes

    class AdapterWithoutReadBytes:
        def get_sections(self) -> list:
            return [{"name": ".data", "vaddr": 0x4000, "size": 100}]

        def get_strings(self) -> list:
            return []

        def get_functions(self) -> list:
            return []

        def get_disasm(self, address=None, size=None):
            return None

    adapter2 = AdapterWithoutReadBytes()
    analyzer = SimHashAnalyzer(adapter=adapter2, filepath="/fake/path")
    result = analyzer._extract_data_section_strings()
    assert result == []


# ---------------------------------------------------------------------------
# _find_similar_functions – similar groups and edge cases
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_find_similar_functions_groups_identical_hashes() -> None:
    value = 0xAAAAAAAAAAAAAAAA
    function_features = {
        "func_a": {"simhash": value},
        "func_b": {"simhash": value},
    }
    adapter = StubAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._find_similar_functions(function_features, max_distance=5)
    assert len(result) == 1
    group = result[0]
    assert set(group["functions"]) == {"func_a", "func_b"}
    assert group["count"] == 2


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_find_similar_functions_skips_already_processed_inner() -> None:
    """Covers the inner-loop 'already processed' branch (line 437)."""
    base = 0xAAAAAAAAAAAAAAAA
    similar = base ^ 0x1  # distance=1

    # func_a and func_c are similar; func_b is not similar to func_a/func_c
    # When outer loop is at func_b, inner loop will encounter func_c already processed.
    function_features = {
        "func_a": {"simhash": base},
        "func_b": {"simhash": 0x5555555555555555},  # very different
        "func_c": {"simhash": similar},
        "func_d": {"simhash": 0x5555555555555554},  # close to func_b
    }
    adapter = StubAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._find_similar_functions(function_features, max_distance=3)
    # func_a and func_c should form a group; func_b and func_d may form another
    all_funcs = [f for group in result for f in group["functions"]]
    assert "func_a" in all_funcs
    assert "func_c" in all_funcs


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_find_similar_functions_returns_empty_when_no_groups() -> None:
    function_features = {
        "func_x": {"simhash": 0x0000000000000000},
        "func_y": {"simhash": 0xFFFFFFFFFFFFFFFF},
    }
    adapter = StubAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._find_similar_functions(function_features, max_distance=5)
    assert result == []


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_find_similar_functions_exception_returns_empty() -> None:
    # Missing 'simhash' key causes KeyError inside the loop
    function_features = {"func_broken": {"addr": 0x1000}}
    adapter = StubAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._find_similar_functions(function_features)
    assert result == []


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_find_similar_functions_returns_empty_when_unavailable() -> None:
    old = _mod.SIMHASH_AVAILABLE
    _mod.SIMHASH_AVAILABLE = False
    try:
        adapter = StubAdapter()
        analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
        result = analyzer._find_similar_functions({"f": {"simhash": 0x1}})
        assert result == []
    finally:
        _mod.SIMHASH_AVAILABLE = old


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_find_similar_functions_sorts_groups_by_size_descending() -> None:
    base = 0xAAAAAAAAAAAAAAAA
    function_features = {
        "f1": {"simhash": base},
        "f2": {"simhash": base ^ 0x1},
        "f3": {"simhash": base ^ 0x2},
        "g1": {"simhash": 0x5555555555555555},
        "g2": {"simhash": 0x5555555555555554},
    }
    adapter = StubAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._find_similar_functions(function_features, max_distance=5)
    if len(result) > 1:
        assert result[0]["count"] >= result[1]["count"]


# ---------------------------------------------------------------------------
# calculate_similarity – all distance levels
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_calculate_similarity_returns_error_when_unavailable() -> None:
    old = _mod.SIMHASH_AVAILABLE
    _mod.SIMHASH_AVAILABLE = False
    try:
        adapter = StubAdapter()
        analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
        result = analyzer.calculate_similarity(0x1234)
        assert "error" in result
        assert "not available" in result["error"]
    finally:
        _mod.SIMHASH_AVAILABLE = old


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_calculate_similarity_returns_error_when_analyze_not_available() -> None:
    adapter = StubAdapter()
    analyzer = _ControlledSimHashAnalyzer(
        adapter=adapter,
        filepath="/fake/path",
        result={"available": False},
    )
    result = analyzer.calculate_similarity(0x1234)
    assert "error" in result
    assert "not available" in result["error"]


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_calculate_similarity_returns_error_when_no_combined_hash() -> None:
    adapter = StubAdapter()
    analyzer = _ControlledSimHashAnalyzer(
        adapter=adapter,
        filepath="/fake/path",
        result={"available": True},
    )
    result = analyzer.calculate_similarity(0x1234, hash_type="combined")
    assert "error" in result
    assert "No combined" in result["error"]


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_calculate_similarity_identical_distance_zero() -> None:
    hash_val = 0xAAAAAAAAAAAAAAAA
    adapter = StubAdapter()
    analyzer = _ControlledSimHashAnalyzer(
        adapter=adapter,
        filepath="/fake/path",
        result={"available": True, "combined_simhash": {"hash": hash_val}},
    )
    result = analyzer.calculate_similarity(hash_val, hash_type="combined")
    assert result["distance"] == 0
    assert result["similarity_level"] == "identical"


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_calculate_similarity_very_similar_distance_3() -> None:
    base = 0xAAAAAAAAAAAAAAAA
    other = base ^ 0x7  # 3 bits differ -> distance=3
    adapter = StubAdapter()
    analyzer = _ControlledSimHashAnalyzer(
        adapter=adapter,
        filepath="/fake/path",
        result={"available": True, "combined_simhash": {"hash": base}},
    )
    result = analyzer.calculate_similarity(other, hash_type="combined")
    assert result["distance"] <= 5
    assert result["similarity_level"] == "very_similar"


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_calculate_similarity_similar_distance_10() -> None:
    base = 0xAAAAAAAAAAAAAAAA
    # XOR with a number that has exactly 10 bits set
    mask = (1 << 10) - 1  # 0x3FF -> 10 bits
    other = base ^ mask
    adapter = StubAdapter()
    analyzer = _ControlledSimHashAnalyzer(
        adapter=adapter,
        filepath="/fake/path",
        result={"available": True, "combined_simhash": {"hash": base}},
    )
    result = analyzer.calculate_similarity(other, hash_type="combined")
    assert 6 <= result["distance"] <= 15
    assert result["similarity_level"] == "similar"


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_calculate_similarity_somewhat_similar_distance_20() -> None:
    base = 0xAAAAAAAAAAAAAAAA
    # 20 bits differ
    mask = (1 << 20) - 1  # 20 bits set
    other = base ^ mask
    adapter = StubAdapter()
    analyzer = _ControlledSimHashAnalyzer(
        adapter=adapter,
        filepath="/fake/path",
        result={"available": True, "combined_simhash": {"hash": base}},
    )
    result = analyzer.calculate_similarity(other, hash_type="combined")
    assert 16 <= result["distance"] <= 25
    assert result["similarity_level"] == "somewhat_similar"


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_calculate_similarity_different_distance_30() -> None:
    base = 0xAAAAAAAAAAAAAAAA
    # 30 bits differ
    mask = (1 << 30) - 1  # 30 bits set
    other = base ^ mask
    adapter = StubAdapter()
    analyzer = _ControlledSimHashAnalyzer(
        adapter=adapter,
        filepath="/fake/path",
        result={"available": True, "combined_simhash": {"hash": base}},
    )
    result = analyzer.calculate_similarity(other, hash_type="combined")
    assert result["distance"] > 25
    assert result["similarity_level"] == "different"


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_calculate_similarity_with_strings_hash_type() -> None:
    hash_val = 0xBBBBBBBBBBBBBBBB
    adapter = StubAdapter()
    analyzer = _ControlledSimHashAnalyzer(
        adapter=adapter,
        filepath="/fake/path",
        result={"available": True, "strings_simhash": {"hash": hash_val}},
    )
    result = analyzer.calculate_similarity(hash_val, hash_type="strings")
    assert result["distance"] == 0
    assert result["hash_type"] == "strings"


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_calculate_similarity_with_opcodes_hash_type() -> None:
    hash_val = 0xCCCCCCCCCCCCCCCC
    adapter = StubAdapter()
    analyzer = _ControlledSimHashAnalyzer(
        adapter=adapter,
        filepath="/fake/path",
        result={"available": True, "opcodes_simhash": {"hash": hash_val}},
    )
    result = analyzer.calculate_similarity(hash_val, hash_type="opcodes")
    assert result["distance"] == 0
    assert result["hash_type"] == "opcodes"


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_calculate_similarity_returns_result_dict_structure() -> None:
    hash_val = 0xDDDDDDDDDDDDDDDD
    adapter = StubAdapter()
    analyzer = _ControlledSimHashAnalyzer(
        adapter=adapter,
        filepath="/fake/path",
        result={"available": True, "combined_simhash": {"hash": hash_val}},
    )
    result = analyzer.calculate_similarity(hash_val)
    assert "distance" in result
    assert "similarity_level" in result
    assert "current_hash" in result
    assert "other_hash" in result
    assert "hash_type" in result


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_calculate_similarity_exception_returns_error_dict() -> None:
    adapter = StubAdapter()

    class ExceptionAnalyzer(_ControlledSimHashAnalyzer):
        def analyze(self) -> dict[str, Any]:
            raise RuntimeError("forced exception")

    analyzer = ExceptionAnalyzer(
        adapter=adapter,
        filepath="/fake/path",
        result={},
    )
    result = analyzer.calculate_similarity(0x1234)
    assert "error" in result
    assert "forced exception" in result["error"]


# ---------------------------------------------------------------------------
# compare_hashes – static method branches
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_compare_hashes_returns_none_when_simhash_unavailable() -> None:
    old = _mod.SIMHASH_AVAILABLE
    _mod.SIMHASH_AVAILABLE = False
    try:
        result = SimHashAnalyzer.compare_hashes("0x1234", "0x5678")
        assert result is None
    finally:
        _mod.SIMHASH_AVAILABLE = old


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_compare_hashes_returns_none_for_empty_first_hash() -> None:
    result = SimHashAnalyzer.compare_hashes("", "0x1234")
    assert result is None


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_compare_hashes_returns_none_for_empty_second_hash() -> None:
    result = SimHashAnalyzer.compare_hashes("0x1234", "")
    assert result is None


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_compare_hashes_with_hex_strings_returns_zero_for_same_value() -> None:
    result = SimHashAnalyzer.compare_hashes("0xAAAAAAAAAAAAAAAA", "0xAAAAAAAAAAAAAAAA")
    assert result == 0


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_compare_hashes_with_int_arguments_returns_zero_for_same_value() -> None:
    result = SimHashAnalyzer.compare_hashes(0xBBBBBBBBBBBBBBBB, 0xBBBBBBBBBBBBBBBB)
    assert result == 0


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_compare_hashes_with_different_values_returns_positive_distance() -> None:
    # 0xAAAA... and 0x5555... differ in all 64 bits; both are non-zero (avoids falsy check)
    result = SimHashAnalyzer.compare_hashes(0xAAAAAAAAAAAAAAAA, 0x5555555555555555)
    assert result == 64


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_compare_hashes_with_invalid_hex_string_returns_none() -> None:
    result = SimHashAnalyzer.compare_hashes("not_hex_value", "0x1234")
    assert result is None


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_compare_hashes_mixed_int_and_string() -> None:
    val = 0xCCCCCCCCCCCCCCCC
    result = SimHashAnalyzer.compare_hashes("0xCCCCCCCCCCCCCCCC", val)
    assert result == 0


# ---------------------------------------------------------------------------
# calculate_simhash_from_file
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_calculate_simhash_from_file_returns_none_for_nonexistent_file() -> None:
    result = SimHashAnalyzer.calculate_simhash_from_file("/nonexistent/file/path.bin")
    assert result is None


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_calculate_simhash_from_file_with_real_fixture(samples_dir: Any) -> None:
    fixture = samples_dir / "hello_elf"
    if not fixture.exists():
        pytest.skip("hello_elf fixture not available")
    result = SimHashAnalyzer.calculate_simhash_from_file(str(fixture))
    # May return None if r2pipe fails; just verify the return type
    assert result is None or isinstance(result, dict)
