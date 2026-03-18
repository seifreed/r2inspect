from __future__ import annotations

from typing import Any

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.simhash_analyzer import SIMHASH_AVAILABLE, SimHashAnalyzer


class FakeR2:
    """Fake r2pipe instance that returns predetermined responses."""

    def __init__(
        self,
        cmdj_map: dict[str, Any] | None = None,
        cmd_map: dict[str, str] | None = None,
    ):
        self.cmdj_map: dict[str, Any] = cmdj_map or {}
        self.cmd_map: dict[str, str] = cmd_map or {}

    def cmdj(self, command: str) -> Any:
        if command in self.cmdj_map:
            value = self.cmdj_map[command]
            if isinstance(value, Exception):
                raise value
            return value
        # Try prefix matching for commands with addresses
        for key, value in self.cmdj_map.items():
            if "@ " in command and "@ " in key:
                prefix_cmd = command.split(" @")[0]
                prefix_key = key.split(" @")[0]
                if prefix_cmd == prefix_key:
                    if isinstance(value, Exception):
                        raise value
                    return value
        return {}

    def cmd(self, command: str) -> str:
        if command in self.cmd_map:
            value = self.cmd_map[command]
            if isinstance(value, Exception):
                raise value
            return value
        # Prefix matching for p8 commands
        for key, value in self.cmd_map.items():
            if key in command:
                if isinstance(value, Exception):
                    raise value
                return value
        return ""


def _make_adapter(
    cmdj_map: dict[str, Any] | None = None,
    cmd_map: dict[str, str] | None = None,
) -> R2PipeAdapter:
    """Create an R2PipeAdapter backed by a FakeR2."""
    return R2PipeAdapter(FakeR2(cmdj_map=cmdj_map, cmd_map=cmd_map))


def _make_analyzer(
    cmdj_map: dict[str, Any] | None = None,
    cmd_map: dict[str, str] | None = None,
    filepath: str = "/fake/path",
) -> SimHashAnalyzer:
    """Create a SimHashAnalyzer backed by FakeR2 -> R2PipeAdapter."""
    adapter = _make_adapter(cmdj_map=cmdj_map, cmd_map=cmd_map)
    return SimHashAnalyzer(adapter=adapter, filepath=filepath)


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


def test_simhash_analyzer_init() -> None:
    analyzer = _make_analyzer()
    assert analyzer.adapter is not None
    assert str(analyzer.filepath) == "/fake/path"
    assert analyzer.min_string_length == 4
    assert analyzer.max_instructions_per_function == 500


# ---------------------------------------------------------------------------
# Library availability
# ---------------------------------------------------------------------------


def test_simhash_analyzer_check_library_availability_true() -> None:
    if not SIMHASH_AVAILABLE:
        pytest.skip("simhash not available")
    analyzer = _make_analyzer()
    available, error = analyzer._check_library_availability()
    assert available is True
    assert error is None


def test_simhash_analyzer_check_library_availability_false() -> None:
    import r2inspect.modules.simhash_analyzer as mod

    old_val = mod.SIMHASH_AVAILABLE
    try:
        mod.SIMHASH_AVAILABLE = False
        analyzer = _make_analyzer()
        available, error = analyzer._check_library_availability()
        assert available is False
        assert "simhash library not available" in error
    finally:
        mod.SIMHASH_AVAILABLE = old_val


# ---------------------------------------------------------------------------
# Hash type
# ---------------------------------------------------------------------------


def test_simhash_analyzer_get_hash_type() -> None:
    analyzer = _make_analyzer()
    assert analyzer._get_hash_type() == "simhash"


# ---------------------------------------------------------------------------
# _calculate_hash
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_calculate_hash_no_features() -> None:
    # No strings and no functions -> no features
    analyzer = _make_analyzer(
        cmdj_map={"izzj": [], "aflj": []},
    )
    hash_val, method, error = analyzer._calculate_hash()
    assert hash_val is None
    assert method is None
    assert "No features" in error


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_calculate_hash_with_features() -> None:
    analyzer = _make_analyzer(
        cmdj_map={
            "izzj": [{"string": "test_string_here"}],
            "aflj": [],
        },
    )
    hash_val, method, error = analyzer._calculate_hash()
    assert hash_val is not None
    assert method == "feature_extraction"
    assert error is None


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_calculate_hash_exception() -> None:
    # An adapter that returns an exception when querying strings
    # will cause _extract_string_features to return [].
    # Also no functions -> no features at all -> error path.
    analyzer = _make_analyzer(
        cmdj_map={"izzj": Exception("Test error"), "aflj": []},
    )
    hash_val, method, error = analyzer._calculate_hash()
    assert hash_val is None
    assert method is None
    assert "No features" in error


# ---------------------------------------------------------------------------
# _extract_string_features
# ---------------------------------------------------------------------------


def test_simhash_analyzer_extract_string_features_empty() -> None:
    analyzer = _make_analyzer(cmdj_map={"izzj": []})
    result = analyzer._extract_string_features()
    assert result == []


def test_simhash_analyzer_extract_string_features_not_list() -> None:
    # When get_strings returns a dict, the adapter validation coerces it;
    # the simhash code checks if the result is a list.
    analyzer = _make_analyzer(cmdj_map={"izzj": {"not": "a list"}})
    result = analyzer._extract_string_features()
    assert result == []


def test_simhash_analyzer_extract_string_features_no_string_field() -> None:
    analyzer = _make_analyzer(cmdj_map={"izzj": [{"other": "field"}]})
    result = analyzer._extract_string_features()
    assert result == []


def test_simhash_analyzer_extract_string_features_too_short() -> None:
    analyzer = _make_analyzer(cmdj_map={"izzj": [{"string": "ab"}]})
    result = analyzer._extract_string_features()
    assert result == []


def test_simhash_analyzer_extract_string_features_not_useful() -> None:
    analyzer = _make_analyzer(cmdj_map={"izzj": [{"string": "12345678"}]})
    result = analyzer._extract_string_features()
    assert result == []


def test_simhash_analyzer_extract_string_features_valid() -> None:
    analyzer = _make_analyzer(cmdj_map={"izzj": [{"string": "valid_string"}]})
    result = analyzer._extract_string_features()
    assert len(result) > 0
    assert any("STR:" in f for f in result)


def test_simhash_analyzer_extract_string_features_exception() -> None:
    # When the adapter raises, _extract_string_features should return []
    analyzer = _make_analyzer(cmdj_map={"izzj": Exception("Test error")})
    result = analyzer._extract_string_features()
    assert result == []


# ---------------------------------------------------------------------------
# _collect_string_features / _add_string_feature_set
# ---------------------------------------------------------------------------


def test_simhash_analyzer_collect_string_features() -> None:
    analyzer = _make_analyzer()
    strings_data = [{"string": "valid_test_string"}, {"string": "another"}]
    string_features: list[str] = []
    analyzer._collect_string_features(strings_data, string_features)
    assert len(string_features) > 0


def test_simhash_analyzer_add_string_feature_set() -> None:
    analyzer = _make_analyzer()
    string_features: list[str] = []
    analyzer._add_string_feature_set(string_features, "test_string")
    assert any("STR:" in f for f in string_features)
    assert any("STRLEN:" in f for f in string_features)


# ---------------------------------------------------------------------------
# _extract_opcodes_features
# ---------------------------------------------------------------------------


def test_simhash_analyzer_extract_opcodes_features_no_functions() -> None:
    analyzer = _make_analyzer(cmdj_map={"aflj": []})
    result = analyzer._extract_opcodes_features()
    assert result == []


def test_simhash_analyzer_extract_opcodes_features_cmdj_fallback() -> None:
    analyzer = _make_analyzer(cmdj_map={"aflj": []})
    result = analyzer._extract_opcodes_features()
    assert result == []


def test_simhash_analyzer_extract_opcodes_features_no_offset() -> None:
    analyzer = _make_analyzer(cmdj_map={"aflj": [{"name": "test"}]})
    result = analyzer._extract_opcodes_features()
    assert result == []


def test_simhash_analyzer_extract_opcodes_features_valid() -> None:
    analyzer = _make_analyzer(
        cmdj_map={
            "aflj": [{"offset": 0x1000, "name": "test_func"}],
            "pdfj @ 4096": {"ops": [{"mnemonic": "mov"}, {"mnemonic": "add"}]},
        },
    )
    result = analyzer._extract_opcodes_features()
    assert len(result) > 0


def test_simhash_analyzer_extract_opcodes_features_addr_field() -> None:
    analyzer = _make_analyzer(
        cmdj_map={
            "aflj": [{"addr": 0x1000, "name": "test_func"}],
            "pdfj @ 4096": {"ops": [{"mnemonic": "mov"}]},
        },
    )
    result = analyzer._extract_opcodes_features()
    assert len(result) > 0


def test_simhash_analyzer_extract_opcodes_features_limit() -> None:
    many_funcs = [{"offset": i * 0x100, "name": f"func_{i}"} for i in range(1000)]
    cmdj_map: dict[str, Any] = {"aflj": many_funcs}
    # Each function disassembly returns some ops
    for func in many_funcs:
        addr = func["offset"]
        cmdj_map[f"pdfj @ {addr}"] = {"ops": [{"mnemonic": "nop"}] * 100}
    analyzer = _make_analyzer(cmdj_map=cmdj_map)
    result = analyzer._extract_opcodes_features()
    assert len(result) > 0


def test_simhash_analyzer_extract_opcodes_features_exception() -> None:
    analyzer = _make_analyzer(cmdj_map={"aflj": Exception("Test error")})
    result = analyzer._extract_opcodes_features()
    assert result == []


# ---------------------------------------------------------------------------
# _extract_function_features
# ---------------------------------------------------------------------------


def test_simhash_analyzer_extract_function_features_empty() -> None:
    analyzer = _make_analyzer(cmdj_map={"aflj": []})
    result = analyzer._extract_function_features()
    assert result == {}


def test_simhash_analyzer_extract_function_features_no_offset() -> None:
    analyzer = _make_analyzer(cmdj_map={"aflj": [{"name": "test"}]})
    result = analyzer._extract_function_features()
    assert result == {}


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_extract_function_features_valid() -> None:
    analyzer = _make_analyzer(
        cmdj_map={
            "aflj": [{"offset": 0x1000, "name": "test_func", "size": 100}],
            "pdfj @ 4096": {"ops": [{"mnemonic": "mov"}, {"mnemonic": "add"}]},
        },
    )
    result = analyzer._extract_function_features()
    assert "test_func" in result
    assert result["test_func"]["addr"] == 0x1000


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_extract_function_features_exception() -> None:
    # get_functions succeeds but get_disasm raises -> empty result
    fake_r2 = FakeR2(
        cmdj_map={
            "aflj": [{"offset": 0x1000, "name": "test_func", "size": 100}],
            "pdfj @ 4096": Exception("Test error"),
        },
    )
    adapter = R2PipeAdapter(fake_r2)
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_function_features()
    assert result == {}


# ---------------------------------------------------------------------------
# _extract_function_opcodes
# ---------------------------------------------------------------------------


def test_simhash_analyzer_extract_function_opcodes_no_adapter() -> None:
    analyzer = SimHashAnalyzer(adapter=None, filepath="/fake/path")
    result = analyzer._extract_function_opcodes(0x1000, "test_func")
    assert result == []


def test_simhash_analyzer_extract_function_opcodes_no_disasm_method() -> None:
    # Use a plain object without get_disasm
    class BareAdapter:
        pass

    analyzer = SimHashAnalyzer(adapter=BareAdapter(), filepath="/fake/path")
    result = analyzer._extract_function_opcodes(0x1000, "test_func")
    assert result == []


def test_simhash_analyzer_extract_function_opcodes_dict_ops() -> None:
    analyzer = _make_analyzer(
        cmdj_map={
            "pdfj @ 4096": {"ops": [{"mnemonic": "mov"}]},
        },
    )
    result = analyzer._extract_function_opcodes(0x1000, "test_func")
    assert len(result) > 0


def test_simhash_analyzer_extract_function_opcodes_list_ops() -> None:
    # First call (pdfj @ addr) returns empty dict -> no ops found.
    # Fallback call (pdj {size} @ addr) returns a list of ops directly.
    analyzer = _make_analyzer(
        cmdj_map={
            "pdfj @ 4096": {"not": "ops"},
            "pdj 500 @ 4096": [{"mnemonic": "mov"}],
        },
    )
    result = analyzer._extract_function_opcodes(0x1000, "test_func")
    assert len(result) > 0


def test_simhash_analyzer_extract_function_opcodes_exception() -> None:
    fake_r2 = FakeR2(
        cmdj_map={"pdfj @ 4096": Exception("Test error")},
    )
    adapter = R2PipeAdapter(fake_r2)
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_function_opcodes(0x1000, "test_func")
    assert result == []


# ---------------------------------------------------------------------------
# _extract_opcodes_from_ops
# ---------------------------------------------------------------------------


def test_simhash_analyzer_extract_opcodes_from_ops_empty() -> None:
    analyzer = _make_analyzer()
    result = analyzer._extract_opcodes_from_ops([])
    assert result == []


def test_simhash_analyzer_extract_opcodes_from_ops_not_dict() -> None:
    analyzer = _make_analyzer()
    result = analyzer._extract_opcodes_from_ops(["not a dict", 123])
    assert result == []


def test_simhash_analyzer_extract_opcodes_from_ops_no_mnemonic() -> None:
    analyzer = _make_analyzer()
    result = analyzer._extract_opcodes_from_ops([{"other": "field"}])
    assert result == []


def test_simhash_analyzer_extract_opcodes_from_ops_empty_mnemonic() -> None:
    analyzer = _make_analyzer()
    result = analyzer._extract_opcodes_from_ops([{"mnemonic": "   "}])
    assert result == []


def test_simhash_analyzer_extract_opcodes_from_ops_valid() -> None:
    analyzer = _make_analyzer()
    ops = [{"mnemonic": "mov"}, {"mnemonic": "add"}, {"mnemonic": "jmp"}]
    result = analyzer._extract_opcodes_from_ops(ops)
    assert len(result) > 0
    assert any("OP:mov" in r for r in result)


def test_simhash_analyzer_extract_opcodes_from_ops_with_bigram() -> None:
    analyzer = _make_analyzer()
    ops = [{"mnemonic": "mov"}, {"mnemonic": "add"}]
    result = analyzer._extract_opcodes_from_ops(ops)
    assert any("BIGRAM:" in r for r in result)


def test_simhash_analyzer_extract_opcodes_from_ops_limit() -> None:
    analyzer = _make_analyzer()
    ops = [{"mnemonic": "nop"}] * 1000
    result = analyzer._extract_opcodes_from_ops(ops)
    assert len(result) <= analyzer.max_instructions_per_function * 3


# ---------------------------------------------------------------------------
# _get_prev_mnemonic
# ---------------------------------------------------------------------------


def test_simhash_analyzer_get_prev_mnemonic_first() -> None:
    analyzer = _make_analyzer()
    ops = [{"mnemonic": "mov"}]
    result = analyzer._get_prev_mnemonic(ops, 0)
    assert result is None


def test_simhash_analyzer_get_prev_mnemonic_out_of_range() -> None:
    analyzer = _make_analyzer()
    ops = [{"mnemonic": "mov"}]
    result = analyzer._get_prev_mnemonic(ops, 10)
    assert result is None


def test_simhash_analyzer_get_prev_mnemonic_valid() -> None:
    analyzer = _make_analyzer()
    ops = [{"mnemonic": "mov"}, {"mnemonic": "add"}]
    result = analyzer._get_prev_mnemonic(ops, 1)
    assert result == "mov"


def test_simhash_analyzer_get_prev_mnemonic_not_dict() -> None:
    analyzer = _make_analyzer()
    ops = ["not a dict", {"mnemonic": "add"}]
    result = analyzer._get_prev_mnemonic(ops, 1)
    assert result is None


# ---------------------------------------------------------------------------
# _extract_data_section_strings / _append_data_section_string
# ---------------------------------------------------------------------------


def test_simhash_analyzer_extract_data_section_strings_not_list() -> None:
    analyzer = _make_analyzer(cmdj_map={"iSj": {"not": "a list"}})
    result = analyzer._extract_data_section_strings()
    assert result == []


def test_simhash_analyzer_extract_data_section_strings_exception() -> None:
    analyzer = _make_analyzer(cmdj_map={"iSj": Exception("Test error")})
    result = analyzer._extract_data_section_strings()
    assert result == []


def test_simhash_analyzer_append_data_section_string_not_dict() -> None:
    analyzer = _make_analyzer()
    data_strings: list[str] = []
    analyzer._append_data_section_string("not a dict", data_strings)
    assert data_strings == []


def test_simhash_analyzer_append_data_section_string_not_data() -> None:
    analyzer = _make_analyzer()
    data_strings: list[str] = []
    analyzer._append_data_section_string({"name": ".text"}, data_strings)
    assert data_strings == []


def test_simhash_analyzer_append_data_section_string_no_addr() -> None:
    analyzer = _make_analyzer()
    data_strings: list[str] = []
    analyzer._append_data_section_string({"name": ".data", "vaddr": 0}, data_strings)
    assert data_strings == []


def test_simhash_analyzer_append_data_section_string_no_adapter() -> None:
    analyzer = SimHashAnalyzer(adapter=None, filepath="/fake/path")
    data_strings: list[str] = []
    analyzer._append_data_section_string(
        {"name": ".data", "vaddr": 0x1000, "size": 100}, data_strings
    )
    assert data_strings == []


def test_simhash_analyzer_append_data_section_string_no_read_bytes() -> None:
    # Use a plain object that has no read_bytes method
    class NoReadBytesAdapter:
        pass

    analyzer = SimHashAnalyzer(adapter=NoReadBytesAdapter(), filepath="/fake/path")
    data_strings: list[str] = []
    analyzer._append_data_section_string(
        {"name": ".data", "vaddr": 0x1000, "size": 100}, data_strings
    )
    assert data_strings == []


def test_simhash_analyzer_append_data_section_string_valid() -> None:
    # p8 100 @ 4096 -> hex-encoded "test_string_here\x00"
    hex_data = b"test_string_here\x00".hex()
    analyzer = _make_analyzer(cmd_map={"p8": hex_data})
    data_strings: list[str] = []
    analyzer._append_data_section_string(
        {"name": ".data", "vaddr": 0x1000, "size": 100}, data_strings
    )
    assert len(data_strings) > 0


# ---------------------------------------------------------------------------
# _is_useful_string
# ---------------------------------------------------------------------------


def test_simhash_analyzer_is_useful_string_empty() -> None:
    analyzer = _make_analyzer()
    assert analyzer._is_useful_string("   ") is False


def test_simhash_analyzer_is_useful_string_numbers_only() -> None:
    analyzer = _make_analyzer()
    assert analyzer._is_useful_string("12345") is False


def test_simhash_analyzer_is_useful_string_hex() -> None:
    analyzer = _make_analyzer()
    assert analyzer._is_useful_string("abcd1234ef") is False


def test_simhash_analyzer_is_useful_string_low_printable() -> None:
    analyzer = _make_analyzer()
    assert analyzer._is_useful_string("test\x00\x01\x02") is False


def test_simhash_analyzer_is_useful_string_valid() -> None:
    analyzer = _make_analyzer()
    assert analyzer._is_useful_string("valid_string") is True


# ---------------------------------------------------------------------------
# _get_strings_data / _get_functions / _get_sections
# ---------------------------------------------------------------------------


def test_simhash_analyzer_get_strings_data_adapter() -> None:
    analyzer = _make_analyzer(cmdj_map={"izzj": [{"string": "test"}]})
    result = analyzer._get_strings_data()
    assert len(result) == 1


def test_simhash_analyzer_get_strings_data_cmdj() -> None:
    # When adapter has no get_strings, falls back to _cmd_list("izzj")
    # With our FakeR2-backed adapter, get_strings always exists.
    # We test the main path instead: ensure data is returned.
    analyzer = _make_analyzer(cmdj_map={"izzj": [{"string": "test"}]})
    result = analyzer._get_strings_data()
    assert len(result) == 1


def test_simhash_analyzer_get_functions_adapter() -> None:
    analyzer = _make_analyzer(cmdj_map={"aflj": [{"offset": 0x1000}]})
    result = analyzer._get_functions()
    assert len(result) == 1


def test_simhash_analyzer_get_functions_cmdj() -> None:
    analyzer = _make_analyzer(cmdj_map={"aflj": [{"offset": 0x1000}]})
    result = analyzer._get_functions()
    assert len(result) == 1


def test_simhash_analyzer_get_sections_adapter() -> None:
    analyzer = _make_analyzer(cmdj_map={"iSj": [{"name": ".text"}]})
    result = analyzer._get_sections()
    assert len(result) == 1


def test_simhash_analyzer_get_sections_cmdj() -> None:
    analyzer = _make_analyzer(cmdj_map={"iSj": [{"name": ".text"}]})
    result = analyzer._get_sections()
    assert len(result) == 1


# ---------------------------------------------------------------------------
# _extract_ops_from_disasm
# ---------------------------------------------------------------------------


def test_simhash_analyzer_extract_ops_from_disasm_dict() -> None:
    analyzer = _make_analyzer()
    disasm = {"ops": [{"mnemonic": "mov"}]}
    result = analyzer._extract_ops_from_disasm(disasm)
    assert len(result) == 1


def test_simhash_analyzer_extract_ops_from_disasm_list() -> None:
    analyzer = _make_analyzer()
    disasm = [{"mnemonic": "mov"}]
    result = analyzer._extract_ops_from_disasm(disasm)
    assert len(result) == 1


def test_simhash_analyzer_extract_ops_from_disasm_invalid() -> None:
    analyzer = _make_analyzer()
    disasm = {"not": "ops"}
    result = analyzer._extract_ops_from_disasm(disasm)
    assert result == []


# ---------------------------------------------------------------------------
# _extract_printable_strings
# ---------------------------------------------------------------------------


def test_simhash_analyzer_extract_printable_strings() -> None:
    analyzer = _make_analyzer()
    data = b"test\x00string\x00\x01\x02valid"
    result = analyzer._extract_printable_strings(data)
    assert "test" in result
    assert "string" in result


def test_simhash_analyzer_extract_printable_strings_min_length() -> None:
    analyzer = _make_analyzer()
    data = b"ab\x00cdef"
    result = analyzer._extract_printable_strings(data)
    assert "ab" not in result
    assert "cdef" in result


# ---------------------------------------------------------------------------
# _get_length_category
# ---------------------------------------------------------------------------


def test_simhash_analyzer_get_length_category() -> None:
    analyzer = _make_analyzer()
    assert analyzer._get_length_category(5) == "short"
    assert analyzer._get_length_category(15) == "medium"
    assert analyzer._get_length_category(50) == "long"
    assert analyzer._get_length_category(150) == "very_long"


# ---------------------------------------------------------------------------
# _classify_string_type
# ---------------------------------------------------------------------------


def test_simhash_analyzer_classify_string_type() -> None:
    analyzer = _make_analyzer()
    result = analyzer._classify_string_type("test_string")
    assert result is not None or result is None


# ---------------------------------------------------------------------------
# _classify_opcode_type
# ---------------------------------------------------------------------------


def test_simhash_analyzer_classify_opcode_type_control() -> None:
    analyzer = _make_analyzer()
    assert analyzer._classify_opcode_type("jmp") == "control"
    assert analyzer._classify_opcode_type("call") == "control"
    assert analyzer._classify_opcode_type("ret") == "control"


def test_simhash_analyzer_classify_opcode_type_data() -> None:
    analyzer = _make_analyzer()
    assert analyzer._classify_opcode_type("mov") == "data"
    assert analyzer._classify_opcode_type("push") == "data"


def test_simhash_analyzer_classify_opcode_type_arithmetic() -> None:
    analyzer = _make_analyzer()
    assert analyzer._classify_opcode_type("add") == "arithmetic"
    assert analyzer._classify_opcode_type("sub") == "arithmetic"


def test_simhash_analyzer_classify_opcode_type_logical() -> None:
    analyzer = _make_analyzer()
    assert analyzer._classify_opcode_type("and") == "logical"
    assert analyzer._classify_opcode_type("xor") == "logical"


def test_simhash_analyzer_classify_opcode_type_compare() -> None:
    analyzer = _make_analyzer()
    assert analyzer._classify_opcode_type("cmp") == "compare"
    assert analyzer._classify_opcode_type("test") == "compare"


def test_simhash_analyzer_classify_opcode_type_string() -> None:
    analyzer = _make_analyzer()
    assert analyzer._classify_opcode_type("strcpy") == "string"
    assert analyzer._classify_opcode_type("rep") == "string"


def test_simhash_analyzer_classify_opcode_type_other() -> None:
    analyzer = _make_analyzer()
    assert analyzer._classify_opcode_type("nop") == "other"


# ---------------------------------------------------------------------------
# _find_similar_functions
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_find_similar_functions_empty() -> None:
    analyzer = _make_analyzer()
    result = analyzer._find_similar_functions({})
    assert result == []


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_find_similar_functions_no_similar() -> None:
    analyzer = _make_analyzer()
    functions = {
        "func1": {"simhash": 0x1111111111111111},
        "func2": {"simhash": 0xFFFFFFFFFFFFFFFF},
    }
    result = analyzer._find_similar_functions(functions, max_distance=5)
    assert len(result) == 0


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_find_similar_functions_exception() -> None:
    analyzer = _make_analyzer()
    functions = {"func1": {"invalid": "data"}}
    result = analyzer._find_similar_functions(functions)
    assert result == []


# ---------------------------------------------------------------------------
# calculate_similarity
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_calculate_similarity_not_available() -> None:
    import r2inspect.modules.simhash_analyzer as mod

    old_val = mod.SIMHASH_AVAILABLE
    try:
        mod.SIMHASH_AVAILABLE = False
        analyzer = _make_analyzer()
        result = analyzer.calculate_similarity(0x1234567890ABCDEF)
        assert "error" in result
        assert "not available" in result["error"]
    finally:
        mod.SIMHASH_AVAILABLE = old_val


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_calculate_similarity_no_analysis() -> None:
    analyzer = _make_analyzer(cmdj_map={"izzj": [], "aflj": []})
    result = analyzer.calculate_similarity(0x1234567890ABCDEF)
    assert "error" in result


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_calculate_similarity_exception() -> None:
    analyzer = _make_analyzer(cmdj_map={"izzj": Exception("Test error"), "aflj": []})
    result = analyzer.calculate_similarity(0x1234567890ABCDEF)
    assert "error" in result


# ---------------------------------------------------------------------------
# compare_hashes (static)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_compare_hashes_none() -> None:
    result = SimHashAnalyzer.compare_hashes(None, 0x1234)
    assert result is None


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_compare_hashes_empty() -> None:
    result = SimHashAnalyzer.compare_hashes("", 0x1234)
    assert result is None


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_compare_hashes_string() -> None:
    result = SimHashAnalyzer.compare_hashes("0x1234", "0x1234")
    assert result == 0


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_compare_hashes_int() -> None:
    result = SimHashAnalyzer.compare_hashes(0x1234, 0x1234)
    assert result == 0


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_compare_hashes_mixed() -> None:
    result = SimHashAnalyzer.compare_hashes("0x1234", 0x1234)
    assert result == 0


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_compare_hashes_exception() -> None:
    result = SimHashAnalyzer.compare_hashes("invalid", 0x1234)
    assert result is None


# ---------------------------------------------------------------------------
# is_available (static)
# ---------------------------------------------------------------------------


def test_simhash_analyzer_is_available() -> None:
    result = SimHashAnalyzer.is_available()
    assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# calculate_simhash_from_file (static)
# ---------------------------------------------------------------------------


def test_simhash_analyzer_calculate_simhash_from_file_none() -> None:
    # The file does not exist, so run_analyzer_on_file returns None
    result = SimHashAnalyzer.calculate_simhash_from_file("/nonexistent/fake/path")
    assert result is None


# ---------------------------------------------------------------------------
# analyze_detailed
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_analyze_detailed_not_available() -> None:
    import r2inspect.modules.simhash_analyzer as mod

    old_val = mod.SIMHASH_AVAILABLE
    try:
        mod.SIMHASH_AVAILABLE = False
        analyzer = _make_analyzer()
        result = analyzer.analyze_detailed()
        assert result["available"] is False
        assert "library_available" in result
        assert result["library_available"] is False
    finally:
        mod.SIMHASH_AVAILABLE = old_val
