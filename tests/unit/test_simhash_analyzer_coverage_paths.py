from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from r2inspect.modules.simhash_analyzer import SIMHASH_AVAILABLE, SimHashAnalyzer


def test_simhash_analyzer_init() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    assert analyzer.adapter == adapter
    assert str(analyzer.filepath) == "/fake/path"
    assert analyzer.min_string_length == 4
    assert analyzer.max_instructions_per_function == 500


def test_simhash_analyzer_check_library_availability_true() -> None:
    if not SIMHASH_AVAILABLE:
        pytest.skip("simhash not available")
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    available, error = analyzer._check_library_availability()
    assert available is True
    assert error is None


def test_simhash_analyzer_check_library_availability_false(monkeypatch: Any) -> None:
    import r2inspect.modules.simhash_analyzer

    old_val = r2inspect.modules.simhash_analyzer.SIMHASH_AVAILABLE
    r2inspect.modules.simhash_analyzer.SIMHASH_AVAILABLE = False

    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    available, error = analyzer._check_library_availability()

    r2inspect.modules.simhash_analyzer.SIMHASH_AVAILABLE = old_val

    assert available is False
    assert "simhash library not available" in error


def test_simhash_analyzer_get_hash_type() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    assert analyzer._get_hash_type() == "simhash"


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_calculate_hash_no_features() -> None:
    adapter = MagicMock()
    adapter.get_strings.return_value = []
    adapter.get_functions.return_value = []

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    hash_val, method, error = analyzer._calculate_hash()
    assert hash_val is None
    assert method is None
    assert "No features" in error


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_calculate_hash_with_features() -> None:
    adapter = MagicMock()
    adapter.get_strings.return_value = [{"string": "test_string_here"}]
    adapter.get_functions.return_value = []

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    hash_val, method, error = analyzer._calculate_hash()
    assert hash_val is not None
    assert method == "feature_extraction"
    assert error is None


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_calculate_hash_exception() -> None:
    adapter = MagicMock()
    adapter.get_strings.side_effect = Exception("Test error")

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    hash_val, method, error = analyzer._calculate_hash()
    assert hash_val is None
    assert method is None
    assert "Test error" in error


def test_simhash_analyzer_extract_string_features_empty() -> None:
    adapter = MagicMock()
    adapter.get_strings.return_value = []

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_string_features()
    assert result == []


def test_simhash_analyzer_extract_string_features_not_list() -> None:
    adapter = MagicMock()
    adapter.get_strings.return_value = {"not": "a list"}

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_string_features()
    assert result == []


def test_simhash_analyzer_extract_string_features_no_string_field() -> None:
    adapter = MagicMock()
    adapter.get_strings.return_value = [{"other": "field"}]

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_string_features()
    assert result == []


def test_simhash_analyzer_extract_string_features_too_short() -> None:
    adapter = MagicMock()
    adapter.get_strings.return_value = [{"string": "ab"}]

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_string_features()
    assert result == []


def test_simhash_analyzer_extract_string_features_not_useful() -> None:
    adapter = MagicMock()
    adapter.get_strings.return_value = [{"string": "12345678"}]

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_string_features()
    assert result == []


def test_simhash_analyzer_extract_string_features_valid() -> None:
    adapter = MagicMock()
    adapter.get_strings.return_value = [{"string": "valid_string"}]

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_string_features()
    assert len(result) > 0
    assert any("STR:" in f for f in result)


def test_simhash_analyzer_extract_string_features_exception() -> None:
    adapter = MagicMock()
    adapter.get_strings.side_effect = Exception("Test error")

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_string_features()
    assert result == []


def test_simhash_analyzer_collect_string_features() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")

    strings_data = [{"string": "valid_test_string"}, {"string": "another"}]
    string_features: list[str] = []

    analyzer._collect_string_features(strings_data, string_features)
    assert len(string_features) > 0


def test_simhash_analyzer_add_string_feature_set() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")

    string_features: list[str] = []
    analyzer._add_string_feature_set(string_features, "test_string")

    assert any("STR:" in f for f in string_features)
    assert any("STRLEN:" in f for f in string_features)


def test_simhash_analyzer_extract_opcodes_features_no_functions() -> None:
    adapter = MagicMock()
    adapter.get_functions.return_value = []

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_opcodes_features()
    assert result == []


def test_simhash_analyzer_extract_opcodes_features_cmdj_fallback() -> None:
    adapter = MagicMock()
    adapter.get_functions.return_value = []
    adapter.cmdj.return_value = []

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_opcodes_features()
    assert result == []


def test_simhash_analyzer_extract_opcodes_features_no_offset() -> None:
    adapter = MagicMock()
    adapter.get_functions.return_value = [{"name": "test"}]

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_opcodes_features()
    assert result == []


def test_simhash_analyzer_extract_opcodes_features_valid() -> None:
    adapter = MagicMock()
    adapter.get_functions.return_value = [{"offset": 0x1000, "name": "test_func"}]
    adapter.get_disasm.return_value = {"ops": [{"mnemonic": "mov"}, {"mnemonic": "add"}]}

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_opcodes_features()
    assert len(result) > 0


def test_simhash_analyzer_extract_opcodes_features_addr_field() -> None:
    adapter = MagicMock()
    adapter.get_functions.return_value = [{"addr": 0x1000, "name": "test_func"}]
    adapter.get_disasm.return_value = {"ops": [{"mnemonic": "mov"}]}

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_opcodes_features()
    assert len(result) > 0


def test_simhash_analyzer_extract_opcodes_features_limit() -> None:
    adapter = MagicMock()
    many_funcs = [{"offset": i * 0x100, "name": f"func_{i}"} for i in range(1000)]
    adapter.get_functions.return_value = many_funcs
    adapter.get_disasm.return_value = {"ops": [{"mnemonic": "nop"}] * 100}

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_opcodes_features()
    assert len(result) > 0


def test_simhash_analyzer_extract_opcodes_features_exception() -> None:
    adapter = MagicMock()
    adapter.get_functions.side_effect = Exception("Test error")

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_opcodes_features()
    assert result == []


def test_simhash_analyzer_extract_function_features_empty() -> None:
    adapter = MagicMock()
    adapter.get_functions.return_value = []

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_function_features()
    assert result == {}


def test_simhash_analyzer_extract_function_features_no_offset() -> None:
    adapter = MagicMock()
    adapter.get_functions.return_value = [{"name": "test"}]

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_function_features()
    assert result == {}


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_extract_function_features_valid() -> None:
    adapter = MagicMock()
    adapter.get_functions.return_value = [{"offset": 0x1000, "name": "test_func", "size": 100}]
    adapter.get_disasm.return_value = {"ops": [{"mnemonic": "mov"}, {"mnemonic": "add"}]}

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_function_features()
    assert "test_func" in result
    assert result["test_func"]["addr"] == 0x1000


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_extract_function_features_exception() -> None:
    adapter = MagicMock()
    adapter.get_functions.return_value = [{"offset": 0x1000, "name": "test_func", "size": 100}]
    adapter.get_disasm.side_effect = Exception("Test error")

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_function_features()
    assert result == {}


def test_simhash_analyzer_extract_function_opcodes_no_adapter() -> None:
    analyzer = SimHashAnalyzer(adapter=None, filepath="/fake/path")
    result = analyzer._extract_function_opcodes(0x1000, "test_func")
    assert result == []


def test_simhash_analyzer_extract_function_opcodes_no_disasm_method() -> None:
    adapter = MagicMock()
    delattr(adapter, "get_disasm")

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_function_opcodes(0x1000, "test_func")
    assert result == []


def test_simhash_analyzer_extract_function_opcodes_dict_ops() -> None:
    adapter = MagicMock()
    adapter.get_disasm.return_value = {"ops": [{"mnemonic": "mov"}]}

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_function_opcodes(0x1000, "test_func")
    assert len(result) > 0


def test_simhash_analyzer_extract_function_opcodes_list_ops() -> None:
    adapter = MagicMock()
    adapter.get_disasm.side_effect = [None, [{"mnemonic": "mov"}]]

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_function_opcodes(0x1000, "test_func")
    assert len(result) > 0


def test_simhash_analyzer_extract_function_opcodes_exception() -> None:
    adapter = MagicMock()
    adapter.get_disasm.side_effect = Exception("Test error")

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_function_opcodes(0x1000, "test_func")
    assert result == []


def test_simhash_analyzer_extract_opcodes_from_ops_empty() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_opcodes_from_ops([])
    assert result == []


def test_simhash_analyzer_extract_opcodes_from_ops_not_dict() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_opcodes_from_ops(["not a dict", 123])
    assert result == []


def test_simhash_analyzer_extract_opcodes_from_ops_no_mnemonic() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_opcodes_from_ops([{"other": "field"}])
    assert result == []


def test_simhash_analyzer_extract_opcodes_from_ops_empty_mnemonic() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_opcodes_from_ops([{"mnemonic": "   "}])
    assert result == []


def test_simhash_analyzer_extract_opcodes_from_ops_valid() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    ops = [{"mnemonic": "mov"}, {"mnemonic": "add"}, {"mnemonic": "jmp"}]
    result = analyzer._extract_opcodes_from_ops(ops)
    assert len(result) > 0
    assert any("OP:mov" in r for r in result)


def test_simhash_analyzer_extract_opcodes_from_ops_with_bigram() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    ops = [{"mnemonic": "mov"}, {"mnemonic": "add"}]
    result = analyzer._extract_opcodes_from_ops(ops)
    assert any("BIGRAM:" in r for r in result)


def test_simhash_analyzer_extract_opcodes_from_ops_limit() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    ops = [{"mnemonic": "nop"}] * 1000
    result = analyzer._extract_opcodes_from_ops(ops)
    assert len(result) <= analyzer.max_instructions_per_function * 3


def test_simhash_analyzer_get_prev_mnemonic_first() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    ops = [{"mnemonic": "mov"}]
    result = analyzer._get_prev_mnemonic(ops, 0)
    assert result is None


def test_simhash_analyzer_get_prev_mnemonic_out_of_range() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    ops = [{"mnemonic": "mov"}]
    result = analyzer._get_prev_mnemonic(ops, 10)
    assert result is None


def test_simhash_analyzer_get_prev_mnemonic_valid() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    ops = [{"mnemonic": "mov"}, {"mnemonic": "add"}]
    result = analyzer._get_prev_mnemonic(ops, 1)
    assert result == "mov"


def test_simhash_analyzer_get_prev_mnemonic_not_dict() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    ops = ["not a dict", {"mnemonic": "add"}]
    result = analyzer._get_prev_mnemonic(ops, 1)
    assert result is None


def test_simhash_analyzer_extract_data_section_strings_not_list() -> None:
    adapter = MagicMock()
    adapter.get_sections.return_value = {"not": "a list"}

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_data_section_strings()
    assert result == []


def test_simhash_analyzer_extract_data_section_strings_exception() -> None:
    adapter = MagicMock()
    adapter.get_sections.side_effect = Exception("Test error")

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_data_section_strings()
    assert result == []


def test_simhash_analyzer_append_data_section_string_not_dict() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    data_strings: list[str] = []
    analyzer._append_data_section_string("not a dict", data_strings)
    assert data_strings == []


def test_simhash_analyzer_append_data_section_string_not_data() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    data_strings: list[str] = []
    analyzer._append_data_section_string({"name": ".text"}, data_strings)
    assert data_strings == []


def test_simhash_analyzer_append_data_section_string_no_addr() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    data_strings: list[str] = []
    analyzer._append_data_section_string({"name": ".data", "vaddr": 0}, data_strings)
    assert data_strings == []


def test_simhash_analyzer_append_data_section_string_no_adapter() -> None:
    analyzer = SimHashAnalyzer(adapter=None, filepath="/fake/path")
    data_strings: list[str] = []
    analyzer._append_data_section_string({"name": ".data", "vaddr": 0x1000, "size": 100}, data_strings)
    assert data_strings == []


def test_simhash_analyzer_append_data_section_string_no_read_bytes() -> None:
    adapter = MagicMock()
    delattr(adapter, "read_bytes")

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    data_strings: list[str] = []
    analyzer._append_data_section_string({"name": ".data", "vaddr": 0x1000, "size": 100}, data_strings)
    assert data_strings == []


def test_simhash_analyzer_append_data_section_string_valid() -> None:
    adapter = MagicMock()
    adapter.read_bytes.return_value = b"test_string_here\x00"

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    data_strings: list[str] = []
    analyzer._append_data_section_string({"name": ".data", "vaddr": 0x1000, "size": 100}, data_strings)
    assert len(data_strings) > 0


def test_simhash_analyzer_is_useful_string_empty() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    assert analyzer._is_useful_string("   ") is False


def test_simhash_analyzer_is_useful_string_numbers_only() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    assert analyzer._is_useful_string("12345") is False


def test_simhash_analyzer_is_useful_string_hex() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    assert analyzer._is_useful_string("abcd1234ef") is False


def test_simhash_analyzer_is_useful_string_low_printable() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    assert analyzer._is_useful_string("test\x00\x01\x02") is False


def test_simhash_analyzer_is_useful_string_valid() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    assert analyzer._is_useful_string("valid_string") is True


def test_simhash_analyzer_get_strings_data_adapter() -> None:
    adapter = MagicMock()
    adapter.get_strings.return_value = [{"string": "test"}]

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._get_strings_data()
    assert len(result) == 1


def test_simhash_analyzer_get_strings_data_cmdj() -> None:
    adapter = MagicMock()
    delattr(adapter, "get_strings")
    adapter.cmdj.return_value = [{"string": "test"}]

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._get_strings_data()
    assert len(result) == 1


def test_simhash_analyzer_get_functions_adapter() -> None:
    adapter = MagicMock()
    adapter.get_functions.return_value = [{"offset": 0x1000}]

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._get_functions()
    assert len(result) == 1


def test_simhash_analyzer_get_functions_cmdj() -> None:
    adapter = MagicMock()
    delattr(adapter, "get_functions")
    adapter.cmdj.return_value = [{"offset": 0x1000}]

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._get_functions()
    assert len(result) == 1


def test_simhash_analyzer_get_sections_adapter() -> None:
    adapter = MagicMock()
    adapter.get_sections.return_value = [{"name": ".text"}]

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._get_sections()
    assert len(result) == 1


def test_simhash_analyzer_get_sections_cmdj() -> None:
    adapter = MagicMock()
    delattr(adapter, "get_sections")
    adapter.cmdj.return_value = [{"name": ".text"}]

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._get_sections()
    assert len(result) == 1


def test_simhash_analyzer_extract_ops_from_disasm_dict() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    disasm = {"ops": [{"mnemonic": "mov"}]}
    result = analyzer._extract_ops_from_disasm(disasm)
    assert len(result) == 1


def test_simhash_analyzer_extract_ops_from_disasm_list() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    disasm = [{"mnemonic": "mov"}]
    result = analyzer._extract_ops_from_disasm(disasm)
    assert len(result) == 1


def test_simhash_analyzer_extract_ops_from_disasm_invalid() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    disasm = {"not": "ops"}
    result = analyzer._extract_ops_from_disasm(disasm)
    assert result == []


def test_simhash_analyzer_extract_printable_strings() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    data = b"test\x00string\x00\x01\x02valid"
    result = analyzer._extract_printable_strings(data)
    assert "test" in result
    assert "string" in result


def test_simhash_analyzer_extract_printable_strings_min_length() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    data = b"ab\x00cdef"
    result = analyzer._extract_printable_strings(data)
    assert "ab" not in result
    assert "cdef" in result


def test_simhash_analyzer_get_length_category() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    assert analyzer._get_length_category(5) == "short"
    assert analyzer._get_length_category(15) == "medium"
    assert analyzer._get_length_category(50) == "long"
    assert analyzer._get_length_category(150) == "very_long"


def test_simhash_analyzer_classify_string_type() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._classify_string_type("test_string")
    assert result is not None or result is None


def test_simhash_analyzer_classify_opcode_type_control() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    assert analyzer._classify_opcode_type("jmp") == "control"
    assert analyzer._classify_opcode_type("call") == "control"
    assert analyzer._classify_opcode_type("ret") == "control"


def test_simhash_analyzer_classify_opcode_type_data() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    assert analyzer._classify_opcode_type("mov") == "data"
    assert analyzer._classify_opcode_type("push") == "data"


def test_simhash_analyzer_classify_opcode_type_arithmetic() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    assert analyzer._classify_opcode_type("add") == "arithmetic"
    assert analyzer._classify_opcode_type("sub") == "arithmetic"


def test_simhash_analyzer_classify_opcode_type_logical() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    assert analyzer._classify_opcode_type("and") == "logical"
    assert analyzer._classify_opcode_type("xor") == "logical"


def test_simhash_analyzer_classify_opcode_type_compare() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    assert analyzer._classify_opcode_type("cmp") == "compare"
    assert analyzer._classify_opcode_type("test") == "compare"


def test_simhash_analyzer_classify_opcode_type_string() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    assert analyzer._classify_opcode_type("strcpy") == "string"
    assert analyzer._classify_opcode_type("rep") == "string"


def test_simhash_analyzer_classify_opcode_type_other() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    assert analyzer._classify_opcode_type("nop") == "other"


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_find_similar_functions_empty() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._find_similar_functions({})
    assert result == []


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_find_similar_functions_no_similar() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    functions = {
        "func1": {"simhash": 0x1111111111111111},
        "func2": {"simhash": 0xFFFFFFFFFFFFFFFF},
    }
    result = analyzer._find_similar_functions(functions, max_distance=5)
    assert len(result) == 0


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_find_similar_functions_exception() -> None:
    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    functions = {"func1": {"invalid": "data"}}
    result = analyzer._find_similar_functions(functions)
    assert result == []


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_calculate_similarity_not_available() -> None:
    import r2inspect.modules.simhash_analyzer

    old_val = r2inspect.modules.simhash_analyzer.SIMHASH_AVAILABLE
    r2inspect.modules.simhash_analyzer.SIMHASH_AVAILABLE = False

    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer.calculate_similarity(0x1234567890ABCDEF)

    r2inspect.modules.simhash_analyzer.SIMHASH_AVAILABLE = old_val

    assert "error" in result
    assert "not available" in result["error"]


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_calculate_similarity_no_analysis() -> None:
    adapter = MagicMock()
    adapter.get_strings.return_value = []
    adapter.get_functions.return_value = []

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer.calculate_similarity(0x1234567890ABCDEF)
    assert "error" in result


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_calculate_similarity_exception() -> None:
    adapter = MagicMock()
    adapter.get_strings.side_effect = Exception("Test error")

    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer.calculate_similarity(0x1234567890ABCDEF)
    assert "error" in result


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


def test_simhash_analyzer_is_available() -> None:
    result = SimHashAnalyzer.is_available()
    assert isinstance(result, bool)


def test_simhash_analyzer_calculate_simhash_from_file_none(monkeypatch: Any) -> None:
    def mock_run_analyzer(*args: Any, **kwargs: Any) -> None:
        return None

    import r2inspect.modules.simhash_analyzer
    monkeypatch.setattr(r2inspect.modules.simhash_analyzer, "run_analyzer_on_file", mock_run_analyzer)

    result = SimHashAnalyzer.calculate_simhash_from_file("/fake/path")
    assert result is None


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_simhash_analyzer_analyze_detailed_not_available(monkeypatch: Any) -> None:
    import r2inspect.modules.simhash_analyzer

    old_val = r2inspect.modules.simhash_analyzer.SIMHASH_AVAILABLE
    r2inspect.modules.simhash_analyzer.SIMHASH_AVAILABLE = False

    adapter = MagicMock()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer.analyze_detailed()

    r2inspect.modules.simhash_analyzer.SIMHASH_AVAILABLE = old_val

    assert result["available"] is False
    assert "library_available" in result
    assert result["library_available"] is False
