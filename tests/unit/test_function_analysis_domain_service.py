"""Pure domain tests for function analysis services."""

from r2inspect.domain.services.function_analysis import (
    build_function_stats,
    build_machoc_summary,
    calculate_cyclomatic_complexity_from_blocks,
    classify_function_type,
    extract_mnemonics_from_ops,
    extract_mnemonics_from_text,
    group_functions_by_machoc_hash,
    machoc_hash_from_mnemonics,
)


def test_build_function_stats_summarizes_sizes_and_types() -> None:
    functions = [
        {"name": "func1", "size": 100, "type": "fcn"},
        {"name": "func2", "size": 200, "type": "fcn"},
        {"name": "func3", "size": 150, "type": "imp"},
    ]

    result = build_function_stats(functions)

    assert result["total_functions"] == 3
    assert result["functions_with_size"] == 3
    assert result["avg_function_size"] == 150.0
    assert result["function_types"] == {"fcn": 2, "imp": 1}
    assert result["largest_functions"][0] == ("func2", 200)


def test_build_function_stats_empty_input_returns_empty_dict() -> None:
    assert build_function_stats([]) == {}
    assert build_function_stats(None) == {}


def test_build_function_stats_accepts_string_sizes() -> None:
    functions = [
        {"name": "func1", "size": "10", "type": "fcn"},
        {"name": "func2", "size": "25", "type": "imp"},
        {"name": "func3", "size": "abc", "type": "fcn"},
    ]

    result = build_function_stats(functions)

    assert result["total_functions"] == 3
    assert result["functions_with_size"] == 2
    assert result["avg_function_size"] == 17.5
    assert result["total_code_size"] == 35
    assert result["largest_functions"][0] == ("func2", 25)


def test_group_functions_by_machoc_hash_keeps_only_duplicates() -> None:
    hashes = {"a": "h1", "b": "h1", "c": "h2", "d": "h3", "e": "h3"}

    result = group_functions_by_machoc_hash(hashes)

    assert result == {"h1": ["a", "b"], "h3": ["d", "e"]}


def test_build_machoc_summary_reports_common_patterns() -> None:
    hashes = {"func_a": "abcdef1234567890x", "func_b": "abcdef1234567890x", "func_c": "z"}

    result = build_machoc_summary(hashes)

    assert result["total_functions_hashed"] == 3
    assert result["unique_machoc_hashes"] == 2
    assert result["duplicate_function_groups"] == 1
    assert result["total_duplicate_functions"] == 2
    assert result["similarities"] == {"abcdef1234567890x": ["func_a", "func_b"]}
    assert result["most_common_patterns"] == [(2, "abcdef1234567890")]


def test_build_machoc_summary_without_hashes_returns_error() -> None:
    assert build_machoc_summary({}) == {"error": "No MACHOC hashes available"}
    assert build_machoc_summary(None) == {"error": "No MACHOC hashes available"}


def test_calculate_cyclomatic_complexity_from_blocks_uses_edges_and_nodes() -> None:
    blocks = [
        {"offset": 0x1000, "jump": 0x1010, "fail": 0x1020},
        {"offset": 0x1010},
        {"offset": 0x1020},
    ]

    assert calculate_cyclomatic_complexity_from_blocks(blocks) == 1


def test_calculate_cyclomatic_complexity_from_blocks_empty_returns_zero() -> None:
    assert calculate_cyclomatic_complexity_from_blocks([]) == 0
    assert calculate_cyclomatic_complexity_from_blocks(None) == 0


def test_classify_function_type_uses_name_and_size_heuristics() -> None:
    assert classify_function_type("kernel32_CreateFile", {}) == "library"
    assert classify_function_type("lib_helper", {}) == "library"
    assert classify_function_type("j_printf", {}) == "thunk"
    assert classify_function_type("small", {"size": 5}) == "thunk"
    assert classify_function_type("main", {"size": 100}) == "user"
    assert classify_function_type("sub_401000", {"size": 100}) == "user"
    assert classify_function_type("weird_name", {"size": 100}) == "unknown"
    assert classify_function_type("glib_start", {"size": 100}) == "unknown"
    assert classify_function_type("calibrate_loop", {"size": 100}) == "unknown"
    assert classify_function_type(None, {}) == "unknown"


def test_classify_function_type_accepts_string_size() -> None:
    assert classify_function_type("normal", {"size": "5"}) == "thunk"
    assert classify_function_type("normal", {"size": "50"}) == "unknown"


def test_mnemonic_helpers_and_hash_remain_stable() -> None:
    ops = [{"opcode": "mov eax, ebx"}, {"opcode": "push ecx"}]
    text = "mov eax, ebx\npush ecx"

    assert extract_mnemonics_from_ops(ops) == ["mov", "push"]
    assert extract_mnemonics_from_text(text) == ["mov", "push"]
    assert extract_mnemonics_from_text(None) == []
    assert machoc_hash_from_mnemonics(["mov", "push"])
    assert machoc_hash_from_mnemonics([]) is None


def test_extract_mnemonics_from_text_skips_pi_addresses() -> None:
    text = "  0x401000 mov eax, ebx\n  0x401005 ret"
    assert extract_mnemonics_from_text(text) == ["mov", "ret"]


def test_extract_mnemonics_from_ops_accepts_mnemonic_key() -> None:
    ops = [{"mnemonic": "mov"}, {"mnemonic": "ret"}]
    assert extract_mnemonics_from_ops(ops) == ["mov", "ret"]
