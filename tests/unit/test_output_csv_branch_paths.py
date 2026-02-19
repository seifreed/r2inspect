#!/usr/bin/env python3
"""Branch-path tests for r2inspect/utils/output_csv.py.

Covers missing lines: 74-78, 93, 97-102, 127-128, 144-145, 147-148,
150-151, 153-154, 159-160, 195-200, 230-233, 254-255, 259, 261-262, 276-277.
"""

from __future__ import annotations

from typing import Any

import pytest

from r2inspect.utils.output_csv import CsvOutputFormatter


# ---------------------------------------------------------------------------
# to_csv – exception path (lines 74-78)
# ---------------------------------------------------------------------------


def test_to_csv_exception_path_writes_error_row():
    # file_info=None causes _add_file_info to raise AttributeError when it
    # calls None.get(...).  _extract_csv_data catches it and adds an "error"
    # key.  dict_writer.writerow then raises ValueError (extra key) which is
    # caught by to_csv's own except block.
    formatter = CsvOutputFormatter({"file_info": None})
    output = formatter.to_csv()
    assert "Error" in output or "CSV Export Failed" in output or "error" in output.lower()


# ---------------------------------------------------------------------------
# _extract_names_from_list – non-list and mixed-item branches (lines 93, 101-102)
# ---------------------------------------------------------------------------


def test_extract_names_from_list_non_list_value_returns_empty():
    formatter = CsvOutputFormatter({})
    result = formatter._extract_names_from_list({"key": "not_a_list"}, "key")
    assert result == ""


def test_extract_names_from_list_non_dict_items_are_stringified():
    formatter = CsvOutputFormatter({})
    data = {"imports": ["kernel32.dll", "ntdll.dll"]}
    result = formatter._extract_names_from_list(data, "imports")
    assert "kernel32.dll" in result
    assert "ntdll.dll" in result


def test_extract_names_from_list_mixed_dict_and_string_items():
    formatter = CsvOutputFormatter({})
    data = {"items": [{"name": "alpha"}, "plain_string", {"name": ""}, ""]}
    result = formatter._extract_names_from_list(data, "items")
    assert "alpha" in result
    assert "plain_string" in result


def test_extract_names_from_list_dict_item_without_name_field():
    formatter = CsvOutputFormatter({})
    data = {"items": [{"other_field": "val"}]}
    result = formatter._extract_names_from_list(data, "items")
    assert result == ""


# ---------------------------------------------------------------------------
# _extract_csv_data – exception path (lines 127-128)
# ---------------------------------------------------------------------------


def test_extract_csv_data_exception_adds_error_key():
    # Pass file_info=None to trigger AttributeError in _add_file_info
    formatter = CsvOutputFormatter({"file_info": None})
    csv_row = formatter._extract_csv_data({"file_info": None})
    assert "error" in csv_row


# ---------------------------------------------------------------------------
# _extract_compile_time – elf_info, macho_info, file_info branches
# (lines 144-154)
# ---------------------------------------------------------------------------


def test_extract_compile_time_from_pe_info():
    formatter = CsvOutputFormatter({})
    data = {"pe_info": {"compile_time": "2024-01-01"}}
    assert formatter._extract_compile_time(data) == "2024-01-01"


def test_extract_compile_time_pe_info_empty_value_returns_empty():
    formatter = CsvOutputFormatter({})
    data = {"pe_info": {"compile_time": ""}}
    assert formatter._extract_compile_time(data) == ""


def test_extract_compile_time_from_elf_info():
    formatter = CsvOutputFormatter({})
    data = {"elf_info": {"compile_time": "2024-06-15"}}
    assert formatter._extract_compile_time(data) == "2024-06-15"


def test_extract_compile_time_elf_info_falsy_value_returns_empty():
    formatter = CsvOutputFormatter({})
    data = {"elf_info": {"compile_time": None}}
    assert formatter._extract_compile_time(data) == ""


def test_extract_compile_time_from_macho_info():
    formatter = CsvOutputFormatter({})
    data = {"macho_info": {"compile_time": "2023-12-01"}}
    assert formatter._extract_compile_time(data) == "2023-12-01"


def test_extract_compile_time_macho_info_empty_value_returns_empty():
    formatter = CsvOutputFormatter({})
    data = {"macho_info": {"compile_time": ""}}
    assert formatter._extract_compile_time(data) == ""


def test_extract_compile_time_from_file_info():
    formatter = CsvOutputFormatter({})
    data = {"file_info": {"compile_time": "2022-03-10"}}
    assert formatter._extract_compile_time(data) == "2022-03-10"


def test_extract_compile_time_file_info_none_value_returns_empty():
    formatter = CsvOutputFormatter({})
    data = {"file_info": {"compile_time": None}}
    assert formatter._extract_compile_time(data) == ""


def test_extract_compile_time_no_source_returns_empty():
    formatter = CsvOutputFormatter({})
    assert formatter._extract_compile_time({}) == ""


# ---------------------------------------------------------------------------
# _extract_imphash – present value and absent (lines 159-160)
# ---------------------------------------------------------------------------


def test_extract_imphash_present_value():
    formatter = CsvOutputFormatter({})
    data = {"pe_info": {"imphash": "abc123"}}
    assert formatter._extract_imphash(data) == "abc123"


def test_extract_imphash_empty_value_returns_empty():
    formatter = CsvOutputFormatter({})
    data = {"pe_info": {"imphash": ""}}
    assert formatter._extract_imphash(data) == ""


def test_extract_imphash_no_pe_info_returns_empty():
    formatter = CsvOutputFormatter({})
    assert formatter._extract_imphash({}) == ""


# ---------------------------------------------------------------------------
# _format_rich_header_compilers – compiler loop (lines 195-200)
# ---------------------------------------------------------------------------


def test_format_rich_header_compilers_with_valid_compilers():
    formatter = CsvOutputFormatter({})
    rich_header_info: dict[str, Any] = {
        "compilers": [
            {"compiler_name": "MSVC 19.0", "count": 5},
            {"compiler_name": "MSVC 18.0", "count": 3},
        ]
    }
    result = formatter._format_rich_header_compilers(rich_header_info)
    assert "MSVC 19.0(5)" in result
    assert "MSVC 18.0(3)" in result


def test_format_rich_header_compilers_skips_unnamed_entries():
    formatter = CsvOutputFormatter({})
    rich_header_info: dict[str, Any] = {
        "compilers": [
            {"compiler_name": "", "count": 2},
            {"compiler_name": "MSVC 19.0", "count": 1},
        ]
    }
    result = formatter._format_rich_header_compilers(rich_header_info)
    assert "MSVC 19.0(1)" in result
    assert result.count("(") == 1


def test_format_rich_header_compilers_non_dict_items_skipped():
    formatter = CsvOutputFormatter({})
    rich_header_info: dict[str, Any] = {"compilers": ["not_a_dict"]}
    result = formatter._format_rich_header_compilers(rich_header_info)
    assert result == ""


def test_format_rich_header_compilers_empty():
    formatter = CsvOutputFormatter({})
    assert formatter._format_rich_header_compilers({}) == ""


# ---------------------------------------------------------------------------
# _count_duplicate_machoc (lines 230-233)
# ---------------------------------------------------------------------------


def test_count_duplicate_machoc_no_duplicates():
    formatter = CsvOutputFormatter({})
    hashes = {"func_a": "hash1", "func_b": "hash2"}
    assert formatter._count_duplicate_machoc(hashes) == 0


def test_count_duplicate_machoc_with_duplicates():
    formatter = CsvOutputFormatter({})
    hashes = {"func_a": "hash1", "func_b": "hash1", "func_c": "hash2"}
    assert formatter._count_duplicate_machoc(hashes) == 1


def test_count_duplicate_machoc_empty_returns_zero():
    formatter = CsvOutputFormatter({})
    assert formatter._count_duplicate_machoc({}) == 0


def test_count_duplicate_machoc_all_same_hash():
    formatter = CsvOutputFormatter({})
    hashes = {"f1": "h1", "f2": "h1", "f3": "h1"}
    assert formatter._count_duplicate_machoc(hashes) == 2


# ---------------------------------------------------------------------------
# _format_file_size – KB/MB conversion and error path (lines 254-255, 259, 261-262)
# ---------------------------------------------------------------------------


def test_format_file_size_bytes():
    formatter = CsvOutputFormatter({})
    assert formatter._format_file_size(512) == "512 B"


def test_format_file_size_kilobytes():
    formatter = CsvOutputFormatter({})
    result = formatter._format_file_size(2048)
    assert "KB" in result
    assert "2.0" in result


def test_format_file_size_megabytes():
    formatter = CsvOutputFormatter({})
    result = formatter._format_file_size(2 * 1024 * 1024)
    assert "MB" in result


def test_format_file_size_zero():
    formatter = CsvOutputFormatter({})
    assert formatter._format_file_size(0) == "0 B"


def test_format_file_size_invalid_input_returns_stringified():
    formatter = CsvOutputFormatter({})
    result = formatter._format_file_size("not_a_number")  # type: ignore[arg-type]
    assert result == "not_a_number"


# ---------------------------------------------------------------------------
# _clean_file_type (lines 269-274, 276-277)
# ---------------------------------------------------------------------------


def test_clean_file_type_removes_section_count():
    formatter = CsvOutputFormatter({})
    result = formatter._clean_file_type("PE32 executable, 5 sections")
    assert "5 sections" not in result
    assert "PE32" in result


def test_clean_file_type_removes_sections_at_start():
    formatter = CsvOutputFormatter({})
    result = formatter._clean_file_type("3 sections, ELF binary")
    assert "3 sections" not in result


def test_clean_file_type_no_section_info():
    formatter = CsvOutputFormatter({})
    result = formatter._clean_file_type("PE32 executable")
    assert result == "PE32 executable"


def test_clean_file_type_empty_string():
    formatter = CsvOutputFormatter({})
    assert formatter._clean_file_type("") == ""


# ---------------------------------------------------------------------------
# _add_tlsh – stats branch (lines 195-200 overlap with tlsh stats)
# ---------------------------------------------------------------------------


def test_add_tlsh_with_stats():
    formatter = CsvOutputFormatter({})
    csv_row: dict[str, Any] = {}
    data = {
        "tlsh": {
            "binary_tlsh": "T1ABC",
            "text_section_tlsh": "T1DEF",
            "stats": {"functions_with_tlsh": 42},
        }
    }
    formatter._add_tlsh(csv_row, data)
    assert csv_row["tlsh_binary"] == "T1ABC"
    assert csv_row["tlsh_text_section"] == "T1DEF"
    assert csv_row["tlsh_functions_with_hash"] == 42


def test_add_tlsh_missing_stats_defaults_to_zero():
    formatter = CsvOutputFormatter({})
    csv_row: dict[str, Any] = {}
    data = {"tlsh": {"binary_tlsh": "T1ABC"}}
    formatter._add_tlsh(csv_row, data)
    assert csv_row["tlsh_functions_with_hash"] == 0


# ---------------------------------------------------------------------------
# _add_function_info – machoc_hashes branch (lines 223-225)
# ---------------------------------------------------------------------------


def test_add_function_info_with_machoc_hashes():
    formatter = CsvOutputFormatter({})
    csv_row: dict[str, Any] = {}
    data = {
        "functions": {
            "total_functions": 10,
            "machoc_hashes": {
                "func_a": "h1",
                "func_b": "h1",
                "func_c": "h2",
            },
        }
    }
    formatter._add_function_info(csv_row, data)
    assert csv_row["num_functions"] == 10
    assert csv_row["num_unique_machoc"] == 2
    assert csv_row["num_duplicate_functions"] == 1


def test_add_function_info_empty_functions():
    formatter = CsvOutputFormatter({})
    csv_row: dict[str, Any] = {}
    formatter._add_function_info(csv_row, {})
    assert csv_row["num_functions"] == 0
    assert csv_row["num_unique_machoc"] == 0
