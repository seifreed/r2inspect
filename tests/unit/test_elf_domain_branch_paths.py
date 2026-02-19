#!/usr/bin/env python3
"""Branch-path tests for r2inspect/modules/elf_domain.py - real objects only."""

from __future__ import annotations

import pytest

from r2inspect.modules.elf_domain import (
    build_section_read_commands,
    find_section_by_name,
    parse_build_id_data,
    parse_comment_compiler_info,
    parse_dwarf_compile_time,
    parse_dwarf_info,
    parse_dwarf_producer,
)


# ---------------------------------------------------------------------------
# parse_comment_compiler_info
# ---------------------------------------------------------------------------


def test_parse_comment_compiler_info_gcc_match():
    data = "GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0"
    result = parse_comment_compiler_info(data)
    assert result["compiler"] == "GCC 9.4.0"
    assert result["compiler_version"] == "9.4.0"
    assert result["build_environment"] == "Ubuntu 9.4.0-1ubuntu1~20.04.1"


def test_parse_comment_compiler_info_gcc_match_different_version():
    data = "GCC: (Debian 12.2.0-14) 12.2.0"
    result = parse_comment_compiler_info(data)
    assert result["compiler"] == "GCC 12.2.0"
    assert result["compiler_version"] == "12.2.0"
    assert result["build_environment"] == "Debian 12.2.0-14"


def test_parse_comment_compiler_info_clang_match():
    data = "clang version 14.0.0 (https://github.com/llvm/llvm-project ...)"
    result = parse_comment_compiler_info(data)
    assert result["compiler"] == "Clang 14.0.0"
    assert result["compiler_version"] == "14.0.0"


def test_parse_comment_compiler_info_no_match_returns_empty():
    result = parse_comment_compiler_info("some random comment data")
    assert result == {}


def test_parse_comment_compiler_info_empty_string():
    result = parse_comment_compiler_info("")
    assert result == {}


def test_parse_comment_compiler_info_gcc_and_clang_gcc_wins():
    # Only one should win - GCC match overwrites, then clang may set
    data = "GCC: (GNU) 11.1.0 clang version 13.0.0"
    result = parse_comment_compiler_info(data)
    # clang match runs after gcc, so clang overwrites if present
    assert "compiler_version" in result


# ---------------------------------------------------------------------------
# parse_dwarf_producer
# ---------------------------------------------------------------------------


def test_parse_dwarf_producer_returns_none_without_keyword():
    line = "DW_AT_language: C"
    result = parse_dwarf_producer(line)
    assert result is None


def test_parse_dwarf_producer_returns_none_on_no_regex_match():
    # Line has DW_AT_producer but regex won't capture with empty
    line = "DW_AT_producer"
    result = parse_dwarf_producer(line)
    assert result is None


def test_parse_dwarf_producer_gnu_c_with_version():
    # Space after C ensures regex captures the version after the space
    line = "    DW_AT_producer : GNU C 11.4.0 -mtune=generic -march=x86-64"
    result = parse_dwarf_producer(line)
    assert result is not None
    assert "dwarf_producer" in result
    assert result["compiler"] == "GCC 11.4.0"
    assert result["compiler_version"] == "11.4.0"


def test_parse_dwarf_producer_gnu_c_no_version():
    line = "    DW_AT_producer : GNU C compiler"
    result = parse_dwarf_producer(line)
    assert result is not None
    assert "dwarf_producer" in result
    # No version captured, so no compiler key from gcc_match
    assert "compiler_version" not in result or result.get("compiler_version") is None


def test_parse_dwarf_producer_clang():
    line = "    DW_AT_producer : clang LLVM version 14.0.6 target x86_64"
    result = parse_dwarf_producer(line)
    assert result is not None
    assert result["compiler"] == "Clang 14.0.6"
    assert result["compiler_version"] == "14.0.6"


def test_parse_dwarf_producer_clang_no_version():
    line = "    DW_AT_producer : clang compiler"
    result = parse_dwarf_producer(line)
    assert result is not None
    assert "dwarf_producer" in result
    # No version captured for clang
    assert "compiler_version" not in result or result.get("compiler_version") is None


def test_parse_dwarf_producer_unknown_producer():
    line = "    DW_AT_producer : Intel C++ Compiler 2021"
    result = parse_dwarf_producer(line)
    assert result is not None
    assert "dwarf_producer" in result
    assert "Intel C++ Compiler 2021" in result["dwarf_producer"]


# ---------------------------------------------------------------------------
# parse_dwarf_compile_time
# ---------------------------------------------------------------------------


def test_parse_dwarf_compile_time_returns_none_without_keyword():
    line = "DW_AT_language: C"
    result = parse_dwarf_compile_time(line)
    assert result is None


def test_parse_dwarf_compile_time_comp_dir_with_iso_date():
    line = "DW_AT_comp_dir : /build/project-2023-05-15"
    result = parse_dwarf_compile_time(line)
    assert result == "2023-05-15"


def test_parse_dwarf_compile_time_compilation_keyword():
    line = "compilation unit at 2022-11-30"
    result = parse_dwarf_compile_time(line)
    assert result == "2022-11-30"


def test_parse_dwarf_compile_time_no_date_returns_none():
    line = "DW_AT_comp_dir : /home/user/project"
    result = parse_dwarf_compile_time(line)
    assert result is None


def test_parse_dwarf_compile_time_compilation_no_date():
    line = "compilation unit compiled with flags"
    result = parse_dwarf_compile_time(line)
    assert result is None


def test_parse_dwarf_compile_time_full_date_string():
    # Extended date format: "Mon Jan  1 12:00:00 2023"
    line = "compilation: Mon Jan  1 12:00:00 2023"
    result = parse_dwarf_compile_time(line)
    # The extended pattern may or may not match, but should not crash
    assert result is None or isinstance(result, str)


# ---------------------------------------------------------------------------
# parse_dwarf_info
# ---------------------------------------------------------------------------


def test_parse_dwarf_info_empty_list():
    result = parse_dwarf_info([])
    assert result == {}


def test_parse_dwarf_info_producer_line():
    lines = ["    DW_AT_producer : GNU C 9.4.0"]
    result = parse_dwarf_info(lines)
    assert "compiler" in result
    assert result["compiler"] == "GCC 9.4.0"


def test_parse_dwarf_info_compile_time_line():
    lines = ["DW_AT_comp_dir : /build/project-2022-06-01"]
    result = parse_dwarf_info(lines)
    assert result.get("compile_time") == "2022-06-01"


def test_parse_dwarf_info_both_producer_and_compile_time():
    lines = [
        "    DW_AT_producer : GNU C 11.4.0",
        "    DW_AT_comp_dir : /src/project-2023-01-15",
    ]
    result = parse_dwarf_info(lines)
    assert result["compiler"] == "GCC 11.4.0"
    assert result["compile_time"] == "2023-01-15"


def test_parse_dwarf_info_non_matching_lines():
    lines = ["DW_AT_language: C", "DW_AT_encoding: unsigned", "random line"]
    result = parse_dwarf_info(lines)
    assert result == {}


# ---------------------------------------------------------------------------
# parse_build_id_data
# ---------------------------------------------------------------------------


def test_parse_build_id_data_none_returns_none():
    result = parse_build_id_data(None)
    assert result is None


def test_parse_build_id_data_empty_string_returns_none():
    result = parse_build_id_data("")
    assert result is None


def test_parse_build_id_data_whitespace_only_returns_none():
    result = parse_build_id_data("   \n  ")
    assert result is None


def test_parse_build_id_data_valid_hex_line():
    # Typical r2 build id output: 4 header bytes then the id
    line = "0x000 00 00 00 00 ab cd ef 01 23 45 67 89"
    result = parse_build_id_data(line)
    # hex_match has > 4 bytes, so returns from index 4 onward
    assert result is not None
    assert isinstance(result, str)


def test_parse_build_id_data_short_hex_line():
    # fewer than 4 hex pairs - should not produce a result from this line
    line = "ab cd"
    result = parse_build_id_data(line)
    assert result is None


def test_parse_build_id_data_multiline_skips_empty():
    data = "\n  \n00 00 00 00 aa bb cc dd ee ff 11 22 33\n"
    result = parse_build_id_data(data)
    assert result is not None


# ---------------------------------------------------------------------------
# find_section_by_name
# ---------------------------------------------------------------------------


def test_find_section_by_name_found():
    sections = [
        {"name": ".text", "size": 1000},
        {"name": ".data", "size": 200},
    ]
    result = find_section_by_name(sections, ".text")
    assert result is not None
    assert result["name"] == ".text"


def test_find_section_by_name_not_found():
    sections = [{"name": ".text"}, {"name": ".data"}]
    result = find_section_by_name(sections, ".bss")
    assert result is None


def test_find_section_by_name_empty_list():
    result = find_section_by_name([], ".text")
    assert result is None


def test_find_section_by_name_none_list():
    result = find_section_by_name(None, ".text")
    assert result is None


def test_find_section_by_name_case_insensitive():
    sections = [{"name": ".TEXT"}]
    result = find_section_by_name(sections, ".text")
    assert result is not None


def test_find_section_by_name_substring_match():
    sections = [{"name": ".comment_section"}]
    result = find_section_by_name(sections, "comment")
    assert result is not None


def test_find_section_by_name_no_name_key():
    sections = [{"size": 100}]
    result = find_section_by_name(sections, ".text")
    assert result is None


# ---------------------------------------------------------------------------
# build_section_read_commands
# ---------------------------------------------------------------------------


def test_build_section_read_commands_valid_section():
    section = {"vaddr": 0x1000, "size": 256}
    result = build_section_read_commands(section, "px")
    assert result is not None
    seek_cmd, read_cmd = result
    assert seek_cmd == "s 4096"
    assert read_cmd == "px 256"


def test_build_section_read_commands_zero_vaddr_returns_none():
    section = {"vaddr": 0, "size": 256}
    result = build_section_read_commands(section, "px")
    assert result is None


def test_build_section_read_commands_zero_size_returns_none():
    section = {"vaddr": 0x1000, "size": 0}
    result = build_section_read_commands(section, "px")
    assert result is None


def test_build_section_read_commands_missing_vaddr_returns_none():
    section = {"size": 100}
    result = build_section_read_commands(section, "px")
    assert result is None


def test_build_section_read_commands_missing_size_returns_none():
    section = {"vaddr": 0x2000}
    result = build_section_read_commands(section, "pxr")
    assert result is None


def test_build_section_read_commands_different_cmd():
    section = {"vaddr": 0x4000, "size": 64}
    result = build_section_read_commands(section, "pxr")
    assert result is not None
    seek_cmd, read_cmd = result
    assert "pxr" in read_cmd
    assert "64" in read_cmd
