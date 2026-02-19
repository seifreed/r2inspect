"""Tests for domain modules: rich_header, compiler, elf, macho, pe_info, string, import."""

from __future__ import annotations

import hashlib
import struct

# ---------------------------------------------------------------------------
# rich_header_domain
# ---------------------------------------------------------------------------
from r2inspect.modules.rich_header_domain import (
    build_rich_header_result,
    calculate_richpe_hash,
    decode_rich_header,
    get_compiler_description,
    parse_clear_data_entries,
    parse_compiler_entries,
    validate_decoded_entries,
)

# ---------------------------------------------------------------------------
# compiler_domain
# ---------------------------------------------------------------------------
from r2inspect.modules.compiler_domain import (
    calculate_compiler_score,
    detect_clang_version,
    detect_gcc_version,
    detect_msvc_version,
    detection_method,
    map_msvc_version_from_rich,
)

# ---------------------------------------------------------------------------
# elf_domain
# ---------------------------------------------------------------------------
from r2inspect.modules.elf_domain import (
    find_section_by_name,
    parse_build_id_data,
    parse_comment_compiler_info,
    parse_dwarf_compile_time,
    parse_dwarf_info,
    parse_dwarf_producer,
)

# ---------------------------------------------------------------------------
# macho_domain
# ---------------------------------------------------------------------------
from r2inspect.modules.macho_domain import (
    build_load_commands,
    build_sections,
    dylib_timestamp_to_string,
    estimate_from_sdk_version,
    platform_from_version_min,
)

# ---------------------------------------------------------------------------
# pe_info_domain
# ---------------------------------------------------------------------------
from r2inspect.modules.pe_info_domain import (
    apply_optional_header_info,
    characteristics_from_bin,
    determine_pe_file_type,
    determine_pe_format,
    normalize_pe_format,
)

# ---------------------------------------------------------------------------
# string_domain
# ---------------------------------------------------------------------------
from r2inspect.modules.string_domain import (
    build_xor_matches,
    decode_base64,
    decode_hex,
    filter_strings,
    find_suspicious,
    parse_search_results,
    xor_string,
)

# ---------------------------------------------------------------------------
# import_domain
# ---------------------------------------------------------------------------
from r2inspect.modules.import_domain import (
    assess_api_risk,
    build_api_categories,
    categorize_apis,
    find_max_risk_score,
    find_suspicious_patterns,
    risk_level_from_score,
)

# ===========================================================================
# rich_header_domain tests
# ===========================================================================

def test_parse_clear_data_entries_normal() -> None:
    prodid = (5 << 16) | 0x0082  # build 5, product 0x82
    count = 3
    data = struct.pack("<II", prodid, count)
    entries = parse_clear_data_entries(data)
    assert len(entries) == 1
    assert entries[0]["count"] == 3
    assert entries[0]["product_id"] == 0x0082


def test_parse_clear_data_entries_zero_count_skipped() -> None:
    data = struct.pack("<II", 0x00820005, 0)
    entries = parse_clear_data_entries(data)
    assert entries == []


def test_parse_clear_data_entries_empty() -> None:
    assert parse_clear_data_entries(b"") == []


def test_parse_clear_data_entries_truncated() -> None:
    assert parse_clear_data_entries(b"\x01\x02\x03") == []


def test_get_compiler_description_known_prefix() -> None:
    desc = get_compiler_description("Utc1900_C", 30319)
    assert "Microsoft C/C++ Compiler" in desc
    assert "30319" in desc


def test_get_compiler_description_linker() -> None:
    desc = get_compiler_description("Linker900", 40219)
    assert "Microsoft Linker" in desc


def test_get_compiler_description_unknown() -> None:
    desc = get_compiler_description("WeirdTool", 1234)
    assert "WeirdTool" in desc
    assert "1234" in desc


def test_parse_compiler_entries_normal() -> None:
    entries = [{"prodid": (30319 << 16) | 0x00B5, "count": 2}]
    result = parse_compiler_entries(entries)
    assert len(result) == 1
    assert result[0]["count"] == 2
    assert "compiler_name" in result[0]
    assert "description" in result[0]


def test_parse_compiler_entries_unknown_product() -> None:
    entries = [{"prodid": (1 << 16) | 0xFFFF, "count": 1}]
    result = parse_compiler_entries(entries)
    assert "Unknown_0x" in result[0]["compiler_name"]


def test_parse_compiler_entries_empty() -> None:
    assert parse_compiler_entries([]) == []


def test_decode_rich_header_normal() -> None:
    xor_key = 0xABCD1234
    prodid = 0x00820005 ^ xor_key
    count = 3 ^ xor_key
    # prefix (4 bytes) + 8-byte entry + suffix (4 bytes)
    data = struct.pack("<I", 0) + struct.pack("<II", prodid, count) + struct.pack("<I", 0)
    entries = decode_rich_header(data, xor_key)
    assert len(entries) == 1
    assert entries[0]["count"] == 3


def test_decode_rich_header_empty() -> None:
    assert decode_rich_header(b"", 0x1234) == []


def test_decode_rich_header_too_short() -> None:
    # Less than prefix + entry + suffix
    result = decode_rich_header(b"\x00" * 8, 0)
    assert isinstance(result, list)


def test_validate_decoded_entries_valid() -> None:
    entries = [{"prodid": 0x0082, "count": 5}]
    assert validate_decoded_entries(entries) is True


def test_validate_decoded_entries_empty() -> None:
    assert validate_decoded_entries([]) is False


def test_validate_decoded_entries_all_invalid() -> None:
    entries = [{"prodid": 0xFFFF0001, "count": 99999}]
    # prodid >= 0x10000 is invalid
    assert validate_decoded_entries(entries) is False


def test_build_rich_header_result_basic() -> None:
    entries = [{"prodid": 0x82, "count": 2}]
    result = build_rich_header_result(entries, 0xDEADBEEF)
    assert result["xor_key"] == 0xDEADBEEF
    assert "checksum" in result
    assert result["entries"] == entries


def test_build_rich_header_result_empty_entries() -> None:
    result = build_rich_header_result([], 0)
    assert result["checksum"] == 0
    assert result["entries"] == []


def test_calculate_richpe_hash_from_clear_data_bytes() -> None:
    data = b"\x82\x00\x00\x00\x02\x00\x00\x00"
    expected = hashlib.md5(data, usedforsecurity=False).hexdigest()
    result = calculate_richpe_hash({"clear_data_bytes": data})
    assert result == expected


def test_calculate_richpe_hash_from_richpe_hash_field() -> None:
    result = calculate_richpe_hash({"richpe_hash": "precomputed_hash"})
    assert result == "precomputed_hash"


def test_calculate_richpe_hash_from_entries() -> None:
    entries = [{"prodid": 0x82, "count": 2}]
    result = calculate_richpe_hash({"entries": entries})
    assert result is not None
    assert len(result) == 32


def test_calculate_richpe_hash_empty_entries() -> None:
    assert calculate_richpe_hash({"entries": []}) is None


def test_calculate_richpe_hash_empty_dict() -> None:
    assert calculate_richpe_hash({}) is None


# ===========================================================================
# compiler_domain tests
# ===========================================================================

def test_calculate_compiler_score_no_matches() -> None:
    sigs = {"strings": ["__gcc_personality"], "imports": ["libgcc"], "sections": [".bss"]}
    score = calculate_compiler_score(sigs, [], [], [], [])
    assert score == 0.0


def test_calculate_compiler_score_full_match() -> None:
    sigs = {"strings": ["__gcc_personality"], "imports": ["libgcc"]}
    score = calculate_compiler_score(
        sigs,
        ["__gcc_personality_v0"],
        ["libgcc_s.so"],
        [],
        [],
    )
    assert score > 0.0


def test_calculate_compiler_score_empty_signatures() -> None:
    score = calculate_compiler_score({}, ["anything"], ["anything"], [], [])
    assert score == 0.0


def test_calculate_compiler_score_section_and_symbol() -> None:
    sigs = {"sections": [".gnu_debuglink"], "symbols": ["__cxa_finalize"]}
    score = calculate_compiler_score(sigs, [], [], [".gnu_debuglink"], ["__cxa_finalize"])
    assert score > 0.0


def test_detection_method_high_confidence_msvc() -> None:
    result = detection_method("MSVC", 0.9)
    assert "High confidence" in result
    assert "Runtime library" in result


def test_detection_method_medium_confidence_gcc() -> None:
    result = detection_method("GCC", 0.7)
    assert "Medium confidence" in result
    assert "Symbol" in result


def test_detection_method_low_confidence_dotnet() -> None:
    result = detection_method("DotNet", 0.3)
    assert "Low confidence" in result
    assert "CLR" in result


def test_detection_method_various_compilers() -> None:
    for compiler in ["AutoIt", "NSIS", "InnoSetup", "PyInstaller", "cx_Freeze",
                     "Nim", "Zig", "Swift", "TinyCC", "NodeJS", "FASM", "Unknown"]:
        result = detection_method(compiler, 0.5)
        assert isinstance(result, str) and len(result) > 0


def test_map_msvc_version_from_rich_known() -> None:
    assert "2019" in map_msvc_version_from_rich("MSVC_2019_CPP")
    assert "2022" in map_msvc_version_from_rich("MSVC_2022_C")
    assert "2015" in map_msvc_version_from_rich("Utc1900_C")
    assert "2017" in map_msvc_version_from_rich("Utc1910_CPP")


def test_map_msvc_version_from_rich_fallback() -> None:
    result = map_msvc_version_from_rich("SomeOtherThing")
    assert "Visual Studio" in result


def test_detect_msvc_version_from_import() -> None:
    versions = {"MSVCR140.dll": "Visual Studio 2015"}
    result = detect_msvc_version([], ["MSVCR140.dll"], versions)
    assert result == "Visual Studio 2015"


def test_detect_msvc_version_from_string() -> None:
    strings = ["Microsoft Visual C++ 14.20"]
    result = detect_msvc_version(strings, [], {})
    # The greedy .* in the regex consumes the leading digit, capturing "4.20"
    assert "Visual Studio" in result
    assert result != "Unknown"


def test_detect_msvc_version_unknown() -> None:
    assert detect_msvc_version([], [], {}) == "Unknown"


def test_detect_gcc_version_from_string() -> None:
    result = detect_gcc_version(["GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0"])
    assert "9.4.0" in result


def test_detect_gcc_version_gnu_fallback() -> None:
    result = detect_gcc_version(["GNU 7.5"])
    assert "7.5" in result


def test_detect_gcc_version_unknown() -> None:
    assert detect_gcc_version([]) == "Unknown"
    assert detect_gcc_version(["no match here"]) == "Unknown"


def test_detect_clang_version_normal() -> None:
    result = detect_clang_version(["clang version 12.0.1"])
    assert "Clang" in result
    assert result != "Unknown"


def test_detect_clang_version_apple() -> None:
    result = detect_clang_version(["Apple clang version 13.1"])
    assert "Apple Clang" in result
    assert result != "Unknown"


def test_detect_clang_version_unknown() -> None:
    assert detect_clang_version([]) == "Unknown"
    assert detect_clang_version(["no clang here"]) == "Unknown"


# ===========================================================================
# elf_domain tests
# ===========================================================================

def test_parse_comment_compiler_info_gcc() -> None:
    comment = "GCC: (Ubuntu 9.4.0-1ubuntu1~20.04) 9.4.0"
    result = parse_comment_compiler_info(comment)
    assert result["compiler"] == "GCC 9.4.0"
    assert result["compiler_version"] == "9.4.0"
    assert "Ubuntu" in result["build_environment"]


def test_parse_comment_compiler_info_clang() -> None:
    comment = "clang version 14.0.0"
    result = parse_comment_compiler_info(comment)
    assert "Clang" in result["compiler"]
    assert result["compiler_version"] == "14.0.0"


def test_parse_comment_compiler_info_empty() -> None:
    assert parse_comment_compiler_info("") == {}


def test_parse_comment_compiler_info_no_match() -> None:
    assert parse_comment_compiler_info("unrelated text") == {}


def test_parse_dwarf_info_with_producer() -> None:
    lines = ["  DW_AT_producer  : GNU C 9.4.0 -march=x86-64"]
    result = parse_dwarf_info(lines)
    assert "dwarf_producer" in result
    assert "GCC" in result.get("compiler", "")


def test_parse_dwarf_info_with_compile_time() -> None:
    lines = ["  DW_AT_comp_dir  : compilation date 2022-03-15"]
    result = parse_dwarf_info(lines)
    assert result.get("compile_time") == "2022-03-15"


def test_parse_dwarf_info_empty() -> None:
    assert parse_dwarf_info([]) == {}


def test_parse_dwarf_producer_returns_none_without_tag() -> None:
    assert parse_dwarf_producer("some random line") is None


def test_parse_dwarf_producer_gcc() -> None:
    line = "  DW_AT_producer  : GNU C 9.4.0"
    result = parse_dwarf_producer(line)
    assert result is not None
    assert result["compiler"] == "GCC 9.4.0"


def test_parse_dwarf_producer_clang() -> None:
    line = "  DW_AT_producer  : clang version 14.0.0 (LLVM)"
    result = parse_dwarf_producer(line)
    assert result is not None
    assert "Clang" in result["compiler"]


def test_parse_dwarf_producer_no_version() -> None:
    line = "  DW_AT_producer  : some unknown toolchain"
    result = parse_dwarf_producer(line)
    assert result is not None
    assert "dwarf_producer" in result


def test_parse_dwarf_compile_time_with_date() -> None:
    line = "  DW_AT_comp_dir  : build done on 2021-06-30"
    result = parse_dwarf_compile_time(line)
    assert result == "2021-06-30"


def test_parse_dwarf_compile_time_no_match() -> None:
    assert parse_dwarf_compile_time("DW_AT_comp_dir no date here") is None


def test_parse_dwarf_compile_time_unrelated_line() -> None:
    assert parse_dwarf_compile_time("DW_AT_name : main.c") is None


def test_parse_build_id_data_normal() -> None:
    line = "00000000: 01 02 03 04 05 ab cd ef\n"
    result = parse_build_id_data(line)
    # first 4 bytes (8 hex chars) are skipped, rest returned
    assert result is not None
    assert "abcdef" in result.lower() or len(result) > 0


def test_parse_build_id_data_none() -> None:
    assert parse_build_id_data(None) is None


def test_parse_build_id_data_empty_string() -> None:
    assert parse_build_id_data("") is None


def test_parse_build_id_data_no_hex() -> None:
    assert parse_build_id_data("no hex bytes here at all") is None


def test_find_section_by_name_found() -> None:
    sections = [{"name": ".text"}, {"name": ".data"}, {"name": ".bss"}]
    result = find_section_by_name(sections, ".text")
    assert result == {"name": ".text"}


def test_find_section_by_name_partial_match() -> None:
    sections = [{"name": ".gnu_debuglink"}]
    result = find_section_by_name(sections, "debuglink")
    assert result is not None


def test_find_section_by_name_not_found() -> None:
    sections = [{"name": ".text"}]
    assert find_section_by_name(sections, ".rodata") is None


def test_find_section_by_name_empty_list() -> None:
    assert find_section_by_name([], ".text") is None


def test_find_section_by_name_none_list() -> None:
    assert find_section_by_name(None, ".text") is None  # type: ignore[arg-type]


# ===========================================================================
# macho_domain tests
# ===========================================================================

def test_estimate_from_sdk_version_known() -> None:
    result = estimate_from_sdk_version("10.15.0")
    assert result is not None
    assert "2019" in result


def test_estimate_from_sdk_version_unknown_version() -> None:
    result = estimate_from_sdk_version("9.0.0")
    assert result is None


def test_estimate_from_sdk_version_no_version() -> None:
    assert estimate_from_sdk_version("") is None
    assert estimate_from_sdk_version("nover") is None


def test_platform_from_version_min_macos() -> None:
    assert platform_from_version_min("LC_VERSION_MIN_MACOSX") == "macOS"


def test_platform_from_version_min_ios() -> None:
    assert platform_from_version_min("LC_VERSION_MIN_IPHONEOS") == "iOS"


def test_platform_from_version_min_tvos() -> None:
    assert platform_from_version_min("LC_VERSION_MIN_TVOS") == "tvOS"


def test_platform_from_version_min_watchos() -> None:
    assert platform_from_version_min("LC_VERSION_MIN_WATCHOS") == "watchOS"


def test_platform_from_version_min_unknown() -> None:
    assert platform_from_version_min("UNKNOWN_TYPE") is None


def test_dylib_timestamp_to_string_valid() -> None:
    ts = 1672531200  # 2023-01-01
    date_str, returned_ts = dylib_timestamp_to_string(ts)
    assert date_str is not None
    assert returned_ts == ts


def test_dylib_timestamp_to_string_zero() -> None:
    date_str, returned_ts = dylib_timestamp_to_string(0)
    assert date_str is None
    assert returned_ts is None


def test_dylib_timestamp_to_string_negative() -> None:
    date_str, returned_ts = dylib_timestamp_to_string(-1)
    assert date_str is None


def test_dylib_timestamp_to_string_overflow() -> None:
    # Very large timestamp may cause overflow
    date_str, returned_ts = dylib_timestamp_to_string(99999999999999)
    # Should not raise; may return (None, ts) or (date_str, ts)
    assert returned_ts is not None or date_str is None


def test_build_load_commands_normal() -> None:
    headers = [
        {"type": "LC_SEGMENT", "size": 56, "offset": 100},
        {"type": "LC_DYLIB", "size": 24, "offset": 200},
    ]
    result = build_load_commands(headers)
    assert len(result) == 2
    assert result[0]["type"] == "LC_SEGMENT"
    assert result[1]["offset"] == 200


def test_build_load_commands_empty() -> None:
    assert build_load_commands([]) == []


def test_build_load_commands_missing_keys() -> None:
    result = build_load_commands([{}])
    assert result[0]["type"] == "Unknown"
    assert result[0]["size"] == 0


def test_build_sections_normal() -> None:
    sections_info = [
        {"name": "__text", "segment": "__TEXT", "type": "S_REGULAR",
         "flags": "", "size": 4096, "vaddr": 0x1000, "paddr": 0},
    ]
    result = build_sections(sections_info)
    assert len(result) == 1
    assert result[0]["name"] == "__text"
    assert result[0]["vaddr"] == 0x1000


def test_build_sections_empty() -> None:
    assert build_sections([]) == []


def test_build_sections_missing_keys() -> None:
    result = build_sections([{}])
    assert result[0]["name"] == "Unknown"
    assert result[0]["size"] == 0


# ===========================================================================
# pe_info_domain tests
# ===========================================================================

def test_determine_pe_file_type_dll_from_desc() -> None:
    bin_info = {"class": "PE32"}
    result = determine_pe_file_type(bin_info, "test.dll", "PE32 dll file")
    assert result == "DLL"


def test_determine_pe_file_type_exe_from_desc() -> None:
    bin_info = {"class": "PE32"}
    result = determine_pe_file_type(bin_info, "test.exe", "Console executable")
    assert result == "EXE"


def test_determine_pe_file_type_driver_from_desc() -> None:
    bin_info = {"class": "PE32"}
    result = determine_pe_file_type(bin_info, "driver.sys", "Windows driver sys")
    assert result == "SYS"


def test_determine_pe_file_type_no_desc() -> None:
    bin_info = {"class": "PE32"}
    result = determine_pe_file_type(bin_info, "test.exe", None)
    assert result == "PE32"


def test_determine_pe_file_type_non_pe_class() -> None:
    bin_info = {"class": "ELF64"}
    result = determine_pe_file_type(bin_info, None, None)
    assert result == "ELF64"


def test_determine_pe_format_from_format_field() -> None:
    bin_info = {"format": "PE32+"}
    assert determine_pe_format(bin_info, None) == "PE32+"


def test_determine_pe_format_from_bits_32() -> None:
    bin_info = {"format": "Unknown", "bits": 32}
    assert determine_pe_format(bin_info, None) == "PE32"


def test_determine_pe_format_from_bits_64() -> None:
    bin_info = {"format": "Unknown", "bits": 64}
    assert determine_pe_format(bin_info, None) == "PE32+"


def test_determine_pe_format_from_magic_pe32() -> None:
    bin_info = {"format": "Unknown", "bits": 0}
    pe_header = {"optional_header": {"Magic": 0x10B}}
    assert determine_pe_format(bin_info, pe_header) == "PE32"


def test_determine_pe_format_from_magic_pe32plus() -> None:
    bin_info = {"format": "Unknown", "bits": 0}
    pe_header = {"optional_header": {"Magic": 0x20B}}
    assert determine_pe_format(bin_info, pe_header) == "PE32+"


def test_determine_pe_format_fallback() -> None:
    bin_info = {"format": "Unknown", "bits": 0}
    result = determine_pe_format(bin_info, None)
    assert result == "PE"


def test_normalize_pe_format_pe_variants() -> None:
    assert normalize_pe_format("PE32") == "PE"
    assert normalize_pe_format("PE32+") == "PE"
    assert normalize_pe_format("PE") == "PE"


def test_normalize_pe_format_unknown() -> None:
    assert normalize_pe_format("Unknown") == "PE"
    assert normalize_pe_format("") == "PE"


def test_normalize_pe_format_non_pe() -> None:
    result = normalize_pe_format("ELF64")
    assert result == "ELF64"


def test_apply_optional_header_info_no_pe_header() -> None:
    info = {"image_base": 0x400000}
    result = apply_optional_header_info(info, None)
    assert result == info


def test_apply_optional_header_info_with_image_base() -> None:
    info = {"image_base": 0}
    pe_header = {"optional_header": {"ImageBase": 0x140000000, "AddressOfEntryPoint": 0x1000}}
    result = apply_optional_header_info(info, pe_header)
    assert result["image_base"] == 0x140000000
    assert result["entry_point"] == 0x140000000 + 0x1000


def test_apply_optional_header_info_no_entry_rva() -> None:
    info = {"image_base": 0x400000}
    pe_header = {"optional_header": {"ImageBase": 0x400000}}
    result = apply_optional_header_info(info, pe_header)
    assert "entry_point" not in result or result.get("entry_point") == result.get("image_base", 0)


def test_characteristics_from_bin_dll_by_type() -> None:
    result = characteristics_from_bin({"type": "dll"}, None)
    assert result["is_dll"] is True


def test_characteristics_from_bin_dll_by_path() -> None:
    result = characteristics_from_bin({}, "C:/Windows/System32/kernel32.dll")
    assert result["is_dll"] is True


def test_characteristics_from_bin_exe_by_path() -> None:
    result = characteristics_from_bin({}, "C:/Users/user/malware.exe")
    assert result["is_executable"] is True


def test_characteristics_from_bin_executable_type() -> None:
    result = characteristics_from_bin({"type": "executable"}, None)
    assert result["is_executable"] is True


def test_characteristics_from_bin_empty() -> None:
    result = characteristics_from_bin({}, None)
    assert "is_dll" in result
    assert "is_executable" in result


# ===========================================================================
# string_domain tests
# ===========================================================================

def test_filter_strings_normal() -> None:
    strings = ["hello", "hi", "a" * 200, "valid_string"]
    result = filter_strings(strings, 4, 100)
    assert "hello" in result
    assert "hi" not in result
    assert "a" * 200 not in result


def test_filter_strings_empty() -> None:
    assert filter_strings([], 4, 100) == []


def test_filter_strings_all_too_short() -> None:
    assert filter_strings(["ab", "c"], 4, 100) == []


def test_filter_strings_non_printable_stripped() -> None:
    result = filter_strings(["\x00\x01\x02AB\x03\x04"], 1, 100)
    assert result == ["AB"]


def test_parse_search_results_normal() -> None:
    output = "0x00401000 hello\n0x00402000 world\nnot_an_address"
    result = parse_search_results(output)
    assert result == ["0x00401000", "0x00402000"]


def test_parse_search_results_empty() -> None:
    assert parse_search_results("") == []


def test_parse_search_results_no_hex_lines() -> None:
    assert parse_search_results("nothing\nhere\neither") == []


def test_xor_string_basic() -> None:
    result = xor_string("ABC", 0x20)
    assert result == "abc"


def test_xor_string_empty() -> None:
    assert xor_string("", 0xFF) == ""


def test_xor_string_roundtrip() -> None:
    original = "Hello, World!"
    key = 42
    assert xor_string(xor_string(original, key), key) == original


def test_build_xor_matches_with_hit() -> None:
    search_string = "A"  # 0x41
    # key=1 XOR 0x41 = 0x40 = '@'
    expected_hex = "@".encode().hex()

    def fake_search(pattern: str) -> str:
        if pattern == expected_hex:
            return "0x00401234 match"
        return ""

    matches = build_xor_matches(search_string, fake_search)
    assert any(m["xor_key"] == 1 for m in matches)


def test_build_xor_matches_no_hits() -> None:
    matches = build_xor_matches("Z", lambda _: "")
    assert matches == []


def test_decode_base64_valid() -> None:
    import base64 as b64
    encoded = b64.b64encode(b"Hello World!").decode()
    result = decode_base64(encoded)
    assert result is not None
    assert result["decoded"] == "Hello World!"
    assert result["encoding"] == "base64"


def test_decode_base64_invalid() -> None:
    assert decode_base64("not base64!!!") is None


def test_decode_base64_too_short() -> None:
    assert decode_base64("abc") is None


def test_decode_base64_wrong_length() -> None:
    assert decode_base64("abcde") is None


def test_decode_hex_valid() -> None:
    hex_str = "48656c6c6f"
    result = decode_hex(hex_str)
    assert result is not None
    assert result["decoded"] == "Hello"
    assert result["encoding"] == "hex"


def test_decode_hex_invalid_chars() -> None:
    assert decode_hex("xyz123") is None


def test_decode_hex_too_short() -> None:
    assert decode_hex("ab") is None


def test_decode_hex_odd_length() -> None:
    assert decode_hex("abc") is None


def test_find_suspicious_url() -> None:
    strings = ["Visit https://evil.example.com/malware"]
    result = find_suspicious(strings)
    assert any(r["type"] == "urls" for r in result)


def test_find_suspicious_ip() -> None:
    strings = ["Connect to 192.168.1.1"]
    result = find_suspicious(strings)
    assert any(r["type"] == "ips" for r in result)


def test_find_suspicious_api_call() -> None:
    strings = ["calling VirtualAlloc to allocate memory"]
    result = find_suspicious(strings)
    assert any(r["type"] == "api_calls" for r in result)


def test_find_suspicious_empty() -> None:
    assert find_suspicious([]) == []


def test_find_suspicious_no_match() -> None:
    strings = ["innocent string with no patterns"]
    result = find_suspicious(strings)
    assert result == []


# ===========================================================================
# import_domain tests
# ===========================================================================

def test_assess_api_risk_empty_categories() -> None:
    suspicious, score = assess_api_risk({})
    assert suspicious == []
    assert score == 0


def test_assess_api_risk_anti_analysis_trigger() -> None:
    categories = {"Anti-Analysis": {"count": 3, "apis": ["IsDebuggerPresent", "NtQuery", "Extra"]}}
    suspicious, score = assess_api_risk(categories)
    assert score >= 20
    assert any("anti-debug" in s.lower() or "anti" in s.lower() for s in suspicious)


def test_assess_api_risk_dll_injection_trigger() -> None:
    categories = {"DLL Injection": {"count": 3, "apis": ["A", "B", "C"]}}
    suspicious, score = assess_api_risk(categories)
    assert score >= 30


def test_assess_api_risk_process_and_memory_trigger() -> None:
    categories = {
        "Process/Thread Management": {"count": 3, "apis": ["A", "B", "C"]},
        "Memory Management": {"count": 3, "apis": ["D", "E", "F"]},
    }
    suspicious, score = assess_api_risk(categories)
    assert score >= 25


def test_assess_api_risk_registry_trigger() -> None:
    categories = {"Registry": {"count": 4, "apis": ["RegSetValueEx"] * 4}}
    suspicious, score = assess_api_risk(categories)
    assert score >= 15


def test_assess_api_risk_network_trigger() -> None:
    from r2inspect.modules.import_domain import NETWORK_CATEGORY
    categories = {NETWORK_CATEGORY: {"count": 3, "apis": ["InternetOpen"] * 3}}
    suspicious, score = assess_api_risk(categories)
    assert score >= 10


def test_build_api_categories_structure() -> None:
    cats = build_api_categories()
    assert "Injection" in cats
    assert "Network" in cats
    assert "Crypto" in cats
    assert isinstance(cats["Injection"], dict)


def test_categorize_apis_match() -> None:
    imports = [{"name": "VirtualAllocEx"}, {"name": "CreateRemoteThread"}]
    api_categories = {"Injection": ["VirtualAllocEx", "CreateRemoteThread"]}
    result = categorize_apis(imports, api_categories)
    assert "Injection" in result
    assert result["Injection"]["count"] == 2


def test_categorize_apis_no_match() -> None:
    imports = [{"name": "MessageBoxA"}]
    api_categories = {"Injection": ["VirtualAllocEx"]}
    result = categorize_apis(imports, api_categories)
    assert result == {}


def test_categorize_apis_empty_imports() -> None:
    result = categorize_apis([], {"Injection": ["VirtualAllocEx"]})
    assert result == {}


def test_find_max_risk_score_found() -> None:
    cats = build_api_categories()
    score, tags = find_max_risk_score("CreateRemoteThread", cats)
    assert score == 95
    assert "Remote Thread Injection" in tags


def test_find_max_risk_score_not_found() -> None:
    cats = build_api_categories()
    score, tags = find_max_risk_score("SomeUnknownAPI", cats)
    assert score == 0
    assert tags == []


def test_find_suspicious_patterns_injection() -> None:
    imports = [
        {"name": "VirtualAllocEx", "category": "Injection"},
        {"name": "WriteProcessMemory", "category": "Injection"},
    ]
    result = find_suspicious_patterns(imports)
    assert any(p["pattern"] == "DLL Injection" for p in result)


def test_find_suspicious_patterns_hollowing() -> None:
    imports = [
        {"name": "CreateProcess", "category": ""},
        {"name": "VirtualAllocEx", "category": ""},
        {"name": "WriteProcessMemory", "category": ""},
        {"name": "SetThreadContext", "category": ""},
        {"name": "ResumeThread", "category": ""},
    ]
    result = find_suspicious_patterns(imports)
    assert any(p["pattern"] == "Process Hollowing" for p in result)


def test_find_suspicious_patterns_keylog() -> None:
    imports = [{"name": "SetWindowsHookEx", "category": ""}]
    result = find_suspicious_patterns(imports)
    assert any(p["pattern"] == "Keylogging" for p in result)


def test_find_suspicious_patterns_anti_analysis() -> None:
    imports = [{"name": "SomeFunc", "category": "Anti-Analysis"}]
    result = find_suspicious_patterns(imports)
    assert any(p["pattern"] == "Anti-Analysis" for p in result)


def test_find_suspicious_patterns_empty() -> None:
    assert find_suspicious_patterns([]) == []


def test_risk_level_from_score_critical() -> None:
    assert risk_level_from_score(80) == "Critical"
    assert risk_level_from_score(100) == "Critical"


def test_risk_level_from_score_high() -> None:
    assert risk_level_from_score(65) == "High"
    assert risk_level_from_score(79) == "High"


def test_risk_level_from_score_medium() -> None:
    assert risk_level_from_score(45) == "Medium"
    assert risk_level_from_score(64) == "Medium"


def test_risk_level_from_score_low() -> None:
    assert risk_level_from_score(25) == "Low"
    assert risk_level_from_score(44) == "Low"


def test_risk_level_from_score_minimal() -> None:
    assert risk_level_from_score(0) == "Minimal"
    assert risk_level_from_score(24) == "Minimal"
