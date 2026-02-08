from __future__ import annotations

from r2inspect.modules.compiler_domain import (
    calculate_compiler_score,
    detect_clang_version,
    detect_gcc_version,
    detect_go_version,
    detect_msvc_version,
    detection_method,
    map_msvc_version_from_rich,
)
from r2inspect.modules.elf_domain import (
    build_section_read_commands,
    find_section_by_name,
    parse_build_id_data,
    parse_comment_compiler_info,
    parse_dwarf_compile_time,
    parse_dwarf_info,
    parse_dwarf_producer,
)
from r2inspect.modules.macho_domain import (
    build_load_commands,
    build_sections,
    dylib_timestamp_to_string,
    estimate_from_sdk_version,
    platform_from_version_min,
)
from r2inspect.modules.pe_info_domain import (
    apply_optional_header_info,
    characteristics_from_bin,
    characteristics_from_header,
    compute_entry_point,
    determine_pe_file_type,
    determine_pe_format,
    normalize_pe_format,
    normalize_resource_entries,
    parse_version_info_text,
)


def test_compiler_domain_helpers() -> None:
    score = calculate_compiler_score(
        signatures={"strings": ["gcc"], "imports": [], "sections": [], "symbols": []},
        strings_data=["gcc 9.3"],
        imports_data=[],
        sections_data=[],
        symbols_data=[],
    )
    assert 0.0 <= score <= 1.0
    assert "High confidence" in detection_method("MSVC", 0.9)
    assert "Medium confidence" in detection_method("GCC", 0.7)
    assert "Low confidence" in detection_method("FASM", 0.1)
    assert map_msvc_version_from_rich("VS 2022") == "Visual Studio 2022"
    assert detect_msvc_version(["Microsoft Visual C++ 19.0"], ["msvcrt"], {"msvcrt": "VS"})
    assert detect_gcc_version(["GCC: (GNU) 9.3.0"]) == "GCC 9.3.0"
    assert detect_clang_version(["clang version 6.0.0"]) == "Clang 6.0.0"
    assert detect_go_version(["go1.20.1"]) == "Go 1.20.1"


def test_elf_domain_helpers() -> None:
    info = parse_comment_compiler_info("GCC: (GNU) 9.3.0")
    assert info["compiler_version"] == "9.3.0"
    dwarf = parse_dwarf_info(
        [
            "DW_AT_producer : GNU C 9.3.0",
            "DW_AT_comp_dir : /build 2024-01-01",
        ]
    )
    assert dwarf["compiler"].startswith("GCC")
    assert parse_dwarf_producer("DW_AT_producer : clang 13.0.0")
    assert parse_dwarf_compile_time("compilation 2025-01-02")
    assert parse_build_id_data("Build ID: aa bb cc dd ee ff") == "eeff"
    sections = [{"name": ".text", "vaddr": 1, "size": 2}]
    assert find_section_by_name(sections, "text") == sections[0]
    assert build_section_read_commands(sections[0], "px") == ("s 1", "px 2")


def test_macho_domain_helpers() -> None:
    assert estimate_from_sdk_version("SDK 13.0")
    assert platform_from_version_min("MACOSX")
    assert platform_from_version_min("IPHONEOS")
    assert dylib_timestamp_to_string(1)[0] is not None
    assert dylib_timestamp_to_string(0) == (None, None)
    headers = [{"type": "LC_SEGMENT", "size": 1, "offset": 2}]
    assert build_load_commands(headers)[0]["type"] == "LC_SEGMENT"
    sections = [{"name": "__text", "segment": "__TEXT", "size": 1}]
    assert build_sections(sections)[0]["name"] == "__text"


def test_pe_info_domain_helpers() -> None:
    assert determine_pe_file_type({"class": "PE"}, None, "DLL") == "DLL"
    assert determine_pe_format({"format": "PE32"}, None) == "PE32"
    assert normalize_pe_format("PE32+") == "PE"
    assert compute_entry_point({"baddr": 10, "boffset": 5}, [{"vaddr": 99}]) == 99
    updated = apply_optional_header_info(
        {"image_base": 0}, {"optional_header": {"ImageBase": 4096}}
    )
    assert updated["image_base"] == 4096
    assert (
        characteristics_from_header({"file_header": {"Characteristics": 0x2002}})["is_dll"] is True
    )
    assert normalize_resource_entries([{"name": "A", "type": "T", "size": 1, "lang": "en"}])
    assert parse_version_info_text("A=1\nB=2")["B"] == "2"
    assert characteristics_from_bin({"type": "dll", "class": "pe"}, "file.dll")["is_dll"] is True
