from __future__ import annotations

import time

import pytest

from r2inspect.modules import elf_domain, macho_domain


@pytest.mark.unit
def test_elf_domain_parsers() -> None:
    gcc_info = elf_domain.parse_comment_compiler_info("GCC: (Ubuntu 9.3.0) 9.3.0")
    assert gcc_info["compiler"] == "GCC 9.3.0"

    clang_info = elf_domain.parse_comment_compiler_info("clang version 14.0.0")
    assert clang_info["compiler"] == "Clang 14.0.0"

    dwarf_lines = [
        "DW_AT_producer : GNU C 11.2.0",
        "DW_AT_comp_dir : 2024-01-02",
    ]
    info = elf_domain.parse_dwarf_info(dwarf_lines)
    assert info["compiler"] == "GCC 11.2.0"
    assert info["compile_time"] == "2024-01-02"

    assert elf_domain.parse_dwarf_producer("no producer") is None
    assert elf_domain.parse_dwarf_compile_time("no date") is None

    build_id = elf_domain.parse_build_id_data("build-id: 00 11 22 33 44 55 66")
    assert build_id == "445566"

    sections = [{"name": ".text"}, {"name": ".data"}]
    assert elf_domain.find_section_by_name(sections, "text") == {"name": ".text"}
    assert elf_domain.find_section_by_name([], "none") is None

    assert elf_domain.build_section_read_commands({"vaddr": 0, "size": 10}, "p8") is None
    assert elf_domain.build_section_read_commands({"vaddr": 1, "size": 0}, "p8") is None
    assert elf_domain.build_section_read_commands({"vaddr": 1, "size": 10}, "p8") == (
        "s 1",
        "p8 10",
    )


@pytest.mark.unit
def test_macho_domain_helpers() -> None:
    assert macho_domain.estimate_from_sdk_version("12.0") == "~2021 (SDK 12.0)"
    assert macho_domain.estimate_from_sdk_version("unknown") is None

    assert macho_domain.platform_from_version_min("LC_VERSION_MIN_MACOSX") == "macOS"
    assert macho_domain.platform_from_version_min("LC_VERSION_MIN_IPHONEOS") == "iOS"
    assert macho_domain.platform_from_version_min("LC_VERSION_MIN_TVOS") == "tvOS"
    assert macho_domain.platform_from_version_min("LC_VERSION_MIN_WATCHOS") == "watchOS"
    assert macho_domain.platform_from_version_min("OTHER") is None

    text, raw = macho_domain.dylib_timestamp_to_string(0)
    assert text is None and raw is None

    now = int(time.time())
    text, raw = macho_domain.dylib_timestamp_to_string(now)
    assert raw == now

    load_cmds = macho_domain.build_load_commands([{"type": "LC_UUID", "size": 10, "offset": 4}])
    assert load_cmds[0]["type"] == "LC_UUID"

    sections = macho_domain.build_sections(
        [{"name": "__text", "segment": "__TEXT", "type": "code", "flags": "", "size": 1}]
    )
    assert sections[0]["name"] == "__text"
