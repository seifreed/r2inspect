from __future__ import annotations

from r2inspect.modules import elf_domain, macho_domain


def test_elf_domain_edge_cases() -> None:
    assert elf_domain.parse_comment_compiler_info("no compiler here") == {}
    assert elf_domain.parse_build_id_data("Build ID: 01 02") is None
    assert elf_domain.find_section_by_name([{"name": None}], "text") is None
    assert elf_domain.build_section_read_commands({"vaddr": 0, "size": 1}, "pxj") is None
    assert elf_domain.build_section_read_commands({"vaddr": 1, "size": 0}, "pxj") is None

    dwarf_lines = [
        "DW_AT_producer: clang 17.0.1",
        "compilation time: Mon Jan 01 01:02:03 2024",
    ]
    parsed = elf_domain.parse_dwarf_info(dwarf_lines)
    assert parsed.get("compiler") == "Clang 17.0.1"
    assert parsed.get("compile_time") == "Mon Jan 01 01:02:03 2024"


def test_macho_domain_edge_cases() -> None:
    assert macho_domain.estimate_from_sdk_version("SDK 14.0") == "~2023 (SDK SDK 14.0)"
    assert macho_domain.platform_from_version_min("lc_version_min_macosx") is None

    text, raw = macho_domain.dylib_timestamp_to_string(2**63)
    assert raw == 2**63
    assert text is None
