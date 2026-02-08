from __future__ import annotations

import logging

import pytest

from r2inspect.modules import elf_domain, macho_domain, pe_resources, rich_header_domain


class DummyAdapter:
    def __init__(self, responses: dict[str, object], raises: bool = False) -> None:
        self._responses = dict(responses)
        self._raises = raises

    def cmd(self, command: str) -> str:
        if self._raises:
            raise RuntimeError("cmd failed")
        return str(self._responses.get(command, ""))

    def cmdj(self, command: str) -> object:
        if self._raises:
            raise RuntimeError("cmdj failed")
        return self._responses.get(command)

    def get_resources_info(self) -> object:
        return self.cmdj("iRj")

    def get_pe_version_info_text(self) -> str:
        return self.cmd("iR~version")


@pytest.mark.unit
def test_elf_domain_parsers_cover_branches() -> None:
    gcc = elf_domain.parse_comment_compiler_info("GCC: (GNU) 12.2.0")
    assert gcc["compiler"] == "GCC 12.2.0"
    assert gcc["build_environment"] == "GNU"

    clang = elf_domain.parse_comment_compiler_info("clang version 16.0.0")
    assert clang["compiler"] == "Clang 16.0.0"

    dwarf = elf_domain.parse_dwarf_info(
        [
            "DW_AT_producer : GNU C 11.2.0",
            "DW_AT_comp_dir : /tmp/build 2024-01-10",
        ]
    )
    assert dwarf["compiler"] == "GCC 11.2.0"
    assert dwarf["compile_time"] == "2024-01-10"

    assert elf_domain.parse_dwarf_producer("no producer") is None
    assert elf_domain.parse_dwarf_compile_time("no time here") is None

    assert elf_domain.parse_build_id_data("Build ID: ab cd ef 01 02 03 04 05") == "02030405"
    assert elf_domain.parse_build_id_data("") is None

    section = elf_domain.find_section_by_name([{"name": ".text"}], "text")
    assert section == {"name": ".text"}
    assert elf_domain.find_section_by_name([], "text") is None

    assert elf_domain.build_section_read_commands({"vaddr": 1, "size": 2}, "px") == (
        "s 1",
        "px 2",
    )
    assert elf_domain.build_section_read_commands({"vaddr": 0, "size": 2}, "px") is None


@pytest.mark.unit
def test_macho_domain_helpers() -> None:
    assert macho_domain.estimate_from_sdk_version("12.0") == "~2021 (SDK 12.0)"
    assert macho_domain.estimate_from_sdk_version("no version") is None

    assert macho_domain.platform_from_version_min("LC_VERSION_MIN_MACOSX") == "macOS"
    assert macho_domain.platform_from_version_min("LC_VERSION_MIN_IPHONEOS") == "iOS"
    assert macho_domain.platform_from_version_min("LC_VERSION_MIN_TVOS") == "tvOS"
    assert macho_domain.platform_from_version_min("LC_VERSION_MIN_WATCHOS") == "watchOS"
    assert macho_domain.platform_from_version_min("LC_OTHER") is None

    date_str, raw = macho_domain.dylib_timestamp_to_string(0)
    assert date_str is None and raw is None
    date_str, raw = macho_domain.dylib_timestamp_to_string(1)
    assert raw == 1

    headers = [{"type": "LC_MAIN", "size": 40, "offset": 12}]
    assert macho_domain.build_load_commands(headers)[0]["type"] == "LC_MAIN"
    assert macho_domain.build_sections([{"name": "__text"}])[0]["name"] == "__text"


@pytest.mark.unit
def test_rich_header_domain_helpers() -> None:
    clear_data = b"\x10\x00\x00\x00\x02\x00\x00\x00"
    entries = rich_header_domain.parse_clear_data_entries(clear_data)
    assert entries[0]["product_id"] == 0x10
    assert entries[0]["count"] == 2

    assert (
        rich_header_domain.get_compiler_description("Utc1900_C", 123)
        == "Microsoft C/C++ Compiler (Build 123)"
    )
    parsed = rich_header_domain.parse_compiler_entries(entries)
    assert parsed[0]["description"].endswith("(Build 0)")

    decoded = rich_header_domain.decode_rich_header(b"\x00" * 16, 0)
    assert isinstance(decoded, list)
    assert rich_header_domain.decode_rich_header(b"", 0) == []
    assert rich_header_domain.validate_decoded_entries([]) is False

    result = rich_header_domain.build_rich_header_result([{"prodid": 1, "count": 2}], 0x1234)
    assert result["checksum"] == 3
    rich_hash = rich_header_domain.calculate_richpe_hash({"entries": [{"prodid": 1, "count": 2}]})
    assert isinstance(rich_hash, str)


@pytest.mark.unit
def test_pe_resources_helpers() -> None:
    adapter = DummyAdapter({"iRj": [{"name": "VERSION", "vaddr": 1, "size": 2}]})
    logger = logging.getLogger("test")
    resources = pe_resources.get_resource_info(adapter, logger)
    assert resources

    adapter_versions = DummyAdapter({"iR~version": "FileVersion=1.2.3.4"})
    version_info = pe_resources.get_version_info(adapter_versions, logger)
    assert version_info.get("FileVersion") == "1.2.3.4"

    failing_adapter = DummyAdapter({}, raises=True)
    assert pe_resources.get_resource_info(failing_adapter, logger) == []
    assert pe_resources.get_version_info(failing_adapter, logger) == {}
