from __future__ import annotations

import base64

from r2inspect.modules import (
    elf_domain,
    macho_domain,
    pe_resources,
    rich_header_domain,
    string_domain,
)


class _DummyLogger:
    def __init__(self) -> None:
        self.errors: list[str] = []

    def error(self, message: str) -> None:
        self.errors.append(message)


class _ResourcesAdapter:
    def __init__(self, resources: list[dict[str, object]]) -> None:
        self._resources = resources

    def get_resources_info(self) -> list[dict[str, object]]:
        return self._resources


class _VersionAdapter:
    def __init__(self, version_text: str) -> None:
        self._version_text = version_text

    def get_pe_version_info_text(self) -> str:
        return self._version_text


def test_elf_domain_parsers() -> None:
    gcc_comment = "GCC: (Ubuntu 13.2.0) 13.2.0"
    clang_comment = "clang version 15.0.7 (some build)"
    assert elf_domain.parse_comment_compiler_info(gcc_comment) == {
        "compiler": "GCC 13.2.0",
        "compiler_version": "13.2.0",
        "build_environment": "Ubuntu 13.2.0",
    }
    assert elf_domain.parse_comment_compiler_info(clang_comment) == {
        "compiler": "Clang 15.0.7",
        "compiler_version": "15.0.7",
    }

    dwarf_lines = [
        "DW_AT_producer : GNU C 12.1.0",
        "DW_AT_comp_dir : /builds/2024-01-20",
        "random line",
    ]
    parsed = elf_domain.parse_dwarf_info(dwarf_lines)
    assert parsed["compiler"] == "GCC 12.1.0"
    assert parsed["compiler_version"] == "12.1.0"
    assert parsed["compile_time"] == "2024-01-20"

    assert elf_domain.parse_dwarf_producer("no producer here") is None
    assert elf_domain.parse_dwarf_compile_time("no comp dir") is None
    assert elf_domain.parse_dwarf_compile_time("compilation time: Mon Jan 01 01:02:03 2024") == (
        "Mon Jan 01 01:02:03 2024"
    )

    build_id = "Build ID: 12 34 56 78 9a bc de f0"
    assert elf_domain.parse_build_id_data(build_id) == "9abcdef0"
    assert elf_domain.parse_build_id_data(None) is None

    sections = [{"name": ".text", "vaddr": 1, "size": 2}, {"name": ".data"}]
    assert elf_domain.find_section_by_name(sections, "TEXT") == sections[0]
    assert elf_domain.find_section_by_name(sections, "rdata") is None
    assert elf_domain.build_section_read_commands(sections[0], "pxj") == ("s 1", "pxj 2")
    assert elf_domain.build_section_read_commands(sections[1], "pxj") is None


def test_macho_domain_parsers() -> None:
    assert macho_domain.estimate_from_sdk_version("14.0.0") == "~2023 (SDK 14.0.0)"
    assert macho_domain.estimate_from_sdk_version("SDK 99.0") is None
    assert macho_domain.platform_from_version_min("LC_VERSION_MIN_MACOSX") == "macOS"
    assert macho_domain.platform_from_version_min("LC_VERSION_MIN_WATCHOS") == "watchOS"
    assert macho_domain.platform_from_version_min("LC_VERSION_MIN_TVOS") == "tvOS"
    assert macho_domain.platform_from_version_min("LC_VERSION_MIN_IPHONEOS") == "iOS"
    assert macho_domain.platform_from_version_min("LC_VERSION_MIN_UNKNOWN") is None

    timestamp_str, ts = macho_domain.dylib_timestamp_to_string(1)
    assert ts == 1
    assert timestamp_str is not None
    assert macho_domain.dylib_timestamp_to_string(0) == (None, None)
    assert macho_domain.dylib_timestamp_to_string(-5) == (None, None)

    headers = [{"type": "LC_ID_DYLIB", "size": 10, "offset": 4, "extra": "x"}]
    sections = [{"name": "__text", "segment": "__TEXT", "type": "code", "flags": "x", "size": 5}]
    assert macho_domain.build_load_commands(headers)[0]["data"] == headers[0]
    built_section = macho_domain.build_sections(sections)[0]
    assert built_section["name"] == "__text"
    assert built_section["segment"] == "__TEXT"


def test_string_domain_helpers() -> None:
    strings = ["ok", "toolong" * 10, "h\x00i"]
    assert string_domain.filter_strings(strings, 2, 10) == ["ok", "hi"]
    assert string_domain.parse_search_results("0x1000 mov eax\n0x2000 ret") == ["0x1000", "0x2000"]
    assert string_domain.xor_string("AB", 1) == "@C"

    def _search_hex(value: str) -> str:
        if value == string_domain.xor_string("test", 1).encode().hex():
            return "0x1234 hit"
        return ""

    matches = string_domain.build_xor_matches("test", _search_hex)
    assert matches[0]["xor_key"] == 1
    assert matches[0]["addresses"] == ["0x1234"]

    suspicious = string_domain.find_suspicious(["http://example.com", "plain"])
    assert suspicious[0]["type"] == "urls"

    sample = base64.b64encode(b"hello").decode()
    assert string_domain.decode_base64(sample)["decoded"] == "hello"
    assert string_domain.decode_base64("notbase64") is None
    assert string_domain.decode_hex("68656c6c6f")["decoded"] == "hello"
    assert string_domain.decode_hex("zz") is None
    assert string_domain.is_base64(sample)
    assert not string_domain.is_base64("abc")
    assert string_domain.is_hex("00ff")
    assert not string_domain.is_hex("0x01")


def test_pe_resources_helpers() -> None:
    logger = _DummyLogger()
    resources_adapter = _ResourcesAdapter([{"name": "RESOURCE", "type": "RT_VERSION"}])
    resources = pe_resources.get_resource_info(resources_adapter, logger)
    assert resources[0]["name"] == "RESOURCE"
    assert logger.errors == []

    version_text = "FileVersion=1.2.3.4\nProductName=Example"
    version_adapter = _VersionAdapter(version_text)
    version_info = pe_resources.get_version_info(version_adapter, logger)
    assert version_info["FileVersion"] == "1.2.3.4"

    class _ErrorAdapter:
        def get_resources_info(self) -> list[dict[str, object]]:
            raise RuntimeError("boom")

    pe_resources.get_resource_info(_ErrorAdapter(), logger)
    assert logger.errors


def test_rich_header_domain_helpers() -> None:
    entry = (0x00B5 << 16) | 0x1234
    clear_data = entry.to_bytes(4, "little") + (3).to_bytes(4, "little")
    entries = rich_header_domain.parse_clear_data_entries(clear_data)
    assert entries[0]["product_id"] == 0x1234
    assert entries[0]["build_number"] == 0x00B5
    assert rich_header_domain.get_compiler_description("Utc1900_C", 123).startswith(
        "Microsoft C/C++ Compiler"
    )
    compiler_entries = rich_header_domain.parse_compiler_entries(entries)
    assert compiler_entries[0]["compiler_name"].startswith("Unknown_0x")

    xor_key = 0xA5A5A5A5
    prodid = 0x1234
    encoded = (
        b"Rich" + (prodid ^ xor_key).to_bytes(4, "little") + (1 ^ xor_key).to_bytes(4, "little")
    )
    decoded = rich_header_domain.decode_rich_header(encoded, xor_key)
    assert decoded[0]["count"] == 1
    assert rich_header_domain.validate_decoded_entries(decoded)
    result = rich_header_domain.build_rich_header_result(decoded, xor_key)
    assert result["xor_key"] == xor_key
    assert rich_header_domain.calculate_richpe_hash({"entries": decoded})
    assert rich_header_domain.calculate_richpe_hash({"clear_data_bytes": clear_data})
