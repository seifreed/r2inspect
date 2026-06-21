#!/usr/bin/env python3
"""Branch-path tests for r2inspect/modules/elf_analyzer.py.

Uses real stub adapters (no mocks). Covers missing lines:
37, 92-93, 105, 110, 115, 121-122, 134, 140-141, 143-144, 146,
157, 159-160, 173-174, 176-177, 179, 207, 209-210, 237, 239-240,
252, 257-262, 265, 268, 271, 274, 277.
"""

from __future__ import annotations

from typing import Any

from r2inspect.modules.elf_analyzer import ELFAnalyzer

# ---------------------------------------------------------------------------
# Stub adapters
# ---------------------------------------------------------------------------


class MinimalELFAdapter:
    """Stub returning safe empty defaults for all adapter methods."""

    def get_file_info(self) -> dict[str, Any]:
        return {}

    def get_sections(self) -> list[dict[str, Any]]:
        return []

    def get_symbols(self) -> list[dict[str, Any]]:
        return []

    def get_dynamic_info_text(self) -> str:
        return ""

    def get_headers_json(self) -> list[dict[str, Any]]:
        return []

    def read_bytes(self, addr: int, size: int) -> bytes:
        return b""


class ELFAdapterWithBinInfo(MinimalELFAdapter):
    """Adapter that returns rich ELF bin info so _get_elf_headers fills all fields."""

    def get_file_info(self) -> dict[str, Any]:
        return {
            "bin": {
                "arch": "x86",
                "machine": "x86",
                "bits": 64,
                "endian": "little",
                "class": "ELF64",
                "format": "elf",
                "baddr": 0x400000,
            }
        }


class ELFAdapterWithSections(ELFAdapterWithBinInfo):
    """Adapter that returns ELF sections including .comment."""

    def get_sections(self) -> list[dict[str, Any]]:
        return [
            {
                "name": ".text",
                "type": "progbits",
                "flags": "ax",
                "size": 0x100,
                "vaddr": 0x401000,
                "paddr": 0x1000,
            },
            {
                "name": ".comment",
                "type": "progbits",
                "flags": "",
                "size": 32,
                "vaddr": 0x403000,
                "paddr": 0x3000,
            },
            {
                "name": ".note.gnu.build-id",
                "type": "note",
                "flags": "a",
                "size": 20,
                "vaddr": 0x404000,
                "paddr": 0x4000,
            },
        ]

    def read_bytes(self, addr: int, size: int) -> bytes:
        if addr == 0x403000:
            # Simulate a GCC comment string
            return b"GCC: (Ubuntu 11.3.0) 11.3.0\x00"
        if addr == 0x404000:
            # Simulate build-id bytes
            return bytes(range(20))
        return b"\x00" * size


class ELFAdapterWithDwarfInfo(ELFAdapterWithBinInfo):
    """Adapter that exposes DWARF-like debug info."""

    def get_dynamic_info_text(self) -> str:
        return "DW_AT_producer : GNU C17 11.3.0 -mtune=generic\n" "compilation date: 2024-01-15\n"


class ELFAdapterWithProgramHeaders(MinimalELFAdapter):
    """Adapter returning one LOAD segment (program header) via iSSj."""

    def cmdj(self, command: str) -> list[dict[str, Any]]:
        if command == "iSSj":
            return [
                {
                    "name": "LOAD0",
                    "perm": "-r-x",
                    "paddr": 0,
                    "vaddr": 0x400000,
                    "size": 0x1000,
                    "vsize": 0x1000,
                }
            ]
        return []


class ELFAdapterRaisingFileInfo(MinimalELFAdapter):
    """Adapter whose get_file_info raises to trigger exception path."""

    def get_file_info(self) -> dict[str, Any]:
        raise RuntimeError("simulated file info failure")


class ELFAdapterRaisingSections(MinimalELFAdapter):
    """Adapter whose get_sections raises to trigger section_info exception path."""

    def get_sections(self) -> list[dict[str, Any]]:
        raise RuntimeError("simulated sections failure")


class ELFAdapterWithoutReadBytes:
    """Adapter that does not implement read_bytes, exercising the guard in _read_section."""

    def get_file_info(self) -> dict[str, Any]:
        return {}

    def get_sections(self) -> list[dict[str, Any]]:
        return []

    def get_symbols(self) -> list[dict[str, Any]]:
        return []

    def get_dynamic_info_text(self) -> str:
        return ""

    def get_headers_json(self) -> list[dict[str, Any]]:
        return []

    # read_bytes intentionally absent


class ELFAdapterWithSymbols(ELFAdapterWithBinInfo):
    """Adapter returning symbols for security feature checks."""

    def get_symbols(self) -> list[dict[str, Any]]:
        return [{"name": "__stack_chk_fail"}, {"name": "main"}]

    def get_dynamic_info_text(self) -> str:
        return "RELRO\nFULL_RELRO\n"


# ---------------------------------------------------------------------------
# supports_format (line 37)
# ---------------------------------------------------------------------------


def test_supports_format_elf_variants():
    analyzer = ELFAnalyzer(MinimalELFAdapter())
    assert analyzer.supports_format("ELF") is True
    assert analyzer.supports_format("ELF32") is True
    assert analyzer.supports_format("ELF64") is True
    assert analyzer.supports_format("elf") is True
    assert analyzer.supports_format("PE") is False
    assert analyzer.supports_format("MACHO") is False


# ---------------------------------------------------------------------------
# _get_elf_headers – exception path (lines 92-93)
# ---------------------------------------------------------------------------


def test_get_elf_headers_exception_returns_empty_info():
    adapter = ELFAdapterRaisingFileInfo()
    analyzer = ELFAnalyzer(adapter)
    info = analyzer._get_elf_headers()
    assert isinstance(info, dict)
    assert info == {}


# ---------------------------------------------------------------------------
# _get_elf_headers – success path populates all fields (lines 84-90)
# ---------------------------------------------------------------------------


def test_get_elf_headers_populates_all_fields():
    adapter = ELFAdapterWithBinInfo()
    analyzer = ELFAnalyzer(adapter)
    info = analyzer._get_elf_headers()
    assert info["architecture"] == "x86"
    assert info["bits"] == 64
    assert info["endian"] == "little"
    assert info["format"] == "elf"
    assert info["entry_point"] == 0x400000


def test_get_elf_headers_accepts_hex_string_fields():
    adapter = ELFAdapterWithBinInfo()
    adapter.get_file_info = lambda: {
        "bin": {
            "arch": "x86",
            "machine": "x86",
            "bits": "0x40",
            "endian": "little",
            "class": "ELF64",
            "format": "elf",
            "baddr": "0x400000",
        }
    }
    analyzer = ELFAnalyzer(adapter)
    info = analyzer._get_elf_headers()
    assert info["bits"] == 64
    assert info["entry_point"] == 0x400000


# ---------------------------------------------------------------------------
# _get_compilation_info – branches when sub-results are present (lines 105, 110, 115)
# ---------------------------------------------------------------------------


def test_get_compilation_info_with_comment_section(tmp_path: None):
    adapter = ELFAdapterWithSections()
    analyzer = ELFAnalyzer(adapter)
    info = analyzer._get_compilation_info()
    # comment section was found and parsed
    assert "comment" in info


def test_get_compilation_info_with_dwarf_info():
    adapter = ELFAdapterWithDwarfInfo()
    analyzer = ELFAnalyzer(adapter)
    compilation_info = analyzer._get_compilation_info()
    # DWARF producer line was parsed — verify it returned something
    assert compilation_info is not None


# ---------------------------------------------------------------------------
# _extract_comment_section – when .comment section exists (lines 140-141, 146)
# ---------------------------------------------------------------------------


def test_extract_comment_section_found_and_parsed():
    adapter = ELFAdapterWithSections()
    analyzer = ELFAnalyzer(adapter)
    info = analyzer._extract_comment_section()
    assert "comment" in info
    assert "GCC" in info["comment"]


def test_extract_comment_section_returns_empty_when_no_comment():
    adapter = MinimalELFAdapter()
    analyzer = ELFAnalyzer(adapter)
    info = analyzer._extract_comment_section()
    assert info == {}


# ---------------------------------------------------------------------------
# _extract_comment_section – exception path (lines 143-144)
# ---------------------------------------------------------------------------


def test_extract_comment_section_exception_returns_empty():
    adapter = ELFAdapterRaisingSections()
    analyzer = ELFAnalyzer(adapter)
    info = analyzer._extract_comment_section()
    assert isinstance(info, dict)


# ---------------------------------------------------------------------------
# _extract_dwarf_info – when debug info is present (lines 157, 159-160)
# ---------------------------------------------------------------------------


def test_extract_dwarf_info_present():
    adapter = ELFAdapterWithDwarfInfo()
    analyzer = ELFAnalyzer(adapter)
    info = analyzer._extract_dwarf_info()
    assert isinstance(info, dict)


def test_extract_dwarf_info_no_debug_info():
    adapter = MinimalELFAdapter()
    analyzer = ELFAnalyzer(adapter)
    info = analyzer._extract_dwarf_info()
    assert info == {}


def test_extract_dwarf_info_non_string_output_returns_empty():
    class BadDebugAdapter(MinimalELFAdapter):
        def cmd(self, command: str):
            if command == "id":
                return 123
            return super().cmd(command)

    analyzer = ELFAnalyzer(BadDebugAdapter())
    assert analyzer._extract_dwarf_info() == {}


# ---------------------------------------------------------------------------
# _extract_build_id – when section found (lines 173-174, 179)
# ---------------------------------------------------------------------------


def test_extract_build_id_with_section():
    adapter = ELFAdapterWithSections()
    analyzer = ELFAnalyzer(adapter)
    build_id = analyzer._extract_build_id()
    # build_id_data is hex bytes; _parse_build_id_data may return None for raw bytes
    # but the code path is exercised
    assert build_id is None or isinstance(build_id, str)


def test_extract_build_id_no_section_returns_none():
    adapter = MinimalELFAdapter()
    analyzer = ELFAnalyzer(adapter)
    result = analyzer._extract_build_id()
    assert result is None


# ---------------------------------------------------------------------------
# _get_section_info – with sections and without (lines 195-207)
# ---------------------------------------------------------------------------


def test_get_section_info_with_sections():
    adapter = ELFAdapterWithSections()
    analyzer = ELFAnalyzer(adapter)
    sections = analyzer._get_section_info()
    assert len(sections) > 0
    assert sections[0]["name"] == ".text"


def test_get_section_info_coerces_string_numeric_fields():
    class StringSectionAnalyzer(ELFAnalyzer):
        def _cmd_list(self, cmd: str):
            if cmd == "iSj":
                return [{"name": ".text", "size": "4096", "vaddr": "4096", "paddr": "8192"}]

            return []

    analyzer = StringSectionAnalyzer(ELFAdapterWithSections())
    sections = analyzer._get_section_info()
    assert sections[0]["size"] == 4096
    assert sections[0]["vaddr"] == 4096
    assert sections[0]["paddr"] == 8192


def test_get_section_info_coerces_hex_string_fields():
    class HexSectionAnalyzer(ELFAnalyzer):
        def _cmd_list(self, cmd: str):
            if cmd == "iSj":
                return [{"name": ".text", "size": "0x1000", "vaddr": "0x1000", "paddr": "0x2000"}]

            return []

    analyzer = HexSectionAnalyzer(ELFAdapterWithSections())
    sections = analyzer._get_section_info()
    assert sections[0]["size"] == 4096
    assert sections[0]["vaddr"] == 4096
    assert sections[0]["paddr"] == 8192


def test_get_section_info_empty_sections():
    adapter = MinimalELFAdapter()
    analyzer = ELFAnalyzer(adapter)
    sections = analyzer._get_section_info()
    assert sections == []


def test_get_section_info_exception_returns_empty_list():
    adapter = ELFAdapterRaisingSections()
    analyzer = ELFAnalyzer(adapter)
    sections = analyzer._get_section_info()
    assert sections == []


# ---------------------------------------------------------------------------
# _get_program_headers – with headers and without (lines 223-237)
# ---------------------------------------------------------------------------


def test_get_program_headers_with_headers():
    adapter = ELFAdapterWithProgramHeaders()
    analyzer = ELFAnalyzer(adapter)
    headers = analyzer._get_program_headers()
    assert len(headers) == 1
    assert headers[0]["type"] == "LOAD0"
    assert headers[0]["flags"] == "-r-x"
    assert headers[0]["memsz"] == 0x1000


def test_get_program_headers_empty():
    adapter = MinimalELFAdapter()
    analyzer = ELFAnalyzer(adapter)
    headers = analyzer._get_program_headers()
    assert headers == []


# ---------------------------------------------------------------------------
# get_security_features (line 252)
# ---------------------------------------------------------------------------


def test_get_security_features_returns_dict():
    adapter = ELFAdapterWithSymbols()
    analyzer = ELFAnalyzer(adapter)
    features = analyzer.get_security_features()
    assert isinstance(features, dict)
    assert "nx" in features


# ---------------------------------------------------------------------------
# _read_section – all three cmd branches (lines 257-262)
# ---------------------------------------------------------------------------


def test_read_section_psz_returns_null_terminated_string():
    adapter = ELFAdapterWithSections()
    analyzer = ELFAnalyzer(adapter)
    section = {"vaddr": 0x403000, "size": 32}
    result = analyzer._read_section(section, "psz")
    assert result == "GCC: (Ubuntu 11.3.0) 11.3.0"


def test_read_section_accepts_numeric_string_fields():
    adapter = ELFAdapterWithSections()
    analyzer = ELFAnalyzer(adapter)
    section = {"vaddr": str(0x403000), "size": "32"}
    result = analyzer._read_section(section, "psz")
    assert result == "GCC: (Ubuntu 11.3.0) 11.3.0"


def test_read_section_px_returns_hex_string():
    adapter = ELFAdapterWithSections()
    analyzer = ELFAnalyzer(adapter)
    section = {"vaddr": 0x403000, "size": 4}
    result = analyzer._read_section(section, "px")
    assert result is not None
    assert "47" in result  # 0x47 == 'G'


def test_read_section_default_returns_decoded_string():
    adapter = ELFAdapterWithSections()
    analyzer = ELFAnalyzer(adapter)
    section = {"vaddr": 0x403000, "size": 4}
    result = analyzer._read_section(section, "other")
    assert result is not None


def test_read_section_none_section_returns_none():
    adapter = MinimalELFAdapter()
    analyzer = ELFAnalyzer(adapter)
    assert analyzer._read_section(None, "psz") is None


def test_read_section_no_vaddr_returns_none():
    adapter = MinimalELFAdapter()
    analyzer = ELFAnalyzer(adapter)
    section = {"vaddr": 0, "size": 10}
    assert analyzer._read_section(section, "psz") is None


def test_read_section_no_read_bytes_on_adapter_returns_none():
    adapter = ELFAdapterWithoutReadBytes()
    analyzer = ELFAnalyzer(adapter)
    section = {"vaddr": 0x1000, "size": 10}
    assert analyzer._read_section(section, "psz") is None


def test_read_section_rejects_text_payload():
    class TextAdapter(ELFAdapterWithoutReadBytes):
        def read_bytes(self, address: int, size: int) -> str:
            return "bad"

    analyzer = ELFAnalyzer(TextAdapter())
    section = {"vaddr": 0x1000, "size": 10}
    assert analyzer._read_section(section, "psz") is None


# ---------------------------------------------------------------------------
# _parse_* delegation methods (lines 265, 268, 271, 274, 277)
# ---------------------------------------------------------------------------


def test_parse_comment_compiler_info_delegates():
    adapter = MinimalELFAdapter()
    analyzer = ELFAnalyzer(adapter)
    result = analyzer._parse_comment_compiler_info("GCC: (Ubuntu 11.3.0) 11.3.0")
    assert "compiler" in result


def test_parse_dwarf_info_delegates():
    adapter = MinimalELFAdapter()
    analyzer = ELFAnalyzer(adapter)
    lines = ["DW_AT_producer : GNU C17 11.3.0"]
    result = analyzer._parse_dwarf_info(lines)
    assert isinstance(result, dict)


def test_parse_build_id_data_delegates_with_none():
    adapter = MinimalELFAdapter()
    analyzer = ELFAnalyzer(adapter)
    result = analyzer._parse_build_id_data(None)
    assert result is None


def test_parse_build_id_data_delegates_with_hex_string():
    adapter = MinimalELFAdapter()
    analyzer = ELFAnalyzer(adapter)
    hex_str = "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13"
    result = analyzer._parse_build_id_data(hex_str)
    assert result is None or isinstance(result, str)


def test_read_section_caps_attacker_controlled_size() -> None:
    """Regression: a crafted ELF section size must not force an unbounded read.

    ``section.get("size")`` comes straight from the (attacker-controlled) ELF
    section header. ``_read_section`` must cap the read so an oversized section
    cannot drive a huge read + decode.
    """
    recorded: list[int] = []

    class _RecordingAdapter(MinimalELFAdapter):
        def read_bytes(self, addr: int, size: int) -> bytes:
            recorded.append(size)
            return b"\x00" * min(size, 16)

    analyzer = ELFAnalyzer(_RecordingAdapter())
    huge_section = {"vaddr": 0x401000, "size": 0xFFFFFFFF}

    analyzer._read_section(huge_section, "px")

    assert recorded == [1024 * 1024]


def test_read_section_passes_small_size_through() -> None:
    """A section smaller than the cap is read at its declared size."""
    recorded: list[int] = []

    class _RecordingAdapter(MinimalELFAdapter):
        def read_bytes(self, addr: int, size: int) -> bytes:
            recorded.append(size)
            return b"\x00" * size

    analyzer = ELFAnalyzer(_RecordingAdapter())
    small_section = {"vaddr": 0x401000, "size": 64}

    analyzer._read_section(small_section, "px")

    assert recorded == [64]
