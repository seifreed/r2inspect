from __future__ import annotations

import struct
from pathlib import Path
from typing import Literal, Self

import pytest

from r2inspect.backends.consensus import ConsensusInspector, compare_results
from r2inspect.backends.core_backend import CoreBackendInspector
from r2inspect.backends.binary_view import BinaryView
from r2inspect.backends.elf_core import (
    _build_id,
    _dynamic_paths,
    _name_sections,
    _program_headers,
    _section_headers,
    _symbols as elf_symbols,
    parse_elf,
)
from r2inspect.backends.pe_core import (
    _exports as pe_exports,
    _imports as pe_imports,
    _rva_offset,
    _sections as pe_sections,
)
from r2inspect.backends.macho_core import (
    _file_to_vm,
    _parse_thin,
    _segment,
    _symbols as macho_symbols,
    parse_macho,
)
from r2inspect.backends.registry import available_backends
from r2inspect.interfaces import BinaryInspector


def test_core_backend_provides_independent_format_metadata(tmp_path: Path) -> None:
    sample = tmp_path / "sample.elf"
    sample.write_bytes(b"\x7fELF" + b"\0" * 8)
    result = CoreBackendInspector(str(sample), "elf-core").analyze()
    assert result["backend"] == "elf-core"
    assert result["format_detection"]["file_format"] == "ELF"
    assert result["file_info"]["sha256"]
    assert result["status"] == "failed"
    assert isinstance(CoreBackendInspector(str(sample), "elf-core"), BinaryInspector)


def test_elf_core_parses_real_structure() -> None:
    sample = Path("samples/fixtures/hello_elf")
    if not sample.exists():
        pytest.skip("hello_elf fixture missing")

    result = CoreBackendInspector(str(sample), "elf-core").analyze()

    assert "error" not in result
    assert result["file_info"]["architecture"] == "x86_64"
    assert result["file_info"]["bits"] == 64
    assert result["elf_info"]["entry_point"] == 0x125C
    assert len(result["sections"]) == 13
    assert len(result["elf_info"]["program_headers"]) == 8
    assert result["security"]["nx"] is True
    assert result["security"]["pie"] is True
    assert result["security"]["relro"] is True
    assert result["elf_info"]["overlay"]["size"] == 0


def test_pe_core_parses_real_structure() -> None:
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("hello_pe.exe fixture missing")

    result = CoreBackendInspector(str(sample), "pe-core").analyze()

    assert "error" not in result
    assert result["file_info"]["architecture"] == "x86_64"
    assert result["pe_info"]["entry_point"] == 0x140001400
    assert len(result["sections"]) == 18
    assert any(item.get("name") == "Sleep" for item in result["imports"])
    assert result["security"]["aslr"] is True
    assert result["security"]["dep"] is True
    assert result["pe_info"]["overlay"]["size"] > 0
    assert result["pe_info"]["signature_status"] == "absent"


def test_pe_core_reports_truncated_structure(tmp_path: Path) -> None:
    sample = tmp_path / "truncated.exe"
    sample.write_bytes(b"MZ" + b"\0" * 62)

    result = CoreBackendInspector(str(sample), "pe-core").analyze()

    assert result["status"] == "failed"
    assert result["error"].startswith("invalid PE structure:")


def test_macho_core_parses_real_structure() -> None:
    sample = Path("samples/fixtures/hello_macho")
    if not sample.exists():
        pytest.skip("hello_macho fixture missing")

    result = CoreBackendInspector(str(sample), "macho-core").analyze()

    assert "error" not in result
    assert result["file_info"]["architecture"] == "arm64"
    assert result["file_info"]["bits"] == 64
    assert result["macho_info"]["entry_point"] == 0x100000460
    assert len(result["sections"]) == 5
    assert len(result["macho_info"]["segments"]) == 4
    assert "/usr/lib/libSystem.B.dylib" in result["macho_info"]["libraries"]
    assert any(item["name"] == "_puts" for item in result["imports"])
    assert any(item["name"] == "_main" for item in result["exports"])
    assert result["macho_info"]["uuid"] == "aa700f20-32f3-40f8-bc47-e22ab436ab16"
    assert result["security"]["pie"] is True
    assert result["security"]["nx"] is True
    assert result["macho_info"]["signature_status"] == "present"
    assert result["macho_info"]["overlay"]["size"] == 0


def test_macho_core_parses_fat_slice(tmp_path: Path) -> None:
    thin = Path("samples/fixtures/hello_macho")
    if not thin.exists():
        pytest.skip("hello_macho fixture missing")
    slice_offset = 4096
    thin_data = thin.read_bytes()
    header = struct.pack(">IIiiIII", 0xCAFEBABE, 1, 0x0100000C, 0, slice_offset, len(thin_data), 12)
    sample = tmp_path / "universal.macho"
    sample.write_bytes(header + bytes(slice_offset - len(header)) + thin_data)

    result = CoreBackendInspector(str(sample), "macho-core").analyze()

    assert "error" not in result
    assert result["macho_info"]["universal"] is True
    assert result["macho_info"]["architectures"] == ["arm64"]
    assert result["file_info"]["architecture"] == "arm64"


def test_consensus_marks_backend_disagreements() -> None:
    class FakeBackend:
        def __init__(self, value: str) -> None:
            self.value = value

        def analyze(self, **_options: object) -> dict[str, object]:
            return {"format_detection": {"file_format": self.value}}

        def close(self) -> None:
            pass

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_args: object) -> Literal[False]:
            return False

    disagreement = compare_results(
        {"format_detection": {"file_format": "PE"}},
        {"format_detection": {"file_format": "ELF"}},
        "r2",
        "elf-core",
    )[0]
    assert disagreement == {
        "field": "format.common.format",
        "left_backend": "r2",
        "right_backend": "elf-core",
        "left": "PE",
        "right": "ELF",
        "severity": "warning",
        "status": "backend_disagreement",
    }
    result = ConsensusInspector(FakeBackend("PE"), FakeBackend("ELF"), "a", "b").analyze()
    assert result["backend"] == "consensus"
    assert result["backend_disagreements"]


def test_consensus_compares_structure_and_security() -> None:
    left = {
        "format_detection": {"file_format": "PE"},
        "pe_info": {
            "entry_point": 4096,
            "sections": [{"name": ".text", "vaddr": 4096, "size": 512}],
            "security_features": {"aslr": True},
        },
        "imports": [{"library": "kernel32.dll", "name": "Sleep"}],
    }
    right = {
        "format_detection": {"file_format": "PE"},
        "pe_info": {
            "entry_point": 8192,
            "sections": [{"name": ".text", "vaddr": 4096, "size": 1024}],
            "security_features": {"aslr": False},
        },
        "imports": [{"library": "kernel32.dll", "name": "Sleep"}],
    }

    fields = {item["field"] for item in compare_results(left, right)}

    assert fields == {
        "format.pe.entry_point",
        "format.pe.section_boundaries",
        "security.aslr",
    }


def test_consensus_normalizes_backend_specific_shapes() -> None:
    left = {
        "format_detection": {"file_format": "PE"},
        "file_info": {"architecture": "x86-64"},
        "sections": [{"name": ".text", "virtual_address": 4096, "virtual_size": 512}],
        "pe_info": {
            "overlay": {"overlay_offset": 8192, "overlay_size": 16, "has_overlay": True},
            "authenticode": {"has_signature": False},
            "security_features": {"aslr": True},
        },
    }
    right = {
        "format_detection": {"file_format": "PE"},
        "file_info": {"architecture": "x86_64"},
        "sections": [{"name": ".text", "vaddr": 4096, "size": 512}],
        "pe_info": {
            "overlay": {"offset": 8192, "size": 16},
            "signature_status": "absent",
            "security_features": {"aslr": True},
        },
    }

    assert compare_results(left, right) == []


def test_builtin_backends_are_discoverable() -> None:
    assert {"r2", "pe-core", "elf-core", "macho-core", "consensus"}.issubset(available_backends())


def test_pe_core_parses_symbol_tables_and_rejects_invalid_layouts() -> None:
    assert _rva_offset(1, [], 2) == 1
    with pytest.raises(ValueError, match="not mapped"):
        _rva_offset(3, [], 2)
    with pytest.raises(ValueError, match="unreasonable PE section count"):
        pe_sections(BinaryView(bytes(40)), 0, 97)

    invalid_section = bytearray(40)
    struct.pack_into("<IIII", invalid_section, 8, 1, 0x1000, 2, 40)
    with pytest.raises(ValueError, match="extends outside"):
        pe_sections(BinaryView(invalid_section), 0, 1)
    assert pe_imports(BinaryView(bytes(1)), (0, 0), [], 1, 64) == []

    imports = bytearray(256)
    struct.pack_into("<IIIII", imports, 0x20, 0x60, 0, 0, 0x50, 0)
    imports[0x50:0x59] = b"demo.dll\0"
    struct.pack_into("<II", imports, 0x60, 0x80000005, 0)
    assert pe_imports(BinaryView(imports), (0x20, 40), [], 256, 32) == [
        {"library": "demo.dll", "ordinal": 5}
    ]

    exports = bytearray(256)
    struct.pack_into("<IIHHIIIIIII", exports, 0x20, 0, 0, 0, 0, 0, 1, 1, 2, 0x60, 0x70, 0x80)
    struct.pack_into("<I", exports, 0x60, 0x1234)
    struct.pack_into("<II", exports, 0x70, 0x90, 0x98)
    struct.pack_into("<HH", exports, 0x80, 0, 1)
    exports[0x90:0x95] = b"demo\0"
    exports[0x98:0x9D] = b"skip\0"
    assert pe_exports(BinaryView(exports), (0x20, 40), [], 256) == [
        {"name": "demo", "ordinal": 1, "vaddr": 0x1234}
    ]


def test_elf_core_parses_32_bit_tables_and_rejects_invalid_layouts() -> None:
    view = BinaryView(bytes(256))
    with pytest.raises(ValueError, match="unreasonable ELF section count"):
        _section_headers(view, "<", 32, 0, 40, 65537)
    with pytest.raises(ValueError, match="section-header size"):
        _section_headers(view, "<", 32, 0, 39, 1)
    invalid_section = bytearray(40)
    struct.pack_into("<IIIIIIIIII", invalid_section, 0, 0, 1, 0, 0, 39, 2, 0, 0, 0, 0)
    with pytest.raises(ValueError, match="extends outside"):
        _section_headers(BinaryView(invalid_section), "<", 32, 0, 40, 1)
    with pytest.raises(ValueError, match="section-name table index"):
        _name_sections(view, [], 0)
    with pytest.raises(ValueError, match="program-header count"):
        _program_headers(view, "<", 32, 0, 32, 65537)
    with pytest.raises(ValueError, match="program-header size"):
        _program_headers(view, "<", 32, 0, 31, 1)

    header = bytearray(32)
    struct.pack_into("<IIIIIIII", header, 0, 1, 31, 2, 3, 4, 5, 6, 7)
    with pytest.raises(ValueError, match="segment 0 extends outside"):
        _program_headers(BinaryView(header), "<", 32, 0, 32, 1)

    data = bytearray(256)
    strings = b"\0import\0export\0"
    data[0x80 : 0x80 + len(strings)] = strings
    struct.pack_into("<IIIBBH", data, 0x20, 1, 0, 0, 0x10, 0, 0)
    struct.pack_into("<IIIBBH", data, 0x30, 8, 0x1000, 1, 0x10, 0, 1)
    sections = [
        {"type": 11, "link": 1, "entry_size": 16, "size": 32, "paddr": 0x20},
        {"type": 3, "size": len(strings), "paddr": 0x80},
    ]
    assert elf_symbols(BinaryView(data), sections, "<", 32) == (
        [{"name": "import", "vaddr": 0, "size": 0}],
        [{"name": "export", "vaddr": 0x1000, "size": 1}],
    )
    with pytest.raises(ValueError, match="string-table index"):
        elf_symbols(view, [{"type": 11, "link": 1}], "<", 64)
    with pytest.raises(ValueError, match="symbol-entry size"):
        elf_symbols(
            view,
            [{"type": 11, "link": 1, "entry_size": 1}, {"type": 3}],
            "<",
            64,
        )

    dynamic = bytearray(128)
    paths = b"\0rpath\0runpath\0"
    dynamic[0x60 : 0x60 + len(paths)] = paths
    struct.pack_into("<iI", dynamic, 0x20, 15, 1)
    struct.pack_into("<iI", dynamic, 0x28, 29, 7)
    struct.pack_into("<iI", dynamic, 0x30, 0, 0)
    dynamic_sections = [
        {"type": 6, "link": 1, "entry_size": 8, "size": 24, "paddr": 0x20},
        {"type": 3, "size": len(paths), "paddr": 0x60},
    ]
    assert _dynamic_paths(BinaryView(dynamic), dynamic_sections, "<", 32) == (
        ["rpath"],
        ["runpath"],
    )
    assert _dynamic_paths(view, [{"type": 6, "link": 2}], "<", 64) == ([], [])
    with pytest.raises(ValueError, match="dynamic-entry size"):
        _dynamic_paths(
            view,
            [{"type": 6, "link": 1, "entry_size": 1}, {"type": 3}],
            "<",
            64,
        )

    note = bytearray(32)
    struct.pack_into("<III", note, 0, 4, 4, 3)
    note[12:16] = b"GNU\0"
    note[16:20] = b"id42"
    note_section = [{"name": ".note.gnu.build-id", "paddr": 0, "size": 20}]
    assert _build_id(BinaryView(note), note_section, "<") == b"id42".hex()
    struct.pack_into("<III", note, 0, 4, 100, 3)
    with pytest.raises(ValueError, match="truncated ELF note"):
        _build_id(BinaryView(note), note_section, "<")

    with pytest.raises(ValueError, match="invalid ELF identification"):
        parse_elf(BinaryView(bytes(64)))
    elf = bytearray(64)
    elf[:16] = b"\x7fELF\x02\x01" + bytes(10)
    struct.pack_into("<HHIQQQIHHHHHH", elf, 16, 2, 0x3E, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    with pytest.raises(ValueError, match="truncated ELF header"):
        parse_elf(BinaryView(elf))


def test_macho_core_rejects_invalid_tables_and_commands() -> None:
    view = BinaryView(bytes(256))
    with pytest.raises(ValueError, match="truncated Mach-O segment"):
        _segment(view, "<", 64, 0, 71)

    segment = bytearray(152)
    struct.pack_into("<II16sQQQQiiII", segment, 0, 0x19, 72, b"seg", 0, 0, 0, 0, 0, 0, 1, 0)
    with pytest.raises(ValueError, match="section count"):
        _segment(BinaryView(segment), "<", 64, 0, 72)
    struct.pack_into("<II16sQQQQiiII", segment, 0, 0x19, 72, b"seg", 0, 0, 150, 4, 0, 0, 0, 0)
    with pytest.raises(ValueError, match="segment .* outside"):
        _segment(BinaryView(segment), "<", 64, 0, 72)
    struct.pack_into("<II16sQQQQiiII", segment, 0, 0x19, 152, b"seg", 0, 0, 0, 0, 0, 0, 1, 0)
    struct.pack_into(
        "<16s16sQQIIIIIIII",
        segment,
        72,
        b"section",
        b"seg",
        0,
        4,
        150,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    with pytest.raises(ValueError, match="section .* outside"):
        _segment(BinaryView(segment), "<", 64, 0, 152)

    with pytest.raises(ValueError, match="invalid Mach-O symbol table"):
        macho_symbols(view, "<", 64, (0, 1_000_001, 0, 0))
    with pytest.raises(ValueError, match="string table extends"):
        macho_symbols(view, "<", 64, (0, 0, 255, 2))
    symbols = bytearray(128)
    symbols[64:72] = b"\0skip\0x\0"
    struct.pack_into("<IBBHQ", symbols, 0, 0, 1, 0, 0, 0)
    struct.pack_into("<IBBHQ", symbols, 16, 1, 0, 0, 0, 0)
    assert macho_symbols(BinaryView(symbols), "<", 64, (0, 2, 64, 8)) == ([], [])
    assert _file_to_vm(7, []) == 7

    with pytest.raises(ValueError, match="unsupported Mach-O magic"):
        _parse_thin(view)

    def thin(command: int, command_size: int, *values: int) -> BinaryView:
        data = bytearray(max(64, 32 + command_size))
        data[:4] = b"\xcf\xfa\xed\xfe"
        struct.pack_into("<iiIIIII", data, 4, 0x0100000C, 0, 2, 1, command_size, 0, 0)
        struct.pack_into("<II", data, 32, command, command_size)
        if values:
            struct.pack_into("<" + "I" * len(values), data, 40, *values)
        return BinaryView(data)

    cases = (
        (0, 4, (), "load command size"),
        (1, 8, (), "does not match header class"),
        (2, 8, (), "symbol-table command"),
        (0xC, 8, (), "dylib command"),
        (0xC, 16, (4,), "dylib name offset"),
        (0x1B, 8, (), "UUID command"),
        (0x32, 8, (), "build-version command"),
        (0x28, 8, (), "entry-point command"),
        (0x1D, 8, (), "code-signature command"),
        (0x1D, 16, (100, 10), "code signature extends"),
    )
    for command, size, values, message in cases:
        with pytest.raises(ValueError, match=message):
            _parse_thin(thin(command, size, *values))

    fat = bytearray(8)
    fat[:4] = b"\xca\xfe\xba\xbe"
    with pytest.raises(ValueError, match="fat architecture count"):
        parse_macho(BinaryView(fat))

    empty_thin = bytearray(32)
    empty_thin[:4] = b"\xcf\xfa\xed\xfe"
    struct.pack_into("<iiIIIII", empty_thin, 4, 0x0100000C, 0, 2, 0, 0, 0, 0)
    fat64 = bytearray(64) + empty_thin
    fat64[:4] = b"\xca\xfe\xba\xbf"
    struct.pack_into(">IiiQQII", fat64, 4, 1, 0x0100000C, 0, 64, 32, 0, 0)
    assert parse_macho(BinaryView(fat64))["architectures"] == ["arm64"]
