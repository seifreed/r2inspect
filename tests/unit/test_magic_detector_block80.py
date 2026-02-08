from __future__ import annotations

import struct
from pathlib import Path

from r2inspect.utils.magic_detector import (
    MagicByteDetector,
    detect_file_type,
    get_file_threat_level,
    is_executable_file,
)


def _write_bytes(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def test_detect_pe_and_helpers(tmp_path: Path):
    # Minimal PE: MZ + e_lfanew at 0x3C pointing to PE signature
    pe_data = bytearray(128)
    pe_data[0:2] = b"MZ"
    pe_offset = 0x40
    pe_data[0x3C:0x40] = struct.pack("<I", pe_offset)
    pe_data[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    file_path = tmp_path / "sample.exe"
    _write_bytes(file_path, bytes(pe_data))

    detector = MagicByteDetector()
    result = detector.detect_file_type(str(file_path))
    assert result["file_format"].startswith("PE")
    assert result["is_executable"] is True

    assert is_executable_file(str(file_path)) is True
    assert get_file_threat_level(str(file_path)) == "High"


def test_detect_elf_and_macho(tmp_path: Path):
    elf_path = tmp_path / "sample.elf"
    _write_bytes(elf_path, b"\x7fELF\x02" + b"\x00" * 100)
    detector = MagicByteDetector()
    elf = detector.detect_file_type(str(elf_path))
    assert elf["file_format"].startswith("ELF")
    assert elf["bits"] in {64, "Unknown"}

    macho_path = tmp_path / "sample.macho"
    macho = b"\xfe\xed\xfa\xce" + struct.pack("<I", 7) + b"\x00" * 64
    _write_bytes(macho_path, macho)
    macho_res = detector.detect_file_type(str(macho_path))
    assert "MACHO" in macho_res["file_format"]
    assert macho_res["architecture"] == "x86"


def test_docx_and_fallback(tmp_path: Path):
    docx_path = tmp_path / "sample.docx"
    content = b"PK\x03\x04" + b"word/" + b"[Content_Types].xml"
    _write_bytes(docx_path, content)

    detector = MagicByteDetector()
    docx = detector.detect_file_type(str(docx_path))
    assert docx["file_format"] in {"DOCX", "ZIP"}

    script_path = tmp_path / "script.ps1"
    _write_bytes(script_path, b"#!/bin/bash\n")
    fallback = detector.detect_file_type(str(script_path))
    assert fallback["format_category"] in {"Script", "Executable"}
    assert fallback["potential_threat"] is True
