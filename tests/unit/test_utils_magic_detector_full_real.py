from __future__ import annotations

import io
import struct
from pathlib import Path

from r2inspect.utils.magic_detector import (
    MagicByteDetector,
    detect_file_type,
    get_file_threat_level,
)


def _write(tmp_path: Path, name: str, data: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def test_magic_detector_formats_and_fallbacks(tmp_path: Path) -> None:
    detector = MagicByteDetector()

    pe_header = bytearray(256)
    pe_header[0:2] = b"MZ"
    pe_offset = 0x40
    pe_header[60:64] = struct.pack("<I", pe_offset)
    pe_header[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    pe_header[pe_offset + 4 : pe_offset + 6] = struct.pack("<H", 0x8664)
    pe_path = _write(tmp_path, "sample.exe", bytes(pe_header))
    pe_result = detect_file_type(pe_path)
    assert pe_result["file_format"].startswith("PE")

    elf_header = bytearray(64)
    elf_header[0:5] = b"\x7fELF\x02"
    elf_header[5] = 1
    elf_header[18:20] = struct.pack("<H", 0x3E)
    elf_path = _write(tmp_path, "sample.elf", bytes(elf_header))
    elf_result = detect_file_type(elf_path)
    assert elf_result["file_format"].startswith("ELF")

    macho_header = struct.pack("<II", 0xFEEDFACF, 0x01000007)
    macho_path = _write(tmp_path, "sample.macho", macho_header + b"\x00" * 32)
    macho_result = detect_file_type(macho_path)
    assert "MACHO" in macho_result["file_format"]

    docx_bytes = b"PK\x03\x04word/[Content_Types].xml"
    docx_path = _write(tmp_path, "sample.docx", docx_bytes)
    docx_result = detect_file_type(docx_path)
    assert docx_result["file_format"] == "DOCX"

    fallback_path = _write(tmp_path, "fallback.bin", b"")
    fallback_result = detect_file_type(fallback_path)
    assert fallback_result["file_format"] == "Unknown"

    exe_path = _write(tmp_path, "fallback.exe", b"\x00" * 10)
    threat = get_file_threat_level(exe_path)
    assert threat in {"High", "Low", "Medium"}

    short = detector._analyze_elf_details(b"\x7fELF")
    assert short["bits"] == "Unknown"

    unknown_macho = detector._analyze_macho_details(b"\x00" * 8)
    assert unknown_macho["architecture"] == "Unknown"


def test_magic_detector_validators_and_helpers(tmp_path: Path) -> None:
    detector = MagicByteDetector()

    short_pe = detector._validate_pe_format(b"short", io.BytesIO(b"short"))
    assert short_pe == 0.0

    docx_one = io.BytesIO(b"PK\x03\x04word/")
    assert detector._validate_docx_format(docx_one) == 0.6

    docx_none = io.BytesIO(b"PK\x03\x04")
    assert detector._validate_docx_format(docx_none) == 0.1

    assert detector._get_format_category("ZIP") == "Archive"
    assert detector._get_format_category("PDF") == "Document"
    assert detector._get_format_category("ELF64") == "Executable"
    assert detector._get_format_category("XYZ") == "Other"

    assert detector._is_executable_format("PE32") is True
    assert detector._is_archive_format("ZIP") is True
    assert detector._is_document_format("DOCX") is True
    assert detector._is_potential_threat("NSIS") is True

    bad_path = tmp_path / "dir"
    bad_path.mkdir()
    result = detect_file_type(str(bad_path))
    assert result["file_format"] == "Unknown"

    elf_short = detector._analyze_elf_details(b"\x7fELF\x02" + b"\x00" * 6)
    assert elf_short["architecture"] == "Unknown"

    pe_header = bytearray(64)
    pe_offset = 0x200
    pe_header[60:64] = struct.pack("<I", pe_offset)
    pe_data = b"PE\x00\x00" + struct.pack("<H", 0x014C) + b"\x00" * 18
    pe_blob = bytearray(pe_offset + len(pe_data))
    pe_blob[pe_offset : pe_offset + len(pe_data)] = pe_data
    pe_details = detector._analyze_pe_details(bytes(pe_header), io.BytesIO(bytes(pe_blob)))
    assert pe_details["architecture"] == "x86"

    class _BadFile:
        def seek(self, _offset: int) -> None:
            raise OSError("boom")

        def read(self, _size: int) -> bytes:
            return b""

    pe_error = detector._analyze_pe_details(bytes(pe_header), _BadFile())
    assert pe_error["bits"] == "Unknown"
