from __future__ import annotations

import os
import struct
from pathlib import Path

from r2inspect.utils.magic_detector import MagicByteDetector, get_file_threat_level


def _write_bytes(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def test_magic_detector_file_errors_and_pe_validation(tmp_path: Path) -> None:
    detector = MagicByteDetector()

    no_access = tmp_path / "no_access.bin"
    _write_bytes(no_access, b"data")
    os.chmod(no_access, 0)
    try:
        result = detector.detect_file_type(str(no_access))
        assert "error" in result
    finally:
        os.chmod(no_access, 0o644)

    small_header = b"MZ"
    with (tmp_path / "small.bin").open("wb") as f:
        f.write(small_header)
        f.flush()
        assert detector._validate_pe_format(small_header, f) == 0.0

    header = b"NZ" + b"\x00" * 62
    with (tmp_path / "non_mz.bin").open("wb") as f:
        f.write(header)
        f.flush()
        assert detector._validate_pe_format(header, f) == 0.0

    pe_file = tmp_path / "pe.bin"
    pe_offset = 128
    header = bytearray(b"MZ" + b"\x00" * 58 + struct.pack("<I", pe_offset))
    header.extend(b"\x00" * (64 - len(header)))
    pe_data = b"PE\x00\x00" + b"\x00" * 20
    _write_bytes(pe_file, bytes(header) + b"\x00" * (pe_offset - len(header)) + pe_data)
    with pe_file.open("rb") as f:
        assert detector._validate_pe_format(bytes(header), f) == 0.95

    with pe_file.open("rb") as f:
        f.close()
        assert detector._validate_pe_format(bytes(header), f) == 0.3


def test_magic_detector_docx_and_elf_macho_details(tmp_path: Path) -> None:
    detector = MagicByteDetector()

    not_zip = tmp_path / "not_zip.bin"
    _write_bytes(not_zip, b"NO")
    with not_zip.open("rb") as f:
        assert detector._validate_docx_format(f) == 0.0

    docx = tmp_path / "docx.bin"
    _write_bytes(docx, b"PK" + b"word/" + b"\x00" * 4000)
    with docx.open("rb") as f:
        assert detector._validate_docx_format(f) == 0.6

    zip_only = tmp_path / "zip_only.bin"
    _write_bytes(zip_only, b"PK" + b"\x00" * 4000)
    with zip_only.open("rb") as f:
        assert detector._validate_docx_format(f) == 0.1

    assert detector._analyze_elf_details(b"\x7fELF")["bits"] == "Unknown"
    elf_header = bytearray(b"\x7fELF" + b"\x01\x03" + b"\x00" * 18)
    details = detector._analyze_elf_details(bytes(elf_header))
    assert details["bits"] == 32
    assert details["endianness"] == "Unknown"

    with docx.open("rb") as f:
        assert detector._analyze_pe_details(b"\x00" * 10, f)["bits"] == "Unknown"

    macho_short = detector._analyze_macho_details(b"\x00" * 4)
    assert macho_short["bits"] == "Unknown"

    macho_64 = detector._analyze_macho_details(struct.pack("<II", 0xFEEDFACF, 0x01000007))
    assert macho_64["bits"] == 64

    macho_universal = detector._analyze_macho_details(struct.pack("<II", 0xCAFEBABE, 7))
    assert macho_universal["bits"] == "Universal"

    macho_unknown = detector._analyze_macho_details(struct.pack("<II", 0x12345678, 7))
    assert macho_unknown["bits"] == "Unknown"


def test_magic_detector_fallback_and_threat_levels(tmp_path: Path) -> None:
    detector = MagicByteDetector()

    zip_path = tmp_path / "file.zip"
    _write_bytes(zip_path, b"MZ" + b"\x00" * 10)
    result = detector._fallback_detection(zip_path.read_bytes(), zip_path)
    assert result["is_archive"] is True
    assert result["potential_threat"] is True

    doc_path = tmp_path / "file.doc"
    _write_bytes(doc_path, b"\x00" * 10)
    result = detector._fallback_detection(doc_path.read_bytes(), doc_path)
    assert result["is_document"] is True

    other_path = tmp_path / "file.txt"
    _write_bytes(other_path, b"\x00" * 10)
    result = detector._fallback_detection(other_path.read_bytes(), other_path)
    assert result["format_category"] == "Unknown"

    assert detector._get_format_category("SWF") == "Bytecode"
    assert detector._get_format_category("CUSTOM") == "Other"

    detector.clear_cache()

    assert get_file_threat_level(str(zip_path)) == "Medium"

    text_threat = tmp_path / "text.bin"
    _write_bytes(text_threat, b"MZ" + b"\x00" * 10)
    assert get_file_threat_level(str(text_threat)) == "Low"

    benign = tmp_path / "benign.bin"
    _write_bytes(benign, b"\x00" * 10)
    assert get_file_threat_level(str(benign)) == "Low"
