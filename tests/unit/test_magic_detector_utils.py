"""Comprehensive tests for r2inspect/utils/magic_detector.py (13% coverage)"""

from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.utils.magic_detector import (
    MagicByteDetector,
    detect_file_type,
    get_file_threat_level,
    is_executable_file,
)


def test_detect_file_type_pe32(tmp_path: Path):
    pe_file = tmp_path / "test.exe"
    pe_header = b"MZ" + b"\x90" * 58 + b"\x80\x00\x00\x00"
    pe_header += b"\x00" * (0x80 - len(pe_header))
    pe_header += b"PE\x00\x00" + b"\x4c\x01" + b"\x00" * 100
    pe_file.write_bytes(pe_header)
    
    result = detect_file_type(str(pe_file))
    
    assert result["file_format"] == "PE32"
    assert result["is_executable"] is True
    assert result["format_category"] == "Executable"
    assert result["potential_threat"] is True
    assert result["confidence"] > 0.5


def test_detect_file_type_elf32(tmp_path: Path):
    elf_file = tmp_path / "test.elf"
    elf_header = b"\x7fELF\x01\x01\x01\x00"
    elf_header += b"\x00" * 8
    elf_header += b"\x02\x00"
    elf_header += b"\x03\x00"
    elf_header += b"\x00" * 100
    elf_file.write_bytes(elf_header)
    
    result = detect_file_type(str(elf_file))
    
    assert result["file_format"] == "ELF32"
    assert result["is_executable"] is True
    assert result["bits"] == 32
    assert result["endianness"] == "Little"


def test_detect_file_type_elf64(tmp_path: Path):
    elf_file = tmp_path / "test.elf"
    elf_header = b"\x7fELF\x02\x02\x01\x00"
    elf_header += b"\x00" * 8
    elf_header += b"\x00\x00"
    elf_header += b"\x00\x01"
    elf_header += b"\x00\x3e"
    elf_header += b"\x00" * 100
    elf_file.write_bytes(elf_header)
    
    result = detect_file_type(str(elf_file))
    
    assert result["file_format"] == "ELF64"
    assert result["bits"] == 64
    assert result["endianness"] == "Big"


def test_detect_file_type_macho32(tmp_path: Path):
    macho_file = tmp_path / "test.macho"
    macho_header = b"\xce\xfa\xed\xfe"
    macho_header += b"\x07\x00\x00\x00"
    macho_header += b"\x00" * 100
    macho_file.write_bytes(macho_header)
    
    result = detect_file_type(str(macho_file))
    
    assert result["file_format"] == "MACHO32"
    assert result["bits"] == 32


def test_detect_file_type_macho64(tmp_path: Path):
    macho_file = tmp_path / "test.macho"
    macho_header = b"\xcf\xfa\xed\xfe"
    macho_header += b"\x07\x00\x00\x01"
    macho_header += b"\x00" * 100
    macho_file.write_bytes(macho_header)
    
    result = detect_file_type(str(macho_file))
    
    assert result["file_format"] == "MACHO64"
    assert result["bits"] == 64


def test_detect_file_type_macho_universal(tmp_path: Path):
    macho_file = tmp_path / "test.macho"
    macho_header = b"\xca\xfe\xba\xbe"
    macho_header += b"\x00" * 100
    macho_file.write_bytes(macho_header)
    
    result = detect_file_type(str(macho_file))
    
    assert result["file_format"] == "MACHO_UNIVERSAL"
    assert result["bits"] == "Universal"


def test_detect_file_type_zip(tmp_path: Path):
    zip_file = tmp_path / "test.zip"
    zip_file.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    
    result = detect_file_type(str(zip_file))
    
    assert result["file_format"] == "ZIP"
    assert result["is_archive"] is True
    assert result["format_category"] == "Archive"


def test_detect_file_type_pdf(tmp_path: Path):
    pdf_file = tmp_path / "test.pdf"
    pdf_file.write_bytes(b"%PDF-1.4\n" + b"test content")
    
    result = detect_file_type(str(pdf_file))
    
    assert result["file_format"] == "PDF"
    assert result["is_document"] is True
    assert result["potential_threat"] is True


def test_detect_file_type_unknown(tmp_path: Path):
    unknown_file = tmp_path / "test.bin"
    unknown_file.write_bytes(b"random data")
    
    result = detect_file_type(str(unknown_file))
    
    assert result["file_format"] == "Unknown"
    assert result["confidence"] == 0.0


def test_detect_file_type_nonexistent():
    result = detect_file_type("/nonexistent/file.bin")
    
    assert result["file_format"] == "Unknown"
    assert result["confidence"] == 0.0


def test_detect_file_type_cache(tmp_path: Path):
    detector = MagicByteDetector()
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"test data")
    
    result1 = detector.detect_file_type(str(test_file))
    result2 = detector.detect_file_type(str(test_file))
    
    assert result1 == result2
    assert len(detector.cache) == 1


def test_magic_detector_clear_cache():
    detector = MagicByteDetector()
    detector.cache["test"] = {"data": "value"}
    
    detector.clear_cache()
    
    assert len(detector.cache) == 0


def test_is_executable_file_true(tmp_path: Path):
    elf_file = tmp_path / "test.elf"
    elf_file.write_bytes(b"\x7fELF\x01" + b"\x00" * 100)
    
    result = is_executable_file(str(elf_file))
    assert result is True


def test_is_executable_file_false(tmp_path: Path):
    text_file = tmp_path / "test.txt"
    text_file.write_bytes(b"Hello World")
    
    result = is_executable_file(str(text_file))
    assert result is False


def test_get_file_threat_level_high(tmp_path: Path):
    pe_file = tmp_path / "test.exe"
    pe_header = b"MZ" + b"\x90" * 58 + b"\x80\x00\x00\x00"
    pe_header += b"PE\x00\x00" + b"\x00" * 100
    pe_file.write_bytes(pe_header)
    
    threat_level = get_file_threat_level(str(pe_file))
    assert threat_level == "High"


def test_get_file_threat_level_medium(tmp_path: Path):
    pdf_file = tmp_path / "test.pdf"
    pdf_file.write_bytes(b"%PDF-1.4\n")
    
    threat_level = get_file_threat_level(str(pdf_file))
    assert threat_level == "Medium"


def test_get_file_threat_level_low(tmp_path: Path):
    text_file = tmp_path / "test.txt"
    text_file.write_bytes(b"Hello World")
    
    threat_level = get_file_threat_level(str(text_file))
    assert threat_level == "Low"


def test_detect_file_type_fallback_exe_extension(tmp_path: Path):
    exe_file = tmp_path / "test.exe"
    exe_file.write_bytes(b"random data")
    
    result = detect_file_type(str(exe_file))
    
    assert result["is_executable"] is True
    assert result["potential_threat"] is True


def test_detect_file_type_fallback_zip_extension(tmp_path: Path):
    zip_file = tmp_path / "test.zip"
    zip_file.write_bytes(b"random data")
    
    result = detect_file_type(str(zip_file))
    
    assert result["is_archive"] is True


def test_detect_file_type_fallback_pdf_extension(tmp_path: Path):
    pdf_file = tmp_path / "test.pdf"
    pdf_file.write_bytes(b"random data")
    
    result = detect_file_type(str(pdf_file))
    
    assert result["is_document"] is True


def test_detect_file_type_elf_x86(tmp_path: Path):
    elf_file = tmp_path / "test.elf"
    elf_header = b"\x7fELF\x01\x01\x01\x00"
    elf_header += b"\x00" * 10
    elf_header += b"\x03\x00"
    elf_header += b"\x00" * 100
    elf_file.write_bytes(elf_header)
    
    result = detect_file_type(str(elf_file))
    
    assert result["architecture"] == "x86"


def test_detect_file_type_elf_arm(tmp_path: Path):
    elf_file = tmp_path / "test.elf"
    elf_header = b"\x7fELF\x01\x01\x01\x00"
    elf_header += b"\x00" * 10
    elf_header += b"\x28\x00"
    elf_header += b"\x00" * 100
    elf_file.write_bytes(elf_header)
    
    result = detect_file_type(str(elf_file))
    
    assert result["architecture"] == "ARM"


def test_detect_file_type_pe_validation_short_header(tmp_path: Path):
    pe_file = tmp_path / "test.exe"
    pe_file.write_bytes(b"MZ")
    
    result = detect_file_type(str(pe_file))
    
    assert result["confidence"] < 0.5


def test_detect_file_type_docx(tmp_path: Path):
    docx_file = tmp_path / "test.docx"
    docx_content = b"PK\x03\x04" + b"\x00" * 500
    docx_content += b"word/" + b"\x00" * 100
    docx_content += b"[Content_Types].xml"
    docx_file.write_bytes(docx_content)
    
    result = detect_file_type(str(docx_file))
    
    assert result["confidence"] > 0.5


def test_detect_file_type_rar(tmp_path: Path):
    rar_file = tmp_path / "test.rar"
    rar_file.write_bytes(b"Rar!\x1a\x07\x00" + b"\x00" * 100)
    
    result = detect_file_type(str(rar_file))
    
    assert result["file_format"] == "RAR"
    assert result["is_archive"] is True


def test_detect_file_type_7zip(tmp_path: Path):
    seven_zip = tmp_path / "test.7z"
    seven_zip.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 100)
    
    result = detect_file_type(str(seven_zip))
    
    assert result["file_format"] == "7ZIP"
    assert result["is_archive"] is True


def test_detect_file_type_rtf(tmp_path: Path):
    rtf_file = tmp_path / "test.rtf"
    rtf_file.write_bytes(b"{\\rtf1\\ansi\\deff0")
    
    result = detect_file_type(str(rtf_file))
    
    assert result["file_format"] == "RTF"
    assert result["is_document"] is True


def test_detect_file_type_script_patterns(tmp_path: Path):
    script_file = tmp_path / "test.sh"
    script_file.write_bytes(b"#!/bin/bash\necho test")
    
    result = detect_file_type(str(script_file))
    
    assert result["potential_threat"] is True


def test_detect_file_type_pe_x86_64(tmp_path: Path):
    pe_file = tmp_path / "test.exe"
    pe_header = b"MZ" + b"\x90" * 58 + b"\x80\x00\x00\x00"
    pe_header += b"\x00" * (0x80 - len(pe_header))
    pe_header += b"PE\x00\x00"
    pe_header += b"\x64\x86"
    pe_header += b"\x00" * 100
    pe_file.write_bytes(pe_header)
    
    result = detect_file_type(str(pe_file))
    
    assert result["file_format"] == "PE32"
    assert result["architecture"] == "x86-64"
    assert result["bits"] == 64


def test_detect_file_type_pe_arm(tmp_path: Path):
    pe_file = tmp_path / "test.exe"
    pe_header = b"MZ" + b"\x90" * 58 + b"\x80\x00\x00\x00"
    pe_header += b"\x00" * (0x80 - len(pe_header))
    pe_header += b"PE\x00\x00"
    pe_header += b"\xc0\x01"
    pe_header += b"\x00" * 100
    pe_file.write_bytes(pe_header)
    
    result = detect_file_type(str(pe_file))
    
    assert result["architecture"] == "ARM"


def test_detect_file_type_macho_arm(tmp_path: Path):
    macho_file = tmp_path / "test.macho"
    macho_header = b"\xcf\xfa\xed\xfe"
    macho_header += b"\x0c\x00\x00\x01"
    macho_header += b"\x00" * 100
    macho_file.write_bytes(macho_header)
    
    result = detect_file_type(str(macho_file))
    
    assert result["file_format"] == "MACHO64"
    assert result["bits"] == 64


def test_detect_file_type_empty_file(tmp_path: Path):
    empty_file = tmp_path / "empty.bin"
    empty_file.write_bytes(b"")
    
    result = detect_file_type(str(empty_file))
    
    assert result["file_format"] == "Unknown"
    assert result["file_size"] == 0


def test_detect_file_type_multiple_matches(tmp_path: Path):
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"MZ" + b"\x00" * 500)
    
    result = detect_file_type(str(test_file))
    
    assert len(result["magic_matches"]) >= 1


def test_detect_file_type_error_handling(tmp_path: Path):
    import os
    
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"test")
    os.chmod(test_file, 0o000)
    
    try:
        result = detect_file_type(str(test_file))
        assert "error" in result
    finally:
        os.chmod(test_file, 0o644)


def test_detect_file_type_pe_offset_beyond_header(tmp_path: Path):
    pe_file = tmp_path / "test.exe"
    pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x10\x00\x00"
    pe_header += b"\x00" * (0x1000 - len(pe_header))
    pe_header += b"PE\x00\x00"
    pe_header += b"\x00" * 100
    pe_file.write_bytes(pe_header)
    
    result = detect_file_type(str(pe_file))
    
    assert result["confidence"] > 0


def test_detect_file_type_extensions_field(tmp_path: Path):
    pe_file = tmp_path / "test.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)
    
    result = detect_file_type(str(pe_file))
    
    assert ".exe" in result["extensions"]
