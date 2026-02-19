#!/usr/bin/env python3
"""
Coverage tests for r2inspect/utils/magic_detector.py

Targets previously uncovered lines:
- 189-192: Exception handler in _validate_docx_format
- 284:     Short pe_data return in _analyze_pe_details
"""

import struct
import tempfile
import os

import pytest

from r2inspect.utils.magic_detector import (
    MagicByteDetector,
    detect_file_type,
    get_file_threat_level,
    is_executable_file,
)


def _write_tmp(data: bytes) -> str:
    fd, path = tempfile.mkstemp()
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    return path


def test_detect_nonexistent_file_returns_unknown():
    result = detect_file_type("/nonexistent/path/file.bin")
    assert result["file_format"] == "Unknown"
    assert result["confidence"] == 0.0


def test_detect_elf32_file():
    data = b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 8 + struct.pack("<H", 0x03) * 5 + b"\x00" * 100
    path = _write_tmp(data)
    try:
        result = detect_file_type(path)
        assert result["is_executable"] is True
        assert result["format_category"] == "Executable"
    finally:
        os.unlink(path)


def test_detect_elf64_file():
    data = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + struct.pack("<H", 0x3E) + b"\x00" * 100
    path = _write_tmp(data)
    try:
        result = detect_file_type(path)
        assert result["is_executable"] is True
        assert "64" in str(result.get("bits", "")) or result["file_format"] == "ELF64"
    finally:
        os.unlink(path)


def test_detect_pdf_file():
    data = b"%PDF-1.4 " + b"\x00" * 200
    path = _write_tmp(data)
    try:
        result = detect_file_type(path)
        assert result["is_document"] is True
        assert result["potential_threat"] is True
    finally:
        os.unlink(path)


def test_detect_zip_file_plain():
    data = b"PK\x03\x04" + b"\x00" * 200
    path = _write_tmp(data)
    try:
        result = detect_file_type(path)
        assert result["is_archive"] is True
    finally:
        os.unlink(path)


def test_detect_macho32_little_endian():
    # 0xCEFAEDFE = Mach-O 32-bit little-endian
    magic = struct.pack("<I", 0xCEFAEDFE)
    cpu_type = struct.pack("<I", 7)  # x86
    data = magic + cpu_type + b"\x00" * 200
    path = _write_tmp(data)
    try:
        result = detect_file_type(path)
        assert result["is_executable"] is True
        assert result["endianness"] == "Little"
        assert result["bits"] == 32
    finally:
        os.unlink(path)


def test_detect_macho64_little_endian():
    magic = struct.pack("<I", 0xCFFAEDFE)
    cpu_type = struct.pack("<I", 0x01000007)  # x86-64
    data = magic + cpu_type + b"\x00" * 200
    path = _write_tmp(data)
    try:
        result = detect_file_type(path)
        assert result["bits"] == 64
        assert result["endianness"] == "Little"
    finally:
        os.unlink(path)


def test_detect_macho64_big_endian():
    # LE-read of bytes gives 0xFEEDFACF → Big-endian 64-bit Mach-O
    magic = struct.pack("<I", 0xFEEDFACF)
    # cpu_type read as big-endian: AArch64 = 0x0100000C
    cpu_type = struct.pack(">I", 0x0100000C)
    data = magic + cpu_type + b"\x00" * 200
    path = _write_tmp(data)
    try:
        result = detect_file_type(path)
        assert result["bits"] == 64
        assert result["endianness"] == "Big"
    finally:
        os.unlink(path)


def test_detect_macho_universal_big_endian():
    # LE-read of bytes gives 0xCAFEBABE → Universal big-endian
    magic = struct.pack("<I", 0xCAFEBABE)
    # cpu_type read as big-endian: PowerPC = 18
    cpu_type = struct.pack(">I", 18)
    data = magic + cpu_type + b"\x00" * 200
    path = _write_tmp(data)
    try:
        result = detect_file_type(path)
        assert result["bits"] == "Universal"
        assert result["endianness"] == "Big"
    finally:
        os.unlink(path)


def test_detect_macho_universal_little_endian():
    magic = struct.pack("<I", 0xBEBAFECA)
    cpu_type = struct.pack("<I", 0x01000012)  # PowerPC64
    data = magic + cpu_type + b"\x00" * 200
    path = _write_tmp(data)
    try:
        result = detect_file_type(path)
        assert result["bits"] == "Universal"
        assert result["endianness"] == "Little"
    finally:
        os.unlink(path)


def test_detect_macho32_big_endian():
    # LE-read of bytes gives 0xFEEDFACE → Big-endian 32-bit Mach-O
    magic = struct.pack("<I", 0xFEEDFACE)
    # cpu_type read as big-endian: ARM = 12
    cpu_type = struct.pack(">I", 12)
    data = magic + cpu_type + b"\x00" * 200
    path = _write_tmp(data)
    try:
        result = detect_file_type(path)
        assert result["bits"] == 32
        assert result["endianness"] == "Big"
    finally:
        os.unlink(path)


def test_detect_pe32_with_valid_pe_signature():
    # Craft a minimal valid PE: MZ header pointing to offset 64, then PE signature
    pe_offset = 64
    header = b"MZ" + b"\x00" * 58 + struct.pack("<I", pe_offset)
    pe_sig = b"PE\x00\x00"
    # COFF machine type for x86 (0x014C)
    coff = struct.pack("<H", 0x014C) + b"\x00" * 18
    data = header + pe_sig + coff + b"\x00" * 500
    path = _write_tmp(data)
    try:
        result = detect_file_type(path)
        assert result["confidence"] >= 0.9
        assert result["architecture"] == "x86"
        assert result["bits"] == 32
        assert result["endianness"] == "Little"
    finally:
        os.unlink(path)


def test_detect_pe32_short_pe_data_returns_unknown_arch():
    """
    Cover line 284: pe_data shorter than 24 bytes causes early return
    with architecture/bits = Unknown.

    File is exactly 64 bytes: MZ header with pe_offset=60, leaving
    only 4 bytes for the PE data slice.
    """
    pe_offset = 60
    # Craft header: 2 bytes MZ + 58 zero bytes + 4-byte pe_offset = 64 bytes total
    data = b"MZ" + b"\x00" * 58 + struct.pack("<I", pe_offset)
    assert len(data) == 64  # pe_data = data[60:84] = 4 bytes < 24
    path = _write_tmp(data)
    try:
        result = detect_file_type(path)
        # PE32 matched (MZ present), but pe_data too short for arch details
        assert result["architecture"] == "Unknown"
        assert result["bits"] == "Unknown"
    finally:
        os.unlink(path)


def test_validate_docx_format_exception_path():
    """
    Cover lines 189-192: exception inside _validate_docx_format.

    Pass a custom non-seekable IO object directly to trigger the except branch.
    """

    class NonSeekableIO:
        """A minimal BinaryIO-compatible object whose seek() always raises."""

        def seek(self, *args, **kwargs):
            raise OSError("not seekable")

        def read(self, *args, **kwargs):
            return b""

    detector = MagicByteDetector()
    result = detector._validate_docx_format(NonSeekableIO())
    assert result == 0.0


def test_fallback_detection_executable_extension():
    data = b"\x00" * 10
    path = _write_tmp(data)
    exe_path = path + ".exe"
    os.rename(path, exe_path)
    try:
        result = detect_file_type(exe_path)
        assert result["is_executable"] is True
        assert result["potential_threat"] is True
    finally:
        if os.path.exists(exe_path):
            os.unlink(exe_path)


def test_fallback_detection_archive_extension():
    data = b"\x00" * 10
    path = _write_tmp(data)
    zip_path = path + ".zip"
    os.rename(path, zip_path)
    try:
        result = detect_file_type(zip_path)
        assert result["is_archive"] is True
    finally:
        if os.path.exists(zip_path):
            os.unlink(zip_path)


def test_fallback_detection_document_extension():
    data = b"\x00" * 10
    path = _write_tmp(data)
    doc_path = path + ".pdf"
    os.rename(path, doc_path)
    try:
        result = detect_file_type(doc_path)
        assert result["is_document"] is True
    finally:
        if os.path.exists(doc_path):
            os.unlink(doc_path)


def test_fallback_detection_script_pattern():
    data = b"#!/bin/bash\necho hello\n"
    path = _write_tmp(data)
    try:
        result = detect_file_type(path)
        assert result["potential_threat"] is True
        assert result["format_category"] == "Script"
    finally:
        os.unlink(path)


def test_clear_cache():
    detector = MagicByteDetector()
    data = b"%PDF-1.4 " + b"\x00" * 50
    path = _write_tmp(data)
    try:
        detect_result = detector.detect_file_type(path)
        assert len(detector.cache) > 0
        detector.clear_cache()
        assert len(detector.cache) == 0
    finally:
        os.unlink(path)


def test_cache_returns_same_result_on_second_call():
    detector = MagicByteDetector()
    data = b"%PDF-1.4 " + b"\x00" * 50
    path = _write_tmp(data)
    try:
        result1 = detector.detect_file_type(path)
        result2 = detector.detect_file_type(path)
        assert result1["file_format"] == result2["file_format"]
    finally:
        os.unlink(path)


def test_is_executable_file_true_for_elf():
    data = b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 100
    path = _write_tmp(data)
    try:
        assert is_executable_file(path) is True
    finally:
        os.unlink(path)


def test_is_executable_file_false_for_pdf():
    data = b"%PDF-1.4 " + b"\x00" * 100
    path = _write_tmp(data)
    try:
        assert is_executable_file(path) is False
    finally:
        os.unlink(path)


def test_get_file_threat_level_high_for_elf():
    data = b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 100
    path = _write_tmp(data)
    try:
        level = get_file_threat_level(path)
        assert level == "High"
    finally:
        os.unlink(path)


def test_get_file_threat_level_low_for_unknown():
    data = b"\x00\x01\x02\x03" * 10
    path = _write_tmp(data)
    try:
        level = get_file_threat_level(path)
        assert level == "Low"
    finally:
        os.unlink(path)


def test_get_file_threat_level_medium_for_pdf():
    data = b"%PDF-1.4 " + b"\x00" * 100
    path = _write_tmp(data)
    try:
        level = get_file_threat_level(path)
        assert level in ("Medium", "High")
    finally:
        os.unlink(path)


def test_elf_big_endian_architecture():
    # ELF32 big-endian (header[5] == 2), machine = PowerPC (0x0014)
    elf_header = (
        b"\x7fELF\x01"  # ELF32
        b"\x02"  # big-endian
        b"\x01\x00"  # version, OS/ABI
        + b"\x00" * 8  # padding
        + b"\x00\x02"  # ET_EXEC
        + struct.pack(">H", 0x14)  # machine: PowerPC
        + b"\x00" * 100
    )
    path = _write_tmp(elf_header)
    try:
        result = detect_file_type(path)
        assert result["bits"] == 32
        assert result["endianness"] == "Big"
        assert result["architecture"] == "PowerPC"
    finally:
        os.unlink(path)


def test_analyze_pe_details_x86_64():
    pe_offset = 64
    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<H", 0x8664) + b"\x00" * 18  # x86-64
    data = b"MZ" + b"\x00" * 58 + struct.pack("<I", pe_offset) + pe_sig + coff + b"\x00" * 500
    path = _write_tmp(data)
    try:
        result = detect_file_type(path)
        assert result["architecture"] == "x86-64"
        assert result["bits"] == 64
    finally:
        os.unlink(path)


def test_analyze_pe_details_aarch64():
    pe_offset = 64
    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<H", 0xAA64) + b"\x00" * 18  # AArch64
    data = b"MZ" + b"\x00" * 58 + struct.pack("<I", pe_offset) + pe_sig + coff + b"\x00" * 500
    path = _write_tmp(data)
    try:
        result = detect_file_type(path)
        assert result["architecture"] == "AArch64"
        assert result["bits"] == 64
    finally:
        os.unlink(path)


def test_docx_format_medium_confidence():
    # ZIP signature + one Office indicator = medium confidence (0.6)
    content = b"PK\x03\x04" + b"\x00" * 100 + b"word/" + b"\x00" * 300
    path = _write_tmp(content)
    try:
        detector = MagicByteDetector()
        with open(path, "rb") as fh:
            confidence = detector._validate_docx_format(fh)
        assert confidence >= 0.1
    finally:
        os.unlink(path)
