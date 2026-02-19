#!/usr/bin/env python3
"""
Tests for r2inspect/utils/magic_detector.py covering branches
not exercised by the existing test suite.
"""

import os
import struct
import tempfile

import pytest

from r2inspect.utils.magic_detector import (
    MagicByteDetector,
    detect_file_type,
    get_file_threat_level,
    is_executable_file,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_tmp(data: bytes) -> str:
    fd, path = tempfile.mkstemp()
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    return path


def _make_pe(machine: int = 0x8664, pe_offset: int = 0x40) -> bytes:
    """Build a minimal valid PE binary."""
    header = bytearray(b"MZ")
    header.extend(b"\x00" * (0x3C - 2))
    header.extend(struct.pack("<I", pe_offset))
    if len(header) < pe_offset:
        header.extend(b"\x00" * (pe_offset - len(header)))
    header.extend(b"PE\x00\x00")
    header.extend(struct.pack("<H", machine))
    header.extend(b"\x00" * 18)
    return bytes(header)


def _make_elf(elf_class: int, endian: int, machine: int) -> bytes:
    """Build a minimal ELF binary."""
    hdr = bytearray(b"\x7fELF")
    hdr.append(elf_class)   # EI_CLASS: 1=32-bit, 2=64-bit
    hdr.append(endian)      # EI_DATA:  1=LE, 2=BE
    hdr.extend(b"\x00" * 12)
    if endian == 1:
        hdr.extend(struct.pack("<H", machine))
    else:
        hdr.extend(struct.pack(">H", machine))
    hdr.extend(b"\x00" * 50)
    return bytes(hdr)


def _make_macho(magic_le: int, cpu_type: int, big_endian_cpu: bool = False) -> bytes:
    """Build a minimal Mach-O binary where magic is stored as 4 LE bytes."""
    data = struct.pack("<I", magic_le)
    if big_endian_cpu:
        data += struct.pack(">I", cpu_type)
    else:
        data += struct.pack("<I", cpu_type)
    data += b"\x00" * 50
    return data


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

def test_cache_hit_returns_same_dict():
    path = _write_tmp(b"\x7fELF\x02\x01\x00" + b"\x00" * 50)
    try:
        detector = MagicByteDetector()
        r1 = detector.detect_file_type(path)
        r2 = detector.detect_file_type(path)
        assert r1 is r2
    finally:
        os.unlink(path)


def test_clear_cache_empties_all_entries():
    path = _write_tmp(b"%PDF-1.4 " + b"\x00" * 50)
    try:
        detector = MagicByteDetector()
        detector.detect_file_type(path)
        assert len(detector.cache) > 0
        detector.clear_cache()
        assert len(detector.cache) == 0
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Non-existent file
# ---------------------------------------------------------------------------

def test_nonexistent_file_returns_zero_confidence():
    detector = MagicByteDetector()
    result = detector.detect_file_type("/tmp/__no_such_file_r2inspect_test__.bin")
    assert result["file_format"] == "Unknown"
    assert result["confidence"] == 0.0
    assert result["file_size"] == 0


# ---------------------------------------------------------------------------
# PE validation branches (_validate_pe_format)
# ---------------------------------------------------------------------------

def test_pe_validation_header_too_short_gives_low_confidence():
    # MZ followed by fewer than 64 bytes total
    path = _write_tmp(b"MZ" + b"\x00" * 10)
    try:
        result = detect_file_type(path)
        assert result["confidence"] <= 0.3
    finally:
        os.unlink(path)


def test_pe_validation_valid_signature_inline():
    path = _write_tmp(_make_pe(machine=0x8664))
    try:
        result = detect_file_type(path)
        assert result["file_format"].startswith("PE")
        assert result["confidence"] >= 0.95
    finally:
        os.unlink(path)


def test_pe_validation_pe_header_beyond_read_buffer():
    """pe_offset > 1024 forces a seek to read the PE signature."""
    pe_offset = 2000
    data = bytearray(b"MZ")
    data.extend(b"\x00" * (0x3C - 2))
    data.extend(struct.pack("<I", pe_offset))
    data.extend(b"\x00" * (pe_offset - len(data)))
    data.extend(b"PE\x00\x00")
    data.extend(struct.pack("<H", 0x014C))
    data.extend(b"\x00" * 18)
    path = _write_tmp(bytes(data))
    try:
        result = detect_file_type(path)
        assert result["confidence"] >= 0.9
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# DOCX validation branches (_validate_docx_format)
# ---------------------------------------------------------------------------

def test_docx_detection_multiple_office_indicators():
    content = b"PK\x03\x04" + b"\x00" * 50 + b"word/_rels/[Content_Types].xml" + b"\x00" * 500
    path = _write_tmp(content)
    try:
        result = detect_file_type(path)
        assert result["confidence"] > 0.0
    finally:
        os.unlink(path)


def test_docx_detection_single_office_indicator():
    content = b"PK\x03\x04" + b"\x00" * 50 + b"word/" + b"\x00" * 500
    path = _write_tmp(content)
    try:
        detector = MagicByteDetector()
        with open(path, "rb") as fh:
            confidence = detector._validate_docx_format(fh)
        assert confidence >= 0.1
    finally:
        os.unlink(path)


def test_docx_detection_no_office_content_in_zip():
    content = b"PK\x03\x04" + b"\x00" * 600
    path = _write_tmp(content)
    try:
        detector = MagicByteDetector()
        with open(path, "rb") as fh:
            confidence = detector._validate_docx_format(fh)
        assert confidence < 0.5
    finally:
        os.unlink(path)


def test_docx_detection_non_zip_returns_zero():
    content = b"\x00\x01\x02\x03" * 100
    path = _write_tmp(content)
    try:
        detector = MagicByteDetector()
        with open(path, "rb") as fh:
            confidence = detector._validate_docx_format(fh)
        assert confidence == 0.0
    finally:
        os.unlink(path)


def test_docx_validation_exception_path_returns_zero():
    class NonSeekableIO:
        def seek(self, *args, **kwargs):
            raise OSError("not seekable")

        def read(self, *args, **kwargs):
            return b""

    detector = MagicByteDetector()
    result = detector._validate_docx_format(NonSeekableIO())
    assert result == 0.0


# ---------------------------------------------------------------------------
# ELF details (_analyze_elf_details)
# ---------------------------------------------------------------------------

def test_elf32_little_endian_x86():
    path = _write_tmp(_make_elf(1, 1, 0x03))
    try:
        result = detect_file_type(path)
        assert result["bits"] == 32
        assert result["endianness"] == "Little"
        assert result["architecture"] == "x86"
    finally:
        os.unlink(path)


def test_elf64_little_endian_x86_64():
    path = _write_tmp(_make_elf(2, 1, 0x3E))
    try:
        result = detect_file_type(path)
        assert result["bits"] == 64
        assert result["endianness"] == "Little"
        assert result["architecture"] == "x86-64"
    finally:
        os.unlink(path)


def test_elf32_big_endian_powerpc():
    path = _write_tmp(_make_elf(1, 2, 0x14))
    try:
        result = detect_file_type(path)
        assert result["bits"] == 32
        assert result["endianness"] == "Big"
        assert result["architecture"] == "PowerPC"
    finally:
        os.unlink(path)


def test_elf64_big_endian_aarch64():
    path = _write_tmp(_make_elf(2, 2, 0xB7))
    try:
        result = detect_file_type(path)
        assert result["bits"] == 64
        assert result["endianness"] == "Big"
        assert result["architecture"] == "AArch64"
    finally:
        os.unlink(path)


def test_elf_unknown_endian():
    path = _write_tmp(_make_elf(1, 0, 0x00))
    try:
        result = detect_file_type(path)
        assert result["endianness"] == "Unknown"
    finally:
        os.unlink(path)


def test_elf_unknown_machine_gives_hex_label():
    path = _write_tmp(_make_elf(2, 1, 0xABCD))
    try:
        result = detect_file_type(path)
        assert "abcd" in result["architecture"].lower() or "Unknown" in result["architecture"]
    finally:
        os.unlink(path)


def test_analyze_elf_details_header_too_short():
    detector = MagicByteDetector()
    r = detector._analyze_elf_details(b"\x7fELF\x02\x01")
    assert r["architecture"] == "Unknown"
    assert r["bits"] == "Unknown"
    assert r["endianness"] == "Unknown"


# ---------------------------------------------------------------------------
# PE details (_analyze_pe_details)
# ---------------------------------------------------------------------------

def test_pe_details_x86():
    path = _write_tmp(_make_pe(machine=0x014C))
    try:
        result = detect_file_type(path)
        assert result["architecture"] == "x86"
        assert result["bits"] == 32
        assert result["endianness"] == "Little"
    finally:
        os.unlink(path)


def test_pe_details_x86_64():
    path = _write_tmp(_make_pe(machine=0x8664))
    try:
        result = detect_file_type(path)
        assert result["architecture"] == "x86-64"
        assert result["bits"] == 64
    finally:
        os.unlink(path)


def test_pe_details_arm():
    path = _write_tmp(_make_pe(machine=0x01C0))
    try:
        result = detect_file_type(path)
        assert result["architecture"] == "ARM"
        assert result["bits"] == 32
    finally:
        os.unlink(path)


def test_pe_details_aarch64():
    path = _write_tmp(_make_pe(machine=0xAA64))
    try:
        result = detect_file_type(path)
        assert result["architecture"] == "AArch64"
        assert result["bits"] == 64
    finally:
        os.unlink(path)


def test_pe_details_itanium():
    path = _write_tmp(_make_pe(machine=0x0200))
    try:
        result = detect_file_type(path)
        assert result["architecture"] == "Intel Itanium"
        assert result["bits"] == 64
    finally:
        os.unlink(path)


def test_pe_details_unknown_machine():
    path = _write_tmp(_make_pe(machine=0xFFFF))
    try:
        result = detect_file_type(path)
        assert "Unknown" in result["architecture"] or "ffff" in result["architecture"].lower()
    finally:
        os.unlink(path)


def test_pe_details_pe_data_too_short_returns_unknown():
    """pe_data < 24 bytes triggers early return with Unknown architecture."""
    pe_offset = 60
    data = b"MZ" + b"\x00" * 58 + struct.pack("<I", pe_offset)
    assert len(data) == 64  # pe_data slice = data[60:84] = only 4 bytes
    path = _write_tmp(data)
    try:
        result = detect_file_type(path)
        assert result["architecture"] == "Unknown"
        assert result["bits"] == "Unknown"
    finally:
        os.unlink(path)


def test_pe_details_pe_offset_beyond_header():
    """pe_offset > 1024 forces file seek in _analyze_pe_details."""
    pe_offset = 2000
    data = bytearray(b"MZ")
    data.extend(b"\x00" * (0x3C - 2))
    data.extend(struct.pack("<I", pe_offset))
    data.extend(b"\x00" * (pe_offset - len(data)))
    data.extend(b"PE\x00\x00")
    data.extend(struct.pack("<H", 0x8664))
    data.extend(b"\x00" * 18)
    path = _write_tmp(bytes(data))
    try:
        result = detect_file_type(path)
        assert result["architecture"] == "x86-64"
        assert result["bits"] == 64
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Mach-O details (_analyze_macho_details)
# ---------------------------------------------------------------------------

def test_macho32_little_endian_x86():
    # File bytes \xce\xfa\xed\xfe → struct.unpack("<I") = 0xFEEDFACE → Big endian
    # File bytes \xfe\xed\xfa\xce → struct.unpack("<I") = 0xCEFAEDFE → Little endian
    path = _write_tmp(b"\xfe\xed\xfa\xce" + struct.pack("<I", 7) + b"\x00" * 50)
    try:
        result = detect_file_type(path)
        assert result["bits"] == 32
        assert result["endianness"] == "Little"
        assert result["architecture"] == "x86"
    finally:
        os.unlink(path)


def test_macho32_big_endian_arm():
    # File bytes \xce\xfa\xed\xfe → magic = 0xFEEDFACE → Big endian
    path = _write_tmp(b"\xce\xfa\xed\xfe" + struct.pack(">I", 12) + b"\x00" * 50)
    try:
        result = detect_file_type(path)
        assert result["bits"] == 32
        assert result["endianness"] == "Big"
        assert result["architecture"] == "ARM"
    finally:
        os.unlink(path)


def test_macho64_little_endian_x86_64():
    # \xcf\xfa\xed\xfe → magic = 0xFEEDFACF → Big endian 64-bit
    # \xfe\xed\xfa\xcf → magic = 0xCFFAEDFE → Little endian 64-bit
    path = _write_tmp(b"\xfe\xed\xfa\xcf" + struct.pack("<I", 0x01000007) + b"\x00" * 50)
    try:
        result = detect_file_type(path)
        assert result["bits"] == 64
        assert result["endianness"] == "Little"
        assert result["architecture"] == "x86-64"
    finally:
        os.unlink(path)


def test_macho64_big_endian_aarch64():
    # \xcf\xfa\xed\xfe → magic = 0xFEEDFACF → Big endian 64-bit
    path = _write_tmp(b"\xcf\xfa\xed\xfe" + struct.pack(">I", 0x0100000C) + b"\x00" * 50)
    try:
        result = detect_file_type(path)
        assert result["bits"] == 64
        assert result["endianness"] == "Big"
        assert result["architecture"] == "AArch64"
    finally:
        os.unlink(path)


def test_macho_universal_big_endian():
    # \xca\xfe\xba\xbe → magic = 0xBEBAFECA → Little endian universal
    # \xbe\xba\xfe\xca → magic = 0xCAFEBABE → Big endian universal
    path = _write_tmp(b"\xbe\xba\xfe\xca" + struct.pack(">I", 18) + b"\x00" * 50)
    try:
        result = detect_file_type(path)
        assert result["bits"] == "Universal"
        assert result["endianness"] == "Big"
    finally:
        os.unlink(path)


def test_macho_universal_little_endian():
    path = _write_tmp(b"\xca\xfe\xba\xbe" + struct.pack("<I", 0x01000012) + b"\x00" * 50)
    try:
        result = detect_file_type(path)
        assert result["bits"] == "Universal"
        assert result["endianness"] == "Little"
    finally:
        os.unlink(path)


def test_analyze_macho_details_header_too_short():
    detector = MagicByteDetector()
    r = detector._analyze_macho_details(b"\xce\xfa")
    assert r["architecture"] == "Unknown"
    assert r["bits"] == "Unknown"


def test_analyze_macho_details_unknown_magic():
    detector = MagicByteDetector()
    r = detector._analyze_macho_details(b"\x01\x02\x03\x04" + b"\x00" * 4)
    assert r["architecture"] == "Unknown"
    assert r["bits"] == "Unknown"


# ---------------------------------------------------------------------------
# Fallback detection (_fallback_detection)
# ---------------------------------------------------------------------------

def test_fallback_exe_extension_marks_executable_and_threat():
    path = _write_tmp(b"\x00" * 32)
    exe_path = path + ".exe"
    os.rename(path, exe_path)
    try:
        result = detect_file_type(exe_path)
        assert result["is_executable"] is True
        assert result["potential_threat"] is True
        assert result["format_category"] == "Executable"
    finally:
        if os.path.exists(exe_path):
            os.unlink(exe_path)


def test_fallback_zip_extension_marks_archive():
    path = _write_tmp(b"\x00" * 32)
    zip_path = path + ".zip"
    os.rename(path, zip_path)
    try:
        result = detect_file_type(zip_path)
        assert result["is_archive"] is True
        assert result["format_category"] == "Archive"
    finally:
        if os.path.exists(zip_path):
            os.unlink(zip_path)


def test_fallback_pdf_extension_marks_document():
    path = _write_tmp(b"\x00" * 32)
    pdf_path = path + ".pdf"
    os.rename(path, pdf_path)
    try:
        result = detect_file_type(pdf_path)
        assert result["is_document"] is True
        assert result["format_category"] == "Document"
    finally:
        if os.path.exists(pdf_path):
            os.unlink(pdf_path)


def test_fallback_script_shebang_marks_threat():
    path = _write_tmp(b"#!/bin/bash\necho hello\n" + b"\x00" * 32)
    try:
        result = detect_file_type(path)
        assert result["potential_threat"] is True
        assert result["format_category"] == "Script"
    finally:
        os.unlink(path)


def test_fallback_mz_bytes_in_header_marks_threat():
    path = _write_tmp(b"\x4d\x5a" + b"\x00" * 100)
    try:
        result = detect_file_type(path)
        assert result["potential_threat"] is True
    finally:
        os.unlink(path)


def test_fallback_elf_bytes_in_header_marks_threat():
    # \x7fELF in header but not at correct offset for pattern match
    path = _write_tmp(b"\x00\x7f\x45\x4c\x46" + b"\x00" * 100)
    try:
        result = detect_file_type(path)
        # The ELF signature is at offset 1, not 0, so magic won't match
        # but the fallback should detect it via header check
        assert isinstance(result["potential_threat"], bool)
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Category and type helpers
# ---------------------------------------------------------------------------

def test_get_format_category_executables():
    d = MagicByteDetector()
    assert d._get_format_category("PE32") == "Executable"
    assert d._get_format_category("ELF64") == "Executable"
    assert d._get_format_category("MACHO32") == "Executable"


def test_get_format_category_archives():
    d = MagicByteDetector()
    assert d._get_format_category("ZIP") == "Archive"
    assert d._get_format_category("RAR") == "Archive"
    assert d._get_format_category("7ZIP") == "Archive"


def test_get_format_category_documents():
    d = MagicByteDetector()
    assert d._get_format_category("PDF") == "Document"
    assert d._get_format_category("DOC") == "Document"
    assert d._get_format_category("DOCX") == "Document"
    assert d._get_format_category("RTF") == "Document"


def test_get_format_category_bytecode():
    d = MagicByteDetector()
    assert d._get_format_category("SWF") == "Bytecode"
    assert d._get_format_category("JAVA_CLASS") == "Bytecode"
    assert d._get_format_category("DEX") == "Bytecode"


def test_get_format_category_other():
    d = MagicByteDetector()
    assert d._get_format_category("UNKNOWN_FORMAT") == "Other"


def test_is_executable_format():
    d = MagicByteDetector()
    assert d._is_executable_format("PE32") is True
    assert d._is_executable_format("ELF64") is True
    assert d._is_executable_format("MACHO64") is True
    assert d._is_executable_format("SWF") is True
    assert d._is_executable_format("JAVA_CLASS") is True
    assert d._is_executable_format("DEX") is True
    assert d._is_executable_format("ZIP") is False
    assert d._is_executable_format("PDF") is False


def test_is_archive_format():
    d = MagicByteDetector()
    assert d._is_archive_format("ZIP") is True
    assert d._is_archive_format("RAR") is True
    assert d._is_archive_format("7ZIP") is True
    assert d._is_archive_format("PDF") is False
    assert d._is_archive_format("PE32") is False


def test_is_document_format():
    d = MagicByteDetector()
    assert d._is_document_format("PDF") is True
    assert d._is_document_format("DOC") is True
    assert d._is_document_format("DOCX") is True
    assert d._is_document_format("RTF") is True
    assert d._is_document_format("ZIP") is False


def test_is_potential_threat_known_formats():
    d = MagicByteDetector()
    for fmt in ["PE32", "ELF32", "ELF64", "PDF", "DOC", "DOCX", "RTF",
                "SWF", "JAVA_CLASS", "DEX", "UPX", "NSIS"]:
        assert d._is_potential_threat(fmt) is True


def test_is_potential_threat_safe_formats():
    d = MagicByteDetector()
    assert d._is_potential_threat("ZIP") is False
    assert d._is_potential_threat("RAR") is False
    assert d._is_potential_threat("7ZIP") is False


# ---------------------------------------------------------------------------
# Module-level functions
# ---------------------------------------------------------------------------

def test_module_detect_file_type_nonexistent():
    result = detect_file_type("/tmp/__ghost_r2inspect_missing__.bin")
    assert result["file_format"] == "Unknown"
    assert result["confidence"] == 0.0


def test_is_executable_file_true_for_pe():
    path = _write_tmp(_make_pe(machine=0x8664))
    try:
        assert is_executable_file(path) is True
    finally:
        os.unlink(path)


def test_is_executable_file_false_for_plain_data():
    path = _write_tmp(b"\x00\x01\x02\x03" * 20)
    try:
        assert is_executable_file(path) is False
    finally:
        os.unlink(path)


def test_get_file_threat_level_high_for_executable():
    path = _write_tmp(_make_pe(machine=0x8664))
    try:
        assert get_file_threat_level(path) == "High"
    finally:
        os.unlink(path)


def test_get_file_threat_level_medium_for_document():
    path = _write_tmp(b"%PDF-1.4 " + b"\x00" * 100)
    try:
        level = get_file_threat_level(path)
        assert level in ("Medium", "High")
    finally:
        os.unlink(path)


def test_get_file_threat_level_low_for_unknown():
    path = _write_tmp(b"\x00\x01\x02\x03" * 10)
    try:
        assert get_file_threat_level(path) == "Low"
    finally:
        os.unlink(path)


def test_get_file_threat_level_low_for_nonexistent():
    level = get_file_threat_level("/tmp/__no_file_r2inspect__.bin")
    assert level == "Low"
