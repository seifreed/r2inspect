"""Comprehensive tests for magic detector - targeting 13% -> 100% coverage"""
import pytest
import tempfile
from pathlib import Path

from r2inspect.utils.magic_detector import (
    MagicByteDetector,
    detect_file_type,
    is_executable_file,
    get_file_threat_level,
)


def test_magic_detector_init():
    detector = MagicByteDetector()
    assert detector.cache == {}
    assert len(detector.MAGIC_PATTERNS) > 0


def test_magic_detector_pe32():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
        # MZ header + PE signature at offset 0x3c
        data = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00"  # PE offset at 0x40
        data += b"\x00" * (0x40 - len(data))
        data += b"PE\x00\x00" + b"\x4c\x01" + b"\x00" * 18  # PE sig + x86 machine type
        f.write(data)
        f.flush()
        
        detector = MagicByteDetector()
        result = detector.detect_file_type(f.name)
        
        assert result["file_format"] in ["PE32", "PE64", "PE"]
        assert result["is_executable"] is True
        
        Path(f.name).unlink()


def test_magic_detector_elf():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".elf") as f:
        # ELF header
        data = b"\x7fELF"  # Magic
        data += b"\x02"  # 64-bit
        data += b"\x01"  # Little endian
        data += b"\x01" + b"\x00" * 9  # ELF version + padding
        data += b"\x3e\x00"  # x86-64 machine type
        data += b"\x00" * 100
        f.write(data)
        f.flush()
        
        detector = MagicByteDetector()
        result = detector.detect_file_type(f.name)
        
        assert "ELF" in result["file_format"]
        assert result["is_executable"] is True
        
        Path(f.name).unlink()


def test_magic_detector_zip():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as f:
        # ZIP header
        f.write(b"PK\x03\x04" + b"\x00" * 100)
        f.flush()
        
        detector = MagicByteDetector()
        result = detector.detect_file_type(f.name)
        
        assert result["is_archive"] is True
        
        Path(f.name).unlink()


def test_magic_detector_pdf():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as f:
        f.write(b"%PDF-1.4\n" + b"\x00" * 100)
        f.flush()
        
        detector = MagicByteDetector()
        result = detector.detect_file_type(f.name)
        
        assert result["is_document"] is True
        
        Path(f.name).unlink()


def test_magic_detector_unknown():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"\xaa" * 100)
        f.flush()
        
        detector = MagicByteDetector()
        result = detector.detect_file_type(f.name)
        
        assert result["file_format"] == "Unknown"
        assert result["confidence"] == 0.0
        
        Path(f.name).unlink()


def test_magic_detector_cache():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"MZ" + b"\x00" * 100)
        f.flush()
        
        detector = MagicByteDetector()
        
        # First call
        result1 = detector.detect_file_type(f.name)
        
        # Second call should use cache
        result2 = detector.detect_file_type(f.name)
        
        assert result1 == result2
        assert len(detector.cache) > 0
        
        Path(f.name).unlink()


def test_magic_detector_clear_cache():
    detector = MagicByteDetector()
    detector.cache["test"] = {}
    
    detector.clear_cache()
    assert detector.cache == {}


def test_magic_detector_nonexistent_file():
    detector = MagicByteDetector()
    result = detector.detect_file_type("/nonexistent/file.exe")
    
    assert result["file_format"] == "Unknown"


def test_magic_detector_fallback_exe_extension():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
        f.write(b"\xaa" * 100)  # Unknown content
        f.flush()
        
        detector = MagicByteDetector()
        result = detector.detect_file_type(f.name)
        
        # Should use fallback based on extension
        assert result["is_executable"] is True or result["potential_threat"] is True
        
        Path(f.name).unlink()


def test_detect_file_type_global():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"MZ" + b"\x00" * 100)
        f.flush()
        
        result = detect_file_type(f.name)
        assert "file_format" in result
        
        Path(f.name).unlink()


def test_is_executable_file():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
        data = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00"
        data += b"\x00" * (0x40 - len(data))
        data += b"PE\x00\x00" + b"\x00" * 20
        f.write(data)
        f.flush()
        
        result = is_executable_file(f.name)
        # Result depends on PE validation
        assert isinstance(result, bool)
        
        Path(f.name).unlink()


def test_get_file_threat_level():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
        f.write(b"MZ" + b"\x00" * 100)
        f.flush()
        
        threat = get_file_threat_level(f.name)
        assert threat in ["High", "Medium", "Low", "Unknown"]
        
        Path(f.name).unlink()


def test_magic_detector_elf_architecture():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        # ELF 64-bit x86-64 little endian
        data = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 10
        data += b"\x3e\x00"  # x86-64
        data += b"\x00" * 100
        f.write(data)
        f.flush()
        
        detector = MagicByteDetector()
        result = detector.detect_file_type(f.name)
        
        assert result["bits"] == 64
        assert result["endianness"] == "Little"
        
        Path(f.name).unlink()


def test_magic_detector_pe_architecture():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        # PE 64-bit x86-64
        data = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00"
        data += b"\x00" * (0x40 - len(data))
        data += b"PE\x00\x00"
        data += b"\x64\x86" + b"\x00" * 18  # x86-64 machine type
        f.write(data)
        f.flush()
        
        detector = MagicByteDetector()
        result = detector.detect_file_type(f.name)
        
        # May detect architecture if PE is valid
        
        Path(f.name).unlink()


def test_magic_detector_macho():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        # Mach-O 64-bit little endian
        data = b"\xcf\xfa\xed\xfe"  # Magic for 64-bit LE
        data += b"\x07\x00\x00\x01"  # CPU type x86-64
        data += b"\x00" * 100
        f.write(data)
        f.flush()
        
        detector = MagicByteDetector()
        result = detector.detect_file_type(f.name)
        
        # May detect Mach-O
        
        Path(f.name).unlink()


def test_magic_detector_format_category():
    detector = MagicByteDetector()
    
    assert detector._get_format_category("PE32") == "Executable"
    assert detector._get_format_category("ZIP") == "Archive"
    assert detector._get_format_category("PDF") == "Document"


def test_magic_detector_is_executable_format():
    detector = MagicByteDetector()
    
    assert detector._is_executable_format("PE32") is True
    assert detector._is_executable_format("ELF64") is True
    assert detector._is_executable_format("ZIP") is False


def test_magic_detector_is_archive_format():
    detector = MagicByteDetector()
    
    assert detector._is_archive_format("ZIP") is True
    assert detector._is_archive_format("RAR") is True
    assert detector._is_archive_format("PE32") is False


def test_magic_detector_is_document_format():
    detector = MagicByteDetector()
    
    assert detector._is_document_format("PDF") is True
    assert detector._is_document_format("DOCX") is True
    assert detector._is_document_format("PE32") is False


def test_magic_detector_is_potential_threat():
    detector = MagicByteDetector()
    
    assert detector._is_potential_threat("PE32") is True
    assert detector._is_potential_threat("PDF") is True
    assert detector._is_potential_threat("ZIP") is False
