from __future__ import annotations

from pathlib import Path

from r2inspect.utils.magic_detector import MagicByteDetector

PE_FIXTURE = Path("samples/fixtures/hello_pe.exe")
ELF_FIXTURE = Path("samples/fixtures/hello_elf")
MACHO_FIXTURE = Path("samples/fixtures/hello_macho")


def test_magic_detector_detects_known_formats() -> None:
    detector = MagicByteDetector()

    pe = detector.detect_file_type(str(PE_FIXTURE))
    assert pe["file_format"].startswith("PE")
    assert pe["is_executable"] is True
    assert pe["confidence"] >= 0.8

    elf = detector.detect_file_type(str(ELF_FIXTURE))
    assert elf["file_format"].startswith("ELF")
    assert elf["is_executable"] is True
    assert elf["confidence"] >= 0.8

    macho = detector.detect_file_type(str(MACHO_FIXTURE))
    assert macho["file_format"].startswith("MACHO")
    assert macho["is_executable"] is True
    assert macho["confidence"] >= 0.8


def test_magic_detector_cache_and_missing_file(tmp_path: Path) -> None:
    detector = MagicByteDetector()
    missing = tmp_path / "missing.bin"

    first = detector.detect_file_type(str(missing))
    second = detector.detect_file_type(str(missing))
    assert first == second
    assert first["file_format"] == "Unknown"


def test_magic_detector_docx_validation(tmp_path: Path) -> None:
    docx = tmp_path / "sample.docx"
    content = b"PK\x03\x04" + b"A" * 20 + b"[Content_Types].xml" + b"word/" + b"docProps/"
    docx.write_bytes(content)

    detector = MagicByteDetector()
    result = detector.detect_file_type(str(docx))
    assert result["file_format"] == "DOCX"
    assert result["is_document"] is True
    assert result["confidence"] >= 0.6


def test_magic_detector_fallback_extension_and_script(tmp_path: Path) -> None:
    detector = MagicByteDetector()

    ps1 = tmp_path / "script.ps1"
    ps1.write_text("Write-Host 'hi'")
    result = detector.detect_file_type(str(ps1))
    assert result["format_category"] == "Executable"
    assert result["is_executable"] is True
    assert result["potential_threat"] is True

    script = tmp_path / "run.txt"
    script.write_text("#!/bin/bash\necho hi")
    result = detector.detect_file_type(str(script))
    assert result["format_category"] == "Script"
    assert result["potential_threat"] is True
