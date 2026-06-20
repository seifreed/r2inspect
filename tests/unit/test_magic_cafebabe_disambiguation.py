#!/usr/bin/env python3
"""0xCAFEBABE is shared by Java class files and Mach-O fat binaries.

Both patterns matched at equal confidence, so dict-insertion order decided the
winner: MACHO_UNIVERSAL is defined first, so every Java .class file was
misclassified as a macOS universal binary. The discriminators read bytes 4-7 —
a fat binary's nfat_arch is a tiny architecture count, while a class file's
major version (bytes 6-7) is >= 45.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.infrastructure.magic_detector import MagicByteDetector


def _write(tmp_path: Path, name: str, payload: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(payload)
    return str(path)


@pytest.mark.unit
def test_java_class_not_misclassified_as_macho(tmp_path: Path) -> None:
    # magic + minor_version=0 + major_version=52 (Java 8)
    payload = b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\x00" * 64
    result = MagicByteDetector().detect_file_type(_write(tmp_path, "T.class", payload))

    assert result["file_format"] == "JAVA_CLASS"
    assert result["format_category"] == "Bytecode"
    assert result["is_executable"] is True


@pytest.mark.unit
def test_fat_macho_still_detected(tmp_path: Path) -> None:
    # magic + nfat_arch=2 + fat_arch entries (zeros are fine for classification)
    payload = b"\xca\xfe\xba\xbe\x00\x00\x00\x02" + b"\x00" * 64
    result = MagicByteDetector().detect_file_type(_write(tmp_path, "fat.bin", payload))

    assert result["file_format"] == "MACHO_UNIVERSAL"
    assert result["format_category"] == "Executable"


@pytest.mark.unit
def test_little_endian_fat_macho_detected(tmp_path: Path) -> None:
    # swapped magic 0xBEBAFECA + little-endian nfat_arch=3
    payload = b"\xbe\xba\xfe\xca\x03\x00\x00\x00" + b"\x00" * 64
    result = MagicByteDetector().detect_file_type(_write(tmp_path, "fatle.bin", payload))

    assert result["file_format"] == "MACHO_UNIVERSAL"
