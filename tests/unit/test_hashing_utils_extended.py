"""Extended comprehensive tests for r2inspect/utils/hashing.py (12% coverage)"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from r2inspect.utils.hashing import (
    calculate_hashes,
    calculate_hashes_for_bytes,
    calculate_imphash,
    calculate_ssdeep,
)


def test_calculate_hashes_large_file(tmp_path: Path):
    test_file = tmp_path / "large.bin"
    large_data = b"A" * 100000
    test_file.write_bytes(large_data)
    
    hashes = calculate_hashes(str(test_file))
    
    assert hashes["md5"] == hashlib.md5(large_data, usedforsecurity=False).hexdigest()
    assert hashes["sha256"] == hashlib.sha256(large_data).hexdigest()


def test_calculate_hashes_binary_content(tmp_path: Path):
    test_file = tmp_path / "binary.bin"
    binary_data = bytes(range(256))
    test_file.write_bytes(binary_data)
    
    hashes = calculate_hashes(str(test_file))
    
    assert len(hashes["md5"]) == 32
    assert len(hashes["sha1"]) == 40
    assert len(hashes["sha256"]) == 64
    assert len(hashes["sha512"]) == 128


def test_calculate_hashes_permission_error(tmp_path: Path):
    test_file = tmp_path / "noaccess.bin"
    test_file.write_bytes(b"secret data")
    os.chmod(test_file, 0o000)
    
    try:
        hashes = calculate_hashes(str(test_file))
        assert "Error:" in hashes["md5"]
        assert "Error:" in hashes["sha1"]
        assert "Error:" in hashes["sha256"]
        assert "Error:" in hashes["sha512"]
    finally:
        os.chmod(test_file, 0o644)


def test_calculate_hashes_multiple_chunks(tmp_path: Path):
    test_file = tmp_path / "chunks.bin"
    data = b"X" * (8192 * 3 + 100)
    test_file.write_bytes(data)
    
    hashes = calculate_hashes(str(test_file))
    
    assert hashes["md5"] == hashlib.md5(data, usedforsecurity=False).hexdigest()
    assert hashes["sha256"] == hashlib.sha256(data).hexdigest()


def test_calculate_hashes_for_bytes_basic():
    test_data = b"Test data"
    
    hashes = calculate_hashes_for_bytes(test_data)
    
    assert hashes["md5"] == hashlib.md5(test_data, usedforsecurity=False).hexdigest()
    assert hashes["sha1"] == hashlib.sha1(test_data, usedforsecurity=False).hexdigest()
    assert hashes["sha256"] == hashlib.sha256(test_data).hexdigest()
    assert "sha512" not in hashes


def test_calculate_hashes_for_bytes_with_sha512():
    test_data = b"Test data with sha512"
    
    hashes = calculate_hashes_for_bytes(test_data, include_sha512=True)
    
    assert hashes["md5"] == hashlib.md5(test_data, usedforsecurity=False).hexdigest()
    assert hashes["sha1"] == hashlib.sha1(test_data, usedforsecurity=False).hexdigest()
    assert hashes["sha256"] == hashlib.sha256(test_data).hexdigest()
    assert hashes["sha512"] == hashlib.sha512(test_data).hexdigest()


def test_calculate_hashes_for_bytes_empty():
    test_data = b""
    
    hashes = calculate_hashes_for_bytes(test_data)
    
    assert hashes["md5"] == "d41d8cd98f00b204e9800998ecf8427e"
    assert hashes["sha1"] == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    assert hashes["sha256"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_calculate_hashes_for_bytes_large():
    test_data = b"B" * 1000000
    
    hashes = calculate_hashes_for_bytes(test_data, include_sha512=True)
    
    assert len(hashes["md5"]) == 32
    assert len(hashes["sha1"]) == 40
    assert len(hashes["sha256"]) == 64
    assert len(hashes["sha512"]) == 128


def test_calculate_hashes_for_bytes_binary():
    test_data = bytes(range(256)) * 10
    
    hashes = calculate_hashes_for_bytes(test_data)
    
    assert hashes["md5"] == hashlib.md5(test_data, usedforsecurity=False).hexdigest()
    assert hashes["sha256"] == hashlib.sha256(test_data).hexdigest()


def test_calculate_imphash_missing_library():
    imports = [
        {"library": "", "name": "CreateFileA"},
        {"library": "USER32.dll", "name": "MessageBoxA"},
    ]
    
    imphash = calculate_imphash(imports)
    
    assert imphash is not None
    import_string = "user32.dll.messageboxa"
    expected = hashlib.md5(import_string.encode(), usedforsecurity=False).hexdigest()
    assert imphash == expected


def test_calculate_imphash_missing_name():
    imports = [
        {"library": "KERNEL32.dll", "name": ""},
        {"library": "USER32.dll", "name": "MessageBoxA"},
    ]
    
    imphash = calculate_imphash(imports)
    
    assert imphash is not None
    import_string = "user32.dll.messageboxa"
    expected = hashlib.md5(import_string.encode(), usedforsecurity=False).hexdigest()
    assert imphash == expected


def test_calculate_imphash_case_normalization():
    imports1 = [
        {"library": "KERNEL32.DLL", "name": "CreateFileA"},
    ]
    imports2 = [
        {"library": "kernel32.dll", "name": "createfilea"},
    ]
    
    imphash1 = calculate_imphash(imports1)
    imphash2 = calculate_imphash(imports2)
    
    assert imphash1 == imphash2


def test_calculate_imphash_multiple_imports():
    imports = [
        {"library": "KERNEL32.dll", "name": "CreateFileA"},
        {"library": "KERNEL32.dll", "name": "ReadFile"},
        {"library": "KERNEL32.dll", "name": "WriteFile"},
        {"library": "USER32.dll", "name": "MessageBoxA"},
        {"library": "ADVAPI32.dll", "name": "RegOpenKeyA"},
    ]
    
    imphash = calculate_imphash(imports)
    
    assert imphash is not None
    assert len(imphash) == 32


def test_calculate_imphash_all_empty():
    imports = [
        {"library": "", "name": ""},
        {"library": "", "name": ""},
    ]
    
    imphash = calculate_imphash(imports)
    assert imphash is None


def test_calculate_imphash_missing_keys():
    imports = [
        {},
        {"library": "KERNEL32.dll"},
        {"name": "CreateFileA"},
    ]
    
    imphash = calculate_imphash(imports)
    assert imphash is None


def test_calculate_imphash_exception_handling():
    imports = [
        {"library": None, "name": "CreateFileA"},
    ]
    
    imphash = calculate_imphash(imports)
    assert imphash is None


def test_calculate_ssdeep_nonexistent_file():
    result = calculate_ssdeep("/nonexistent/file.bin")
    assert result is None


def test_calculate_ssdeep_with_file(tmp_path: Path):
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"Test data for ssdeep" * 100)
    
    result = calculate_ssdeep(str(test_file))


def test_calculate_ssdeep_exception_handling(tmp_path: Path):
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"data")
    os.chmod(test_file, 0o000)
    
    try:
        result = calculate_ssdeep(str(test_file))
        assert result is None
    finally:
        os.chmod(test_file, 0o644)


def test_calculate_hashes_special_characters(tmp_path: Path):
    test_file = tmp_path / "special.bin"
    test_data = b"\x00\x01\xff\xfe\x7f\x80\x81"
    test_file.write_bytes(test_data)
    
    hashes = calculate_hashes(str(test_file))
    
    assert hashes["md5"] == hashlib.md5(test_data, usedforsecurity=False).hexdigest()
    assert hashes["sha256"] == hashlib.sha256(test_data).hexdigest()


def test_calculate_hashes_for_bytes_special():
    test_data = b"\x00\x01\xff\xfe\x7f\x80\x81"
    
    hashes = calculate_hashes_for_bytes(test_data, include_sha512=True)
    
    assert hashes["md5"] == hashlib.md5(test_data, usedforsecurity=False).hexdigest()
    assert hashes["sha512"] == hashlib.sha512(test_data).hexdigest()


def test_calculate_imphash_single_import():
    imports = [
        {"library": "KERNEL32.dll", "name": "ExitProcess"},
    ]
    
    imphash = calculate_imphash(imports)
    
    assert imphash is not None
    import_string = "kernel32.dll.exitprocess"
    expected = hashlib.md5(import_string.encode(), usedforsecurity=False).hexdigest()
    assert imphash == expected


def test_calculate_hashes_known_values(tmp_path: Path):
    test_file = tmp_path / "known.txt"
    test_file.write_bytes(b"abc")
    
    hashes = calculate_hashes(str(test_file))
    
    assert hashes["md5"] == "900150983cd24fb0d6963f7d28e17f72"
    assert hashes["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_calculate_hashes_for_bytes_known_values():
    hashes = calculate_hashes_for_bytes(b"abc")
    
    assert hashes["md5"] == "900150983cd24fb0d6963f7d28e17f72"
    assert hashes["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
