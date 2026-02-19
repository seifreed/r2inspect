#!/usr/bin/env python3
"""Tests for utils/hashing.py"""

from __future__ import annotations

import hashlib
from pathlib import Path

from r2inspect.utils import hashing


def test_calculate_hashes_basic(tmp_path: Path):
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"test data")
    
    result = hashing.calculate_hashes(str(test_file))
    
    assert "md5" in result
    assert "sha1" in result
    assert "sha256" in result
    assert "sha512" in result
    assert len(result["md5"]) == 32
    assert len(result["sha1"]) == 40
    assert len(result["sha256"]) == 64
    assert len(result["sha512"]) == 128


def test_calculate_hashes_empty_file(tmp_path: Path):
    test_file = tmp_path / "empty.bin"
    test_file.write_bytes(b"")
    
    result = hashing.calculate_hashes(str(test_file))
    
    assert result["md5"] == hashlib.md5(b"", usedforsecurity=False).hexdigest()
    assert result["sha256"] == hashlib.sha256(b"").hexdigest()


def test_calculate_hashes_large_file(tmp_path: Path):
    test_file = tmp_path / "large.bin"
    test_file.write_bytes(b"x" * 100000)
    
    result = hashing.calculate_hashes(str(test_file))
    
    assert len(result["sha256"]) == 64
    assert "Error" not in result["sha256"]


def test_calculate_hashes_nonexistent_file():
    result = hashing.calculate_hashes("/nonexistent/file.bin")
    
    assert result["md5"] == ""
    assert result["sha1"] == ""
    assert result["sha256"] == ""
    assert result["sha512"] == ""


def test_calculate_hashes_for_bytes_basic():
    data = b"test data"
    
    result = hashing.calculate_hashes_for_bytes(data)
    
    assert "md5" in result
    assert "sha1" in result
    assert "sha256" in result
    assert "sha512" not in result
    assert len(result["md5"]) == 32
    assert len(result["sha1"]) == 40
    assert len(result["sha256"]) == 64


def test_calculate_hashes_for_bytes_with_sha512():
    data = b"test data"
    
    result = hashing.calculate_hashes_for_bytes(data, include_sha512=True)
    
    assert "sha512" in result
    assert len(result["sha512"]) == 128


def test_calculate_hashes_for_bytes_empty():
    data = b""
    
    result = hashing.calculate_hashes_for_bytes(data)
    
    assert result["md5"] == hashlib.md5(b"", usedforsecurity=False).hexdigest()
    assert result["sha256"] == hashlib.sha256(b"").hexdigest()


def test_calculate_imphash_basic():
    imports = [
        {"library": "kernel32.dll", "name": "CreateFileA"},
        {"library": "KERNEL32.DLL", "name": "ReadFile"},
    ]
    
    result = hashing.calculate_imphash(imports)
    
    assert result is not None
    assert len(result) == 32


def test_calculate_imphash_empty_list():
    result = hashing.calculate_imphash([])
    
    assert result is None


def test_calculate_imphash_no_library():
    imports = [
        {"name": "CreateFileA"},
    ]
    
    result = hashing.calculate_imphash(imports)
    
    assert result is None


def test_calculate_imphash_no_name():
    imports = [
        {"library": "kernel32.dll"},
    ]
    
    result = hashing.calculate_imphash(imports)
    
    assert result is None


def test_calculate_imphash_mixed():
    imports = [
        {"library": "kernel32.dll", "name": "CreateFileA"},
        {"library": "", "name": "ReadFile"},
        {"library": "user32.dll", "name": ""},
        {"library": "advapi32.dll", "name": "RegOpenKeyA"},
    ]
    
    result = hashing.calculate_imphash(imports)
    
    assert result is not None
    assert len(result) == 32


def test_calculate_imphash_case_insensitive():
    imports1 = [{"library": "KERNEL32.DLL", "name": "CreateFileA"}]
    imports2 = [{"library": "kernel32.dll", "name": "createfilea"}]
    
    result1 = hashing.calculate_imphash(imports1)
    result2 = hashing.calculate_imphash(imports2)
    
    assert result1 == result2


def test_calculate_imphash_exception():
    imports = [{"library": None, "name": None}]
    
    result = hashing.calculate_imphash(imports)
    
    assert result is None


def test_calculate_ssdeep_no_module(monkeypatch):
    import sys
    
    original = sys.modules.get("ssdeep")
    monkeypatch.setitem(sys.modules, "ssdeep", None)
    
    from r2inspect.utils import ssdeep_loader
    ssdeep_loader._ssdeep_module = None
    
    result = hashing.calculate_ssdeep("/test.exe")
    
    assert result is None
    
    if original is not None:
        sys.modules["ssdeep"] = original


def test_calculate_ssdeep_exception(tmp_path: Path):
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"test")
    
    result = hashing.calculate_ssdeep(str(test_file))
    
    assert result is None or isinstance(result, str)
