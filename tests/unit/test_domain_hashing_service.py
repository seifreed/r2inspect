"""Unit tests for domain/services/hashing.py."""

from __future__ import annotations

from r2inspect.domain.services.hashing import (
    calculate_hashes_for_bytes,
    calculate_imphash,
)


def test_calculate_hashes_for_bytes_basic() -> None:
    data = b"hello world"
    result = calculate_hashes_for_bytes(data)
    assert "md5" in result
    assert "sha1" in result
    assert "sha256" in result
    assert len(result["md5"]) == 32
    assert len(result["sha1"]) == 40
    assert len(result["sha256"]) == 64


def test_calculate_hashes_for_bytes_with_sha512() -> None:
    data = b"hello world"
    result = calculate_hashes_for_bytes(data, include_sha512=True)
    assert "sha512" in result
    assert len(result["sha512"]) == 128


def test_calculate_hashes_for_bytes_deterministic() -> None:
    data = b"test data"
    result1 = calculate_hashes_for_bytes(data)
    result2 = calculate_hashes_for_bytes(data)
    assert result1["md5"] == result2["md5"]
    assert result1["sha1"] == result2["sha1"]
    assert result1["sha256"] == result2["sha256"]


def test_calculate_hashes_for_bytes_empty() -> None:
    result = calculate_hashes_for_bytes(b"")
    assert result["md5"] == "d41d8cd98f00b204e9800998ecf8427e"
    assert result["sha1"] == "da39a3ee5e6b4b0d3255bfef95601890afd80709"


def test_calculate_imphash_basic() -> None:
    imports = [
        {"library": "kernel32.dll", "name": "CreateFile"},
        {"library": "kernel32.dll", "name": "ReadFile"},
    ]
    result = calculate_imphash(imports)
    assert result is not None
    assert len(result) == 32


def test_calculate_imphash_empty() -> None:
    assert calculate_imphash([]) is None


def test_calculate_imphash_none() -> None:
    assert calculate_imphash(None) is None  # type: ignore


def test_calculate_imphash_with_dll_key() -> None:
    imports = [
        {"dll": "kernel32.dll", "name": "CreateFile"},
    ]
    result = calculate_imphash(imports)
    assert result is not None


def test_calculate_imphash_with_libname_key() -> None:
    imports = [
        {"libname": "kernel32.dll", "name": "CreateFile"},
    ]
    result = calculate_imphash(imports)
    assert result is not None


def test_calculate_imphash_deterministic() -> None:
    imports = [
        {"library": "kernel32.dll", "name": "CreateFile"},
        {"library": "kernel32.dll", "name": "ReadFile"},
    ]
    result1 = calculate_imphash(imports)
    result2 = calculate_imphash(imports)
    assert result1 == result2


def test_calculate_imphash_missing_name() -> None:
    imports = [
        {"library": "kernel32.dll"},
    ]
    result = calculate_imphash(imports)
    assert result is None


def test_calculate_imphash_missing_library() -> None:
    imports = [
        {"name": "CreateFile"},
    ]
    result = calculate_imphash(imports)
    assert result is None
