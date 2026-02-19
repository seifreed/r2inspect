#!/usr/bin/env python3
"""Branch-path tests for r2inspect/utils/hashing.py.

Missing lines targeted:
15-46 (calculate_hashes), 49-65 (calculate_hashes_for_bytes),
68-92 (calculate_imphash), 95-103 (calculate_ssdeep).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from r2inspect.utils.hashing import (
    calculate_hashes,
    calculate_hashes_for_bytes,
    calculate_imphash,
    calculate_ssdeep,
)


# ---------------------------------------------------------------------------
# calculate_hashes – lines 15-46
# ---------------------------------------------------------------------------


def test_calculate_hashes_returns_all_four_keys(tmp_path: Path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"hello r2inspect")
    result = calculate_hashes(str(f))
    assert set(result.keys()) == {"md5", "sha1", "sha256", "sha512"}


def test_calculate_hashes_values_match_hashlib(tmp_path: Path):
    data = b"deterministic data"
    f = tmp_path / "data.bin"
    f.write_bytes(data)
    result = calculate_hashes(str(f))
    assert result["md5"] == hashlib.md5(data, usedforsecurity=False).hexdigest()
    assert result["sha1"] == hashlib.sha1(data, usedforsecurity=False).hexdigest()
    assert result["sha256"] == hashlib.sha256(data).hexdigest()
    assert result["sha512"] == hashlib.sha512(data).hexdigest()


def test_calculate_hashes_empty_file(tmp_path: Path):
    f = tmp_path / "empty.bin"
    f.write_bytes(b"")
    result = calculate_hashes(str(f))
    assert result["md5"] == hashlib.md5(b"", usedforsecurity=False).hexdigest()
    assert result["sha256"] == hashlib.sha256(b"").hexdigest()


def test_calculate_hashes_large_file_chunked(tmp_path: Path):
    data = b"x" * (8192 * 3 + 100)
    f = tmp_path / "large.bin"
    f.write_bytes(data)
    result = calculate_hashes(str(f))
    assert result["sha256"] == hashlib.sha256(data).hexdigest()
    assert "Error" not in result["sha256"]


def test_calculate_hashes_nonexistent_file_returns_empty_strings():
    result = calculate_hashes("/nonexistent/path/file.bin")
    assert result == {"md5": "", "sha1": "", "sha256": "", "sha512": ""}


def test_calculate_hashes_correct_hex_digest_lengths(tmp_path: Path):
    f = tmp_path / "check.bin"
    f.write_bytes(b"length check")
    result = calculate_hashes(str(f))
    assert len(result["md5"]) == 32
    assert len(result["sha1"]) == 40
    assert len(result["sha256"]) == 64
    assert len(result["sha512"]) == 128


# ---------------------------------------------------------------------------
# calculate_hashes_for_bytes – lines 49-65
# ---------------------------------------------------------------------------


def test_calculate_hashes_for_bytes_default_keys():
    result = calculate_hashes_for_bytes(b"test")
    assert set(result.keys()) == {"md5", "sha1", "sha256"}


def test_calculate_hashes_for_bytes_include_sha512():
    result = calculate_hashes_for_bytes(b"test", include_sha512=True)
    assert "sha512" in result
    assert len(result["sha512"]) == 128


def test_calculate_hashes_for_bytes_values_correct():
    data = b"r2inspect bytes"
    result = calculate_hashes_for_bytes(data)
    assert result["md5"] == hashlib.md5(data, usedforsecurity=False).hexdigest()
    assert result["sha1"] == hashlib.sha1(data, usedforsecurity=False).hexdigest()
    assert result["sha256"] == hashlib.sha256(data).hexdigest()


def test_calculate_hashes_for_bytes_empty_data():
    result = calculate_hashes_for_bytes(b"")
    assert result["md5"] == hashlib.md5(b"", usedforsecurity=False).hexdigest()


def test_calculate_hashes_for_bytes_sha512_not_present_by_default():
    result = calculate_hashes_for_bytes(b"data")
    assert "sha512" not in result


def test_calculate_hashes_for_bytes_sha512_value_correct():
    data = b"sha512 test"
    result = calculate_hashes_for_bytes(data, include_sha512=True)
    assert result["sha512"] == hashlib.sha512(data).hexdigest()


# ---------------------------------------------------------------------------
# calculate_imphash – lines 68-92
# ---------------------------------------------------------------------------


def test_calculate_imphash_empty_list_returns_none():
    assert calculate_imphash([]) is None


def test_calculate_imphash_no_lib_func_returns_none():
    imports = [{"other": "field"}, {"also": "missing"}]
    assert calculate_imphash(imports) is None


def test_calculate_imphash_matches_expected_md5():
    imports = [
        {"library": "KERNEL32.DLL", "name": "CreateFileW"},
        {"library": "USER32.DLL", "name": "MessageBoxA"},
    ]
    import_string = "kernel32.dll.createfilew,user32.dll.messageboxa"
    expected = hashlib.md5(import_string.encode(), usedforsecurity=False).hexdigest()
    assert calculate_imphash(imports) == expected


def test_calculate_imphash_single_import():
    imports = [{"library": "ntdll.dll", "name": "NtCreateFile"}]
    result = calculate_imphash(imports)
    assert result is not None
    assert len(result) == 32


def test_calculate_imphash_skips_entries_with_missing_lib_or_name():
    imports = [
        {"library": "kernel32.dll"},
        {"name": "ReadFile"},
        {"library": "user32.dll", "name": "MessageBoxA"},
    ]
    result = calculate_imphash(imports)
    assert result is not None
    import_string = "user32.dll.messageboxa"
    expected = hashlib.md5(import_string.encode(), usedforsecurity=False).hexdigest()
    assert result == expected


def test_calculate_imphash_lowercases_lib_and_name():
    imports_lower = [{"library": "kernel32.dll", "name": "createfilea"}]
    imports_upper = [{"library": "KERNEL32.DLL", "name": "CreateFileA"}]
    assert calculate_imphash(imports_lower) == calculate_imphash(imports_upper)


# ---------------------------------------------------------------------------
# calculate_ssdeep – lines 95-103
# ---------------------------------------------------------------------------


def test_calculate_ssdeep_returns_string_or_none(tmp_path: Path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"A" * 4096)
    result = calculate_ssdeep(str(f))
    assert result is None or isinstance(result, str)


def test_calculate_ssdeep_nonexistent_file_returns_none():
    result = calculate_ssdeep("/nonexistent/file.bin")
    assert result is None
