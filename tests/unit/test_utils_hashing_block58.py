from __future__ import annotations

import os
from pathlib import Path

import pytest

from r2inspect.utils.hashing import calculate_hashes, calculate_imphash, calculate_ssdeep


def test_calculate_hashes_success(tmp_path: Path):
    file_path = tmp_path / "data.bin"
    file_path.write_bytes(b"hello")

    hashes = calculate_hashes(str(file_path))
    assert hashes["md5"]
    assert hashes["sha1"]
    assert hashes["sha256"]
    assert hashes["sha512"]


def test_calculate_hashes_error(tmp_path: Path):
    file_path = tmp_path / "secret.bin"
    file_path.write_bytes(b"secret")
    # Remove read permissions to trigger error on open
    os.chmod(file_path, 0)
    try:
        hashes = calculate_hashes(str(file_path))
        assert hashes["md5"].startswith("Error:")
    finally:
        os.chmod(file_path, 0o600)


def test_calculate_imphash():
    imports = [
        {"library": "KERNEL32.dll", "name": "CreateFileA"},
        {"library": "USER32.dll", "name": "MessageBoxA"},
    ]
    imphash = calculate_imphash(imports)
    assert imphash is not None

    assert calculate_imphash([]) is None
    assert calculate_imphash([{"library": "", "name": ""}]) is None


def test_calculate_ssdeep_optional(tmp_path: Path):
    file_path = tmp_path / "data.bin"
    file_path.write_bytes(b"hello")
    # If ssdeep is unavailable, function returns None
    _ = calculate_ssdeep(str(file_path))
