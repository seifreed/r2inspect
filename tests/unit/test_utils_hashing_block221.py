from __future__ import annotations

import hashlib
from pathlib import Path

from r2inspect.utils.hashing import calculate_hashes, calculate_imphash, calculate_ssdeep


def test_calculate_hashes(tmp_path: Path) -> None:
    path = tmp_path / "sample.bin"
    data = b"r2inspect"
    path.write_bytes(data)

    hashes = calculate_hashes(str(path))
    assert hashes["md5"] == hashlib.md5(data, usedforsecurity=False).hexdigest()
    assert hashes["sha1"] == hashlib.sha1(data, usedforsecurity=False).hexdigest()
    assert hashes["sha256"] == hashlib.sha256(data).hexdigest()
    assert hashes["sha512"] == hashlib.sha512(data).hexdigest()

    missing = calculate_hashes(str(tmp_path / "missing.bin"))
    assert all(value == "" for value in missing.values())


def test_calculate_imphash_and_ssdeep(tmp_path: Path) -> None:
    imports = [
        {"library": "KERNEL32.dll", "name": "CreateFileA"},
        {"library": "USER32.dll", "name": "MessageBoxA"},
    ]
    imphash = calculate_imphash(imports)
    assert isinstance(imphash, str)
    assert calculate_imphash([]) is None

    path = tmp_path / "sample.bin"
    path.write_bytes(b"r2inspect")
    ssdeep = calculate_ssdeep(str(path))
    assert ssdeep is None or isinstance(ssdeep, str)
