from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.utils import hashing


@pytest.mark.unit
def test_calculate_hashes_and_imphash(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc")

    hashes = hashing.calculate_hashes(str(sample))
    assert hashes["md5"]
    assert hashes["sha1"]

    missing = hashing.calculate_hashes(str(tmp_path / "missing.bin"))
    assert missing["md5"] == ""

    imports = [{"library": "KERNEL32.dll", "name": "CreateFileA"}]
    assert hashing.calculate_imphash(imports) is not None
    assert hashing.calculate_imphash([]) is None

    # Invalid import entries should return None
    assert hashing.calculate_imphash([{"library": "", "name": ""}]) is None


@pytest.mark.unit
def test_calculate_ssdeep_handles_missing_library(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abcd")
    result = hashing.calculate_ssdeep(str(sample))
    assert result is None or isinstance(result, str)
