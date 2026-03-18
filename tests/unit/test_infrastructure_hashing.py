"""Canonical import tests for infrastructure hashing helpers."""

from pathlib import Path

from r2inspect.infrastructure.hashing import calculate_hashes


def test_infrastructure_hashing_calculates_file_hashes(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc")

    hashes = calculate_hashes(str(sample))

    assert hashes["md5"]
    assert hashes["sha256"]
