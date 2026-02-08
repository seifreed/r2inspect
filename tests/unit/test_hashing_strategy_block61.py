from __future__ import annotations

import os
from pathlib import Path

import pytest

from r2inspect.abstractions.hashing_strategy import HashingStrategy


class _DummyHash(HashingStrategy):
    def _check_library_availability(self):
        return True, None

    def _calculate_hash(self):
        return "deadbeef", "dummy", None

    def _get_hash_type(self):
        return "dummy"

    @staticmethod
    def compare_hashes(hash1: str, hash2: str):
        if not hash1 or not hash2:
            return None
        return 0 if hash1 == hash2 else 1

    @staticmethod
    def is_available() -> bool:
        return True


def test_hashing_strategy_stat_error(tmp_path: Path):
    data = tmp_path / "data.bin"
    data.write_bytes(b"hello")

    # Remove permissions from parent dir to trigger stat error
    os.chmod(tmp_path, 0)
    try:
        analyzer = _DummyHash(str(data))
        err = analyzer._validate_file()
        assert err is not None
        assert "Cannot access file statistics" in err
    finally:
        os.chmod(tmp_path, 0o700)


def test_hashing_strategy_analyze_success(tmp_path: Path):
    data = tmp_path / "data.bin"
    data.write_bytes(b"hello")
    analyzer = _DummyHash(str(data))
    result = analyzer.analyze()
    assert result["hash_value"] == "deadbeef"
