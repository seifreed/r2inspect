from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.abstractions.hashing_strategy import HashingStrategy


class DemoHashing(HashingStrategy):
    def _check_library_availability(self) -> tuple[bool, str | None]:
        return True, None

    def _calculate_hash(self) -> tuple[str | None, str | None, str | None]:
        return "abc", "demo", None

    def _get_hash_type(self) -> str:
        return "demo"

    @staticmethod
    def compare_hashes(hash1: str, hash2: str) -> int | None:
        if not hash1 or not hash2:
            return None
        return 0 if hash1 == hash2 else 1

    @staticmethod
    def is_available() -> bool:
        return True


def test_hashing_strategy_flow(tmp_path: Path) -> None:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"data")
    strategy = DemoHashing(str(path))
    result = strategy.analyze()
    assert result["available"] is True
    assert result["hash_value"] == "abc"
    assert result["method_used"] == "demo"
    assert result["hash_type"] == "demo"
    assert strategy.get_file_extension() == "bin"
    assert strategy.get_file_size() == 4
    assert "demo" in str(strategy)
    assert "filepath" in repr(strategy)


def test_hashing_strategy_validation_errors(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        DemoHashing("")
    with pytest.raises(ValueError):
        DemoHashing("x", max_file_size=0)
    with pytest.raises(ValueError):
        DemoHashing("x", min_file_size=2, max_file_size=1)

    path = tmp_path / "tiny.bin"
    path.write_bytes(b"x")
    strategy = DemoHashing(str(path), min_file_size=2)
    result = strategy.analyze()
    assert result["available"] is False
    assert result["error"]
