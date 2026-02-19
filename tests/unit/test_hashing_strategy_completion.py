from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.abstractions.hashing_strategy import (
    HashingStrategy,
    R2HashingStrategy,
)


class TestHashingStrategy(HashingStrategy):
    def __init__(self, *args, **kwargs):
        self.lib_available = kwargs.pop("lib_available", True)
        self.lib_error = kwargs.pop("lib_error", None)
        self.hash_error = kwargs.pop("hash_error", None)
        super().__init__(*args, **kwargs)

    def _check_library_availability(self) -> tuple[bool, str | None]:
        return self.lib_available, self.lib_error

    def _calculate_hash(self) -> tuple[str | None, str | None, str | None]:
        if self.hash_error:
            return None, None, self.hash_error
        return "testhash123", "test_method", None

    def _get_hash_type(self) -> str:
        return "test_hash"

    @staticmethod
    def compare_hashes(hash1: str, hash2: str) -> int | None:
        if not hash1 or not hash2:
            return None
        return 0 if hash1 == hash2 else 1

    @staticmethod
    def is_available() -> bool:
        return True


def test_hashing_strategy_successful_analysis(tmp_path: Path) -> None:
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"test content")

    strategy = TestHashingStrategy(str(test_file))
    result = strategy.analyze()

    assert result["available"] is True
    assert result["hash_type"] == "test_hash"
    assert result["hash_value"] == "testhash123"
    assert result["method_used"] == "test_method"
    assert result["file_size"] == 12
    assert result["error"] is None
    assert result["execution_time"] > 0


def test_hashing_strategy_library_unavailable(tmp_path: Path) -> None:
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"test")

    strategy = TestHashingStrategy(
        str(test_file), lib_available=False, lib_error="Library not found"
    )
    result = strategy.analyze()

    assert result["available"] is False
    assert result["error"] == "Library not found"
    assert result["hash_value"] is None


def test_hashing_strategy_library_unavailable_no_error_message(tmp_path: Path) -> None:
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"test")

    strategy = TestHashingStrategy(str(test_file), lib_available=False)
    result = strategy.analyze()

    assert result["available"] is False
    assert result["error"] == "Required library not available"


def test_hashing_strategy_hash_calculation_error(tmp_path: Path) -> None:
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"test")

    strategy = TestHashingStrategy(str(test_file), hash_error="Hash computation failed")
    result = strategy.analyze()

    assert result["available"] is True
    assert result["error"] == "Hash computation failed"
    assert result["hash_value"] is None


def test_hashing_strategy_unexpected_exception(tmp_path: Path, monkeypatch) -> None:
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"test")

    strategy = TestHashingStrategy(str(test_file))

    def failing_check():
        raise RuntimeError("Unexpected error")

    monkeypatch.setattr(strategy, "_check_library_availability", failing_check)
    result = strategy.analyze()

    assert "Unexpected error in test_hash analysis" in result["error"]
    assert result["execution_time"] > 0


def test_hashing_strategy_file_not_found() -> None:
    strategy = TestHashingStrategy("/nonexistent/file.bin")
    result = strategy.analyze()

    assert result["available"] is False
    assert "does not exist" in result["error"]


def test_hashing_strategy_directory_not_file(tmp_path: Path) -> None:
    test_dir = tmp_path / "test_dir"
    test_dir.mkdir()

    strategy = TestHashingStrategy(str(test_dir))
    result = strategy.analyze()

    assert result["available"] is False
    assert "not a regular file" in result["error"]


def test_hashing_strategy_file_too_small(tmp_path: Path) -> None:
    test_file = tmp_path / "tiny.bin"
    test_file.write_bytes(b"x")

    strategy = TestHashingStrategy(str(test_file), min_file_size=10)
    result = strategy.analyze()

    assert result["available"] is False
    assert "too small" in result["error"]
    assert "1 bytes" in result["error"]
    assert "minimum: 10 bytes" in result["error"]


def test_hashing_strategy_file_too_large(tmp_path: Path) -> None:
    test_file = tmp_path / "large.bin"
    test_file.write_bytes(b"x" * 1000)

    strategy = TestHashingStrategy(str(test_file), max_file_size=100)
    result = strategy.analyze()

    assert result["available"] is False
    assert "too large" in result["error"]
    assert "1000 bytes" in result["error"]
    assert "maximum: 100 bytes" in result["error"]


def test_hashing_strategy_file_access_error(tmp_path: Path, monkeypatch) -> None:
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"test")

    strategy = TestHashingStrategy(str(test_file))

    import os

    def mock_access(path, mode):
        return False

    monkeypatch.setattr(os, "access", mock_access)

    result = strategy.analyze()

    assert result["available"] is False
    assert "not readable" in result["error"]


def test_hashing_strategy_os_error_on_stat() -> None:
    test_file = "/tmp/nonexistent_for_test.bin"

    strategy = TestHashingStrategy(test_file)

    result = strategy.analyze()

    assert result["available"] is False
    assert "does not exist" in result["error"]


def test_hashing_strategy_get_file_size_success(tmp_path: Path) -> None:
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"test content")

    strategy = TestHashingStrategy(str(test_file))
    size = strategy.get_file_size()

    assert size == 12


def test_hashing_strategy_get_file_size_error(monkeypatch) -> None:
    strategy = TestHashingStrategy("/nonexistent/file.bin")
    size = strategy.get_file_size()

    assert size is None


def test_hashing_strategy_get_file_extension(tmp_path: Path) -> None:
    test_file = tmp_path / "sample.TXT"
    test_file.write_bytes(b"test")

    strategy = TestHashingStrategy(str(test_file))
    ext = strategy.get_file_extension()

    assert ext == "txt"


def test_hashing_strategy_get_file_extension_no_extension(tmp_path: Path) -> None:
    test_file = tmp_path / "noext"
    test_file.write_bytes(b"test")

    strategy = TestHashingStrategy(str(test_file))
    ext = strategy.get_file_extension()

    assert ext == ""


def test_hashing_strategy_str_representation(tmp_path: Path) -> None:
    test_file = tmp_path / "sample.bin"
    test_file.write_bytes(b"test")

    strategy = TestHashingStrategy(str(test_file))
    str_repr = str(strategy)

    assert "TestHashingStrategy" in str_repr
    assert "type=test_hash" in str_repr
    assert "file=sample.bin" in str_repr


def test_hashing_strategy_repr_representation(tmp_path: Path) -> None:
    test_file = tmp_path / "sample.bin"
    test_file.write_bytes(b"test")

    strategy = TestHashingStrategy(
        str(test_file), max_file_size=50000, min_file_size=5
    )
    repr_str = repr(strategy)

    assert "TestHashingStrategy" in repr_str
    assert "filepath=" in repr_str
    assert "max_file_size=50000" in repr_str
    assert "min_file_size=5" in repr_str


def test_hashing_strategy_compare_hashes() -> None:
    assert TestHashingStrategy.compare_hashes("abc", "abc") == 0
    assert TestHashingStrategy.compare_hashes("abc", "def") == 1
    assert TestHashingStrategy.compare_hashes("", "abc") is None
    assert TestHashingStrategy.compare_hashes("abc", "") is None


def test_hashing_strategy_is_available() -> None:
    assert TestHashingStrategy.is_available() is True


def test_r2_hashing_strategy_initialization(tmp_path: Path) -> None:
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"test")

    class MockAdapter:
        pass

    adapter = MockAdapter()

    class TestR2Hash(R2HashingStrategy):
        def _check_library_availability(self) -> tuple[bool, str | None]:
            return True, None

        def _calculate_hash(self) -> tuple[str | None, str | None, str | None]:
            return "r2hash", "r2", None

        def _get_hash_type(self) -> str:
            return "r2_hash"

        @staticmethod
        def compare_hashes(hash1: str, hash2: str) -> int | None:
            return 0

        @staticmethod
        def is_available() -> bool:
            return True

    strategy = TestR2Hash(adapter, str(test_file), max_file_size=1000, min_file_size=1)

    assert strategy.adapter is adapter
    assert strategy.r2 is adapter
    assert strategy.filepath == Path(test_file)
    assert strategy.max_file_size == 1000
    assert strategy.min_file_size == 1


def test_r2_hashing_strategy_inherits_validation(tmp_path: Path) -> None:
    class MockAdapter:
        pass

    adapter = MockAdapter()

    class TestR2Hash(R2HashingStrategy):
        def _check_library_availability(self) -> tuple[bool, str | None]:
            return True, None

        def _calculate_hash(self) -> tuple[str | None, str | None, str | None]:
            return "r2hash", "r2", None

        def _get_hash_type(self) -> str:
            return "r2_hash"

        @staticmethod
        def compare_hashes(hash1: str, hash2: str) -> int | None:
            return 0

        @staticmethod
        def is_available() -> bool:
            return True

    strategy = TestR2Hash(adapter, "/nonexistent/file.bin")
    result = strategy.analyze()

    assert result["available"] is False
    assert "does not exist" in result["error"]


def test_hashing_strategy_init_validation_empty_filepath() -> None:
    with pytest.raises(ValueError, match="filepath cannot be empty"):
        TestHashingStrategy("")


def test_hashing_strategy_init_validation_negative_max_size() -> None:
    with pytest.raises(ValueError, match="File size limits must be positive"):
        TestHashingStrategy("test.bin", max_file_size=-1)


def test_hashing_strategy_init_validation_negative_min_size() -> None:
    with pytest.raises(ValueError, match="File size limits must be positive"):
        TestHashingStrategy("test.bin", min_file_size=-1)


def test_hashing_strategy_init_validation_min_greater_than_max() -> None:
    with pytest.raises(ValueError, match="min_file_size cannot exceed max_file_size"):
        TestHashingStrategy("test.bin", min_file_size=100, max_file_size=50)
