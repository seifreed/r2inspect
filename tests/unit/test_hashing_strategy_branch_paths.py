from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.abstractions.hashing_strategy import HashingStrategy, R2HashingStrategy


class _AlwaysAvailableHash(HashingStrategy):
    def _check_library_availability(self) -> tuple[bool, str | None]:
        return True, None

    def _calculate_hash(self) -> tuple[str | None, str | None, str | None]:
        return "deadbeef", "test_lib", None

    def _get_hash_type(self) -> str:
        return "test"

    @staticmethod
    def compare_hashes(hash1: str, hash2: str) -> int | None:
        if not hash1 or not hash2:
            return None
        return 0 if hash1 == hash2 else 1

    @staticmethod
    def is_available() -> bool:
        return True


class _UnavailableHash(HashingStrategy):
    def _check_library_availability(self) -> tuple[bool, str | None]:
        return False, "test library not installed"

    def _calculate_hash(self) -> tuple[str | None, str | None, str | None]:
        return None, None, "unavailable"

    def _get_hash_type(self) -> str:
        return "unavail"

    @staticmethod
    def compare_hashes(hash1: str, hash2: str) -> int | None:
        return None

    @staticmethod
    def is_available() -> bool:
        return False


class _ErrorCalcHash(HashingStrategy):
    def _check_library_availability(self) -> tuple[bool, str | None]:
        return True, None

    def _calculate_hash(self) -> tuple[str | None, str | None, str | None]:
        return None, None, "calculation failed"

    def _get_hash_type(self) -> str:
        return "errored"

    @staticmethod
    def compare_hashes(hash1: str, hash2: str) -> int | None:
        return None

    @staticmethod
    def is_available() -> bool:
        return True


def test_empty_filepath_raises() -> None:
    with pytest.raises(ValueError, match="filepath cannot be empty"):
        _AlwaysAvailableHash("")


def test_invalid_size_limits_raise() -> None:
    with pytest.raises(ValueError):
        _AlwaysAvailableHash("x", max_file_size=0)

    with pytest.raises(ValueError):
        _AlwaysAvailableHash("x", min_file_size=-1)

    with pytest.raises(ValueError):
        _AlwaysAvailableHash("x", min_file_size=10, max_file_size=5)


def test_nonexistent_file_returns_error(tmp_path: Path) -> None:
    strategy = _AlwaysAvailableHash(str(tmp_path / "missing.bin"))
    result = strategy.analyze()
    assert result["available"] is False
    assert "does not exist" in result["error"]


def test_path_is_directory_returns_error(tmp_path: Path) -> None:
    strategy = _AlwaysAvailableHash(str(tmp_path))
    result = strategy.analyze()
    assert result["available"] is False
    assert "not a regular file" in result["error"]


def test_file_too_small_returns_error(tmp_path: Path) -> None:
    tiny = tmp_path / "tiny.bin"
    tiny.write_bytes(b"x")
    strategy = _AlwaysAvailableHash(str(tiny), min_file_size=10)
    result = strategy.analyze()
    assert result["available"] is False
    assert "too small" in result["error"]


def test_file_too_large_returns_error(tmp_path: Path) -> None:
    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * 100)
    strategy = _AlwaysAvailableHash(str(big), max_file_size=10)
    result = strategy.analyze()
    assert result["available"] is False
    assert "too large" in result["error"]


def test_library_unavailable_returns_error(tmp_path: Path) -> None:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"data" * 100)
    strategy = _UnavailableHash(str(path))
    result = strategy.analyze()
    assert result["available"] is False
    assert "test library not installed" in result["error"]


def test_calculation_error_stored_in_result(tmp_path: Path) -> None:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"data" * 100)
    strategy = _ErrorCalcHash(str(path))
    result = strategy.analyze()
    assert result["available"] is True
    assert result["error"] == "calculation failed"
    assert result["hash_value"] is None


def test_successful_analysis_result(tmp_path: Path) -> None:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"data" * 100)
    strategy = _AlwaysAvailableHash(str(path))
    result = strategy.analyze()
    assert result["available"] is True
    assert result["hash_value"] == "deadbeef"
    assert result["method_used"] == "test_lib"
    assert result["hash_type"] == "test"
    assert result["execution_time"] >= 0


def test_get_file_size_returns_bytes(tmp_path: Path) -> None:
    path = tmp_path / "sized.bin"
    path.write_bytes(b"a" * 42)
    strategy = _AlwaysAvailableHash(str(path))
    assert strategy.get_file_size() == 42


def test_get_file_size_nonexistent_returns_none(tmp_path: Path) -> None:
    strategy = _AlwaysAvailableHash(str(tmp_path / "missing.bin"))
    assert strategy.get_file_size() is None


def test_get_file_extension(tmp_path: Path) -> None:
    path = tmp_path / "sample.exe"
    path.write_bytes(b"x" * 10)
    strategy = _AlwaysAvailableHash(str(path))
    assert strategy.get_file_extension() == "exe"


def test_get_file_extension_no_extension(tmp_path: Path) -> None:
    path = tmp_path / "noext"
    path.write_bytes(b"x" * 10)
    strategy = _AlwaysAvailableHash(str(path))
    assert strategy.get_file_extension() == ""


def test_str_representation(tmp_path: Path) -> None:
    path = tmp_path / "file.bin"
    path.write_bytes(b"x" * 10)
    strategy = _AlwaysAvailableHash(str(path))
    s = str(strategy)
    assert "test" in s
    assert "file.bin" in s


def test_repr_representation(tmp_path: Path) -> None:
    path = tmp_path / "file.bin"
    path.write_bytes(b"x" * 10)
    strategy = _AlwaysAvailableHash(str(path))
    r = repr(strategy)
    assert "filepath" in r
    assert "max_file_size" in r


def test_r2_hashing_strategy_init(tmp_path: Path) -> None:
    class _ConcreteR2Hash(R2HashingStrategy):
        def _check_library_availability(self) -> tuple[bool, str | None]:
            return True, None

        def _calculate_hash(self) -> tuple[str | None, str | None, str | None]:
            return "abc", "r2", None

        def _get_hash_type(self) -> str:
            return "r2hash"

        @staticmethod
        def compare_hashes(hash1: str, hash2: str) -> int | None:
            return None

        @staticmethod
        def is_available() -> bool:
            return True

    path = tmp_path / "file.bin"
    path.write_bytes(b"x" * 10)

    class _FakeAdapter:
        def cmd(self, _: str) -> str:
            return ""

        def cmdj(self, _: str) -> dict:
            return {}

    adapter = _FakeAdapter()
    strategy = _ConcreteR2Hash(adapter=adapter, filepath=str(path))
    assert strategy.adapter is adapter
    assert strategy.r2 is adapter
    result = strategy.analyze()
    assert result["hash_value"] == "abc"
