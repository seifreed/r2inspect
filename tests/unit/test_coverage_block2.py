import os
from pathlib import Path
from tempfile import NamedTemporaryFile

from r2inspect.abstractions.hashing_strategy import HashingStrategy


class DummyHashingStrategy(HashingStrategy):
    def __init__(self, *args, **kwargs):
        self._library_available = True
        self._library_error = None
        self._hash_value = "deadbeef"
        self._method_used = "dummy"
        self._calc_error = None
        super().__init__(*args, **kwargs)

    def _check_library_availability(self):
        return self._library_available, self._library_error

    def _calculate_hash(self):
        return self._hash_value, self._method_used, self._calc_error

    def _get_hash_type(self):
        return "dummy"

    @staticmethod
    def compare_hashes(hash1: str, hash2: str):
        if not hash1 or not hash2:
            return None
        return 1 if hash1 == hash2 else 2

    @staticmethod
    def is_available() -> bool:
        return True


class ExplodingHashingStrategy(DummyHashingStrategy):
    def _calculate_hash(self):
        raise RuntimeError("boom")


def test_hashing_strategy_constructor_validation(tmp_path: Path):
    try:
        DummyHashingStrategy("")
    except ValueError as exc:
        assert "filepath" in str(exc)
    else:
        raise AssertionError("Expected ValueError for empty filepath")

    try:
        DummyHashingStrategy(str(tmp_path / "file.bin"), max_file_size=0)
    except ValueError as exc:
        assert "File size limits" in str(exc)
    else:
        raise AssertionError("Expected ValueError for invalid size limits")

    try:
        DummyHashingStrategy(str(tmp_path / "file.bin"), min_file_size=10, max_file_size=1)
    except ValueError as exc:
        assert "min_file_size" in str(exc)
    else:
        raise AssertionError("Expected ValueError for min > max")


def test_hashing_strategy_validate_file_errors(tmp_path: Path):
    missing = DummyHashingStrategy(str(tmp_path / "missing.bin"))
    result = missing.analyze()
    assert result["error"] and "does not exist" in result["error"]

    directory = DummyHashingStrategy(str(tmp_path))
    result = directory.analyze()
    assert result["error"] and "not a regular file" in result["error"]

    tiny = tmp_path / "tiny.bin"
    tiny.write_bytes(b"a")
    small = DummyHashingStrategy(str(tiny), min_file_size=10)
    result = small.analyze()
    assert "too small" in (result["error"] or "")


def test_hashing_strategy_size_limits_and_permissions(tmp_path: Path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc")

    too_large = DummyHashingStrategy(str(sample), max_file_size=1)
    result = too_large.analyze()
    assert "too large" in (result["error"] or "")

    unreadable = tmp_path / "unreadable.bin"
    unreadable.write_bytes(b"abc")
    os.chmod(unreadable, 0)
    try:
        blocked = DummyHashingStrategy(str(unreadable))
        result = blocked.analyze()
        assert "not readable" in (result["error"] or "")
    finally:
        os.chmod(unreadable, 0o600)


def test_hashing_strategy_library_and_hash_errors(tmp_path: Path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc")

    unavailable = DummyHashingStrategy(str(sample))
    unavailable._library_available = False
    unavailable._library_error = "missing"
    result = unavailable.analyze()
    assert result["available"] is False
    assert result["error"] == "missing"

    failing = DummyHashingStrategy(str(sample))
    failing._calc_error = "calc failed"
    result = failing.analyze()
    assert result["error"] == "calc failed"

    exploding = ExplodingHashingStrategy(str(sample))
    result = exploding.analyze()
    assert "Unexpected error" in (result["error"] or "")


def test_hashing_strategy_success_and_result_helpers(tmp_path: Path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc")

    analyzer = DummyHashingStrategy(str(sample))
    result = analyzer.analyze()
    assert result["available"] is True
    assert result["hash_value"] == "deadbeef"
    assert result["method_used"] == "dummy"
    assert result["file_size"] == 3

    assert analyzer.get_file_size() == 3
    assert analyzer.get_file_extension() == "bin"
    assert "dummy" in str(analyzer)
    assert "DummyHashingStrategy" in repr(analyzer)

    assert DummyHashingStrategy.compare_hashes("a", "a") == 1
    assert DummyHashingStrategy.compare_hashes("a", "b") == 2
    assert DummyHashingStrategy.compare_hashes("", "b") is None
    assert DummyHashingStrategy.is_available() is True
