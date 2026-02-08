from __future__ import annotations

from pathlib import Path

from r2inspect.abstractions.base_analyzer import BaseAnalyzer
from r2inspect.abstractions.hashing_strategy import HashingStrategy


class DummyAnalyzer(BaseAnalyzer):
    def analyze(self) -> dict[str, object]:
        return self._init_result_structure({"data": "ok", "available": True})

    def get_category(self) -> str:
        return "metadata"


class DummyHash(HashingStrategy):
    def __init__(
        self,
        filepath: str,
        available: bool = True,
        hash_error: str | None = None,
        **kwargs,
    ):
        super().__init__(filepath, **kwargs)
        self._available = available
        self._hash_error = hash_error

    def _check_library_availability(self) -> tuple[bool, str | None]:
        return self._available, None if self._available else "library missing"

    def _calculate_hash(self) -> tuple[str | None, str | None, str | None]:
        if self._hash_error:
            return None, None, self._hash_error
        return "deadbeef", "dummy", None

    def _get_hash_type(self) -> str:
        return "dummy"

    def compare_hashes(self, _hash1: str, _hash2: str) -> float:
        return 1.0

    @classmethod
    def is_available(cls) -> bool:
        return True


def test_base_analyzer_helpers(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abcd")

    analyzer = DummyAnalyzer(filepath=sample)
    result = analyzer.analyze()
    assert result["analyzer"] == "dummy"
    assert analyzer.get_category() == "metadata"
    assert analyzer.get_file_size() == 4
    assert analyzer.get_file_extension() == "bin"
    assert analyzer.file_exists()
    assert "DummyAnalyzer" in repr(analyzer)
    assert "DummyAnalyzer" in str(analyzer)


def test_measure_execution_time_sets_field() -> None:
    analyzer = DummyAnalyzer()

    @analyzer._measure_execution_time
    def _run():
        return {"available": True}

    result = _run()
    assert "execution_time" in result
    assert result["execution_time"] >= 0.0


def test_hashing_strategy_validation_and_flow(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abcd")

    analyzer = DummyHash(str(sample))
    result = analyzer.analyze()
    assert result["available"] is True
    assert result["hash_value"] == "deadbeef"
    assert result["method_used"] == "dummy"


def test_hashing_strategy_validation_errors(tmp_path: Path) -> None:
    missing = tmp_path / "missing.bin"
    analyzer = DummyHash(str(missing))
    result = analyzer.analyze()
    assert result["available"] is False
    assert "does not exist" in result["error"]

    too_small = tmp_path / "small.bin"
    too_small.write_bytes(b"")
    analyzer_small = DummyHash(str(too_small))
    result_small = analyzer_small.analyze()
    assert result_small["available"] is False
    assert "File too small" in result_small["error"]

    too_big = tmp_path / "big.bin"
    too_big.write_bytes(b"1234")
    analyzer_big = DummyHash(str(too_big), max_file_size=1)
    result_big = analyzer_big.analyze()
    assert result_big["available"] is False
    assert "File too large" in result_big["error"]

    analyzer_unavailable = DummyHash(str(too_big), available=False)
    result_unavailable = analyzer_unavailable.analyze()
    assert result_unavailable["available"] is False
    assert "library missing" in result_unavailable["error"]

    analyzer_error = DummyHash(str(too_big), hash_error="boom")
    result_error = analyzer_error.analyze()
    assert result_error["available"] is True
    assert result_error["error"] == "boom"
