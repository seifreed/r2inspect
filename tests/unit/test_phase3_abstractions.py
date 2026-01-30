from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.abstractions.analysis_result import AnalysisResult
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


def test_analysis_result_validation_and_serialization(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc")

    result = AnalysisResult(file_path=str(sample), file_format="ELF")
    assert isinstance(result.file_path, Path)
    assert result.file_path.name == "sample.bin"

    result.add_hash("MD5", "abc123")
    result.add_detection("yara", "rule_name", severity="HIGH", metadata={"id": 1})
    result.add_error("bad", context="unit")
    result.add_warning("warn", context="unit")

    data = result.to_dict()
    assert data["file_path"] == str(sample.absolute())
    assert data["hashes"]["md5"] == "abc123"
    assert data["detections"][0]["severity"] == "high"
    assert data["errors"][0].startswith("[unit]")
    assert data["warnings"][0].startswith("[unit]")

    json_data = result.to_json()
    loaded = AnalysisResult.from_json(json_data)
    assert loaded.file_format == "ELF"
    assert loaded.get_hash("md5") == "abc123"


def test_analysis_result_error_paths(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc")

    with pytest.raises(ValueError):
        AnalysisResult(file_path=str(sample), file_format="")

    result = AnalysisResult(file_path=sample, file_format="PE")
    with pytest.raises(ValueError):
        result.add_hash("", "x")
    with pytest.raises(ValueError):
        result.add_hash("md5", "")
    with pytest.raises(ValueError):
        result.add_detection("", "name")
    with pytest.raises(ValueError):
        result.add_detection("yara", "")

    other = AnalysisResult(file_path=tmp_path / "other.bin", file_format="PE")
    with pytest.raises(ValueError):
        result.merge(other)


def test_analysis_result_merge_accumulates(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc")

    left = AnalysisResult(file_path=sample, file_format="PE", execution_time=0.5)
    right = AnalysisResult(file_path=sample, file_format="PE", execution_time=1.25)
    left.file_info["size"] = 1
    right.format_info["format"] = "PE"
    right.add_hash("sha256", "hash")
    right.add_error("oops")

    left.merge(right)
    assert left.file_info["size"] == 1
    assert left.format_info["format"] == "PE"
    assert left.get_hash("sha256") == "hash"
    assert left.has_errors()
    assert left.execution_time == pytest.approx(1.75)


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

    analysis_result = analyzer.to_analysis_result({"available": False, "error": "fail"})
    assert analysis_result.has_errors()
    assert analysis_result.has_warnings()


def test_base_analyzer_requires_filepath() -> None:
    analyzer = DummyAnalyzer()
    with pytest.raises(ValueError):
        analyzer.to_analysis_result({"available": True})


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
