from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest

from r2inspect.application.batch_cache import BatchCache
from r2inspect.application.use_cases.analyze_binary import AnalyzeBinaryUseCase
from r2inspect.config_store import ConfigStore
from r2inspect.infrastructure.r2_session_cleanup import terminate_radare2_processes


class RecordingAnalysisService:
    def __init__(self, *, error: Exception | None = None) -> None:
        self.error = error

    def reset_stats(self) -> None:
        return

    def execute(self, _inspector: Any, _options: dict[str, Any]) -> dict[str, Any]:
        if self.error is not None:
            raise self.error
        return {"file_info": {"name": "sample.bin"}}

    def add_statistics(self, _results: dict[str, Any]) -> None:
        return

    def validate_results(self, _results: dict[str, Any]) -> None:
        return


def test_analysis_use_case_emits_one_success_outcome(caplog: pytest.LogCaptureFixture) -> None:
    use_case = AnalyzeBinaryUseCase(analysis_service=RecordingAnalysisService())  # type: ignore[arg-type]
    with caplog.at_level(logging.DEBUG, logger="r2inspect.application.use_cases.analyze_binary"):
        use_case.run(object(), {}, validate_schemas=False)  # type: ignore[arg-type]

    completed = [
        record
        for record in caplog.records
        if getattr(record, "event_name", None) == "analysis.completed"
    ]
    assert len(completed) == 1
    assert completed[0].outcome == "success"
    assert completed[0].duration_ms >= 0


def test_analysis_use_case_records_unexpected_failure(caplog: pytest.LogCaptureFixture) -> None:
    use_case = AnalyzeBinaryUseCase(  # type: ignore[arg-type]
        analysis_service=RecordingAnalysisService(error=RuntimeError("boom"))
    )
    with (
        caplog.at_level(logging.ERROR, logger="r2inspect.application.use_cases.analyze_binary"),
        pytest.raises(RuntimeError, match="boom"),
    ):
        use_case.run(object(), {}, validate_schemas=False)  # type: ignore[arg-type]

    failed = [
        record
        for record in caplog.records
        if getattr(record, "event_name", None) == "analysis.failed"
    ]
    assert len(failed) == 1
    assert failed[0].exc_info is not None
    assert failed[0].outcome == "failed"


def test_batch_cache_emits_hit_miss_and_store_events(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    other = tmp_path / "other.bin"
    other.write_bytes(b"other")
    cache = BatchCache(tmp_path / "cache.sqlite3", {}, {})

    with caplog.at_level(logging.DEBUG, logger="r2inspect.application.batch_cache"):
        assert cache.get(sample) is None
        cache.put(sample, {"result": "ok"})
        assert cache.get(sample) == {"result": "ok"}
        assert cache.get(other) is None

    outcomes = [
        record.outcome
        for record in caplog.records
        if getattr(record, "event_name", None) == "batch_cache.lookup"
    ]
    assert outcomes == ["miss", "hit", "miss"]
    assert any(
        getattr(record, "event_name", None) == "batch_cache.stored" for record in caplog.records
    )


def test_denied_process_scan_is_observable(caplog: pytest.LogCaptureFixture) -> None:
    def denied(_attributes: list[str]) -> Any:
        raise PermissionError("sandbox denied process scan")

    with caplog.at_level(logging.WARNING, logger="r2inspect.infrastructure.r2_session_cleanup"):
        terminate_radare2_processes("sample.bin", process_iter=denied)

    event = next(
        record
        for record in caplog.records
        if getattr(record, "event_name", None) == "r2.cleanup_process_scan_unavailable"
    )
    assert event.outcome == "degraded"
    assert event.error_type == "PermissionError"


def test_configuration_events_minimize_paths(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "settings.json"
    with caplog.at_level(logging.DEBUG, logger="r2inspect.config_store"):
        ConfigStore.save(str(path), {"safe": True})
        assert ConfigStore.load(str(path)) == {"safe": True}
        assert ConfigStore.load(str(tmp_path / "missing.json")) is None

    events = {
        record.event_name: record for record in caplog.records if hasattr(record, "event_name")
    }
    assert events["configuration.saved"].outcome == "success"
    assert events["configuration.loaded"].duration_ms >= 0
    assert events["configuration.load_failed"].error_type == "FileNotFoundError"
    assert events["configuration.loaded"].config_file == "settings.json"
    assert str(tmp_path) not in caplog.text
