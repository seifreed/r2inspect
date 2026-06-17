#!/usr/bin/env python3
"""Tests for the low-memory (streaming) batch path.

Zero mocks / zero monkeypatch: env vars are snapshotted and restored by a
hand-written context manager, and collaborators are injected as plain
functions or hand-rolled doubles.
"""

from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
from typing import Any

from r2inspect.cli import batch_processing
from r2inspect.cli.batch_streaming import (
    LOW_MEMORY_ENV,
    StreamingBatchAggregator,
    build_streaming_json_payload,
    low_memory_enabled,
    make_streaming_create_batch_summary,
    write_streaming_csv,
)
from r2inspect.cli.batch_workers import process_files_parallel
from r2inspect.cli.output_formatters import OutputFormatter
from r2inspect.cli.batch_output import get_csv_fieldnames


@contextlib.contextmanager
def _env(key: str, value: str | None):
    saved = os.environ.get(key)
    if value is None:
        os.environ.pop(key, None)
    else:
        os.environ[key] = value
    try:
        yield
    finally:
        if saved is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = saved


class _AcceptingLimiter:
    def acquire(self, timeout=None) -> bool:
        return True

    def release_success(self) -> None:
        pass

    def release_error(self, error_type: str = "unknown") -> None:
        pass


def _result(file_type: str = "PE32+") -> dict[str, Any]:
    return {
        "file_info": {"name": "x", "md5": "abc", "file_type": file_type, "architecture": "x64"},
        "packer_info": {"detected": True, "name": "UPX"},
        "crypto_info": ["aes"],
        "indicators": [{"type": "t", "description": "d"}],
        "compiler": {"detected": True, "compiler": "MSVC"},
        "yara_matches": [{"rule": "evil"}],
        "extra_heavy": ["x"] * 5,
    }


# --- low_memory_enabled -----------------------------------------------------


def test_low_memory_enabled_via_injected_env():
    assert low_memory_enabled({LOW_MEMORY_ENV: "1"}) is True
    assert low_memory_enabled({LOW_MEMORY_ENV: "true"}) is True
    assert low_memory_enabled({LOW_MEMORY_ENV: "YES"}) is True
    assert low_memory_enabled({LOW_MEMORY_ENV: "0"}) is False
    assert low_memory_enabled({}) is False


def test_low_memory_enabled_reads_os_environ():
    with _env(LOW_MEMORY_ENV, "1"):
        assert low_memory_enabled() is True
    with _env(LOW_MEMORY_ENV, None):
        assert low_memory_enabled() is False


# --- aggregator -------------------------------------------------------------


def test_aggregator_folds_stats_and_returns_projection_without_csv():
    agg = StreamingBatchAggregator(
        output_csv=False, output_formatter_cls=OutputFormatter, fieldnames=get_csv_fieldnames()
    )
    projection = agg.on_result("f1", _result())

    assert agg.csv_rows == []
    assert set(projection) == {"file_info", "compiler", "yara_matches"}
    assert "extra_heavy" not in projection
    assert agg.stats["packers_detected"] == [{"file": "f1", "packer": "UPX"}]
    assert agg.stats["file_types"] == {"PE32+": 1}
    assert agg.stats["compilers"] == {"MSVC": 1}


def test_aggregator_collects_csv_rows_when_enabled():
    agg = StreamingBatchAggregator(
        output_csv=True, output_formatter_cls=OutputFormatter, fieldnames=get_csv_fieldnames()
    )
    agg.on_result("f1", _result())

    assert len(agg.csv_rows) == 1
    assert set(agg.csv_rows[0]) == set(get_csv_fieldnames())


# --- write_streaming_csv ----------------------------------------------------


def test_write_streaming_csv_round_trips(tmp_path: Path):
    csv_file = tmp_path / "out.csv"
    write_streaming_csv(csv_file, [{"name": "a", "md5": "1"}], ["name", "md5"])
    text = csv_file.read_text(encoding="utf-8")
    assert "name,md5" in text
    assert "a,1" in text


# --- build_streaming_json_payload -------------------------------------------


def test_build_streaming_json_payload_omits_embedded_results():
    agg = StreamingBatchAggregator(
        output_csv=False, output_formatter_cls=OutputFormatter, fieldnames=get_csv_fieldnames()
    )
    agg.on_result("f1", _result())
    payload = build_streaming_json_payload(agg, ["f1"], [("bad", "boom")])

    assert "results" not in payload
    assert payload["batch_summary"]["successful_analyses"] == 1
    assert payload["batch_summary"]["failed_analyses"] == 1
    assert payload["batch_summary"]["total_files"] == 2
    assert payload["failed_files"] == [{"file": "bad", "error": "boom"}]
    assert payload["statistics"]["packers_detected"] == [{"file": "f1", "packer": "UPX"}]


# --- make_streaming_create_batch_summary ------------------------------------


def _make_summary(agg, recorder):
    return make_streaming_create_batch_summary(
        agg,
        determine_csv_file_path=lambda out, ts: (out / "r.csv", "r.csv"),
        show_summary_table=lambda results: recorder.append(results),
    )


def test_streaming_summary_csv_only(tmp_path: Path):
    agg = StreamingBatchAggregator(
        output_csv=True, output_formatter_cls=OutputFormatter, fieldnames=get_csv_fieldnames()
    )
    agg.on_result("f1", _result())
    recorder: list[Any] = []
    summary = _make_summary(agg, recorder)

    name = summary({"f1": {}}, [], tmp_path, False, True)
    assert name == "r.csv"
    assert (tmp_path / "r.csv").exists()
    assert recorder == [{"f1": {}}]


def test_streaming_summary_json_only(tmp_path: Path):
    agg = StreamingBatchAggregator(
        output_csv=False, output_formatter_cls=OutputFormatter, fieldnames=get_csv_fieldnames()
    )
    agg.on_result("f1", _result())
    summary = _make_summary(agg, [])

    name = summary({"f1": {}}, [], tmp_path, True, False)
    assert name is not None and name.endswith(".json")
    written = json.loads((tmp_path / name).read_text(encoding="utf-8"))
    assert "results" not in written
    assert written["batch_summary"]["successful_analyses"] == 1


def test_streaming_summary_csv_and_json(tmp_path: Path):
    agg = StreamingBatchAggregator(
        output_csv=True, output_formatter_cls=OutputFormatter, fieldnames=get_csv_fieldnames()
    )
    agg.on_result("f1", _result())
    summary = _make_summary(agg, [])

    name = summary({"f1": {}}, [], tmp_path, True, True)
    assert name is not None and name.startswith("r.csv + ")


def test_streaming_summary_neither_returns_none(tmp_path: Path):
    agg = StreamingBatchAggregator(
        output_csv=False, output_formatter_cls=OutputFormatter, fieldnames=get_csv_fieldnames()
    )
    recorder: list[Any] = []
    summary = _make_summary(agg, recorder)

    assert summary({}, [], tmp_path, False, False) is None
    assert recorder == [{}]


# --- process_files_parallel on_result sink ----------------------------------


def test_process_files_parallel_stores_sink_return(tmp_path: Path):
    all_results: dict[str, dict[str, Any]] = {}
    failed: list[tuple[str, str]] = []
    captured: list[str] = []

    def _sink(file_key: str, result: dict[str, Any]) -> dict[str, Any]:
        captured.append(file_key)
        return {"compact": file_key}

    target = tmp_path / "x.bin"
    process_files_parallel(
        files_to_process=[target],
        all_results=all_results,
        failed_files=failed,
        output_path=tmp_path,
        batch_path=tmp_path,
        config_obj=None,
        options={},
        output_json=False,
        threads=1,
        rate_limiter=_AcceptingLimiter(),
        process_fn=lambda *args, **kwargs: (args[0], {"big": "data"}, None),
        on_result=_sink,
    )

    assert captured == [str(target)]
    assert all_results == {str(target): {"compact": str(target)}}


# --- _resolve_batch_collaborator_fns ----------------------------------------


def _request(**over: Any) -> Any:
    from r2inspect.cli.batch_processing_runtime import BatchRunRequest

    base: dict[str, Any] = {
        "batch_dir": "d",
        "options": {},
        "output_json": False,
        "output_csv": True,
        "output_dir": None,
        "recursive": True,
        "extensions": None,
        "verbose": False,
        "config_obj": None,
        "auto_detect": True,
        "threads": 1,
        "quiet": False,
    }
    base.update(over)
    return BatchRunRequest(**base)


def test_resolve_returns_default_pair_when_disabled():
    from r2inspect.cli.batch_output import create_batch_summary

    with _env(LOW_MEMORY_ENV, None):
        process_fn, summary_fn = batch_processing._resolve_batch_collaborator_fns(_request())
    assert process_fn is process_files_parallel
    assert summary_fn is create_batch_summary


def test_resolve_returns_streaming_pair_when_enabled(tmp_path: Path):
    with _env(LOW_MEMORY_ENV, "1"):
        process_fn, summary_fn = batch_processing._resolve_batch_collaborator_fns(_request())

    assert process_fn is not process_files_parallel

    # The streaming process wrapper routes results through the aggregator sink.
    all_results: dict[str, dict[str, Any]] = {}
    process_fn(
        files_to_process=[tmp_path / "x.bin"],
        all_results=all_results,
        failed_files=[],
        output_path=tmp_path,
        batch_path=tmp_path,
        config_obj=None,
        options={},
        output_json=False,
        threads=1,
        rate_limiter=_AcceptingLimiter(),
        process_fn=lambda *args, **kwargs: (args[0], _result(), None),
    )
    key = str(tmp_path / "x.bin")
    assert set(all_results[key]) == {"file_info", "compiler", "yara_matches"}

    # The paired summary writer consumes that aggregator's folded data.
    name = summary_fn(all_results, [], tmp_path, False, True)
    assert name is not None and name.endswith(".csv")


def test_show_summary_table_prints(capsys: Any):
    batch_processing._show_summary_table({"f1": _result()})
    assert capsys.readouterr().out  # rendered something
