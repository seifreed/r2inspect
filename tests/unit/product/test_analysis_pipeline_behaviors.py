from __future__ import annotations

import json
import logging
from pathlib import Path
import time
from typing import Any

from r2inspect.infrastructure.logging import bind_log_context, setup_logger
from r2inspect.pipeline.analysis_pipeline import AnalysisPipeline
from r2inspect.pipeline.stage_models import AnalysisStage


class RecordingStage(AnalysisStage):
    def __init__(
        self,
        name: str,
        result: dict[str, Any] | None = None,
        *,
        dependencies: list[str] | None = None,
        condition=None,
        timeout: float | None = None,
        sink: list[str] | None = None,
    ) -> None:
        super().__init__(
            name=name,
            dependencies=dependencies,
            condition=condition,
            timeout=timeout,
        )
        self._result = result if result is not None else {name: {"success": True}}
        self._sink = sink

    def _execute(self, _context: dict[str, Any]) -> dict[str, Any]:
        if self._sink is not None:
            self._sink.append(self.name)
        return self._result


class SlowStage(AnalysisStage):
    def __init__(self, name: str, delay: float, *, timeout: float) -> None:
        super().__init__(name=name, timeout=timeout)
        self._delay = delay

    def _execute(self, _context: dict[str, Any]) -> dict[str, Any]:
        time.sleep(self._delay)
        return {self.name: {"success": True}}


def _close_logger(logger: logging.Logger) -> None:
    for handler in list(logger.handlers):
        handler.close()
        logger.removeHandler(handler)


def test_analysis_pipeline_executes_dependencies_before_dependents() -> None:
    execution_order: list[str] = []
    pipeline = AnalysisPipeline(max_workers=2)
    pipeline.add_stage(RecordingStage("collect", sink=execution_order))
    pipeline.add_stage(RecordingStage("hash", dependencies=["collect"], sink=execution_order))

    results = pipeline.execute(parallel=True)

    assert execution_order == ["collect", "hash"]
    assert results["collect"]["success"] is True
    assert results["hash"]["success"] is True


def test_parallel_pipeline_propagates_correlation_to_worker_threads(tmp_path: Path) -> None:
    path = tmp_path / "pipeline.jsonl"
    root_logger = setup_logger(
        "r2inspect",
        level=logging.DEBUG,
        format_name="json",
        destination="file",
        log_file=path,
    )
    pipeline = AnalysisPipeline(max_workers=2)
    pipeline.add_stage(RecordingStage("first"))
    pipeline.add_stage(RecordingStage("second"))
    try:
        with bind_log_context(correlation_id="pipeline-correlation"):
            pipeline.execute(parallel=True)
        for handler in root_logger.handlers:
            handler.flush()
    finally:
        _close_logger(root_logger)

    events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    stage_events = [
        event for event in events if event.get("event_name") == "pipeline.stage_completed"
    ]
    assert {event["stage"] for event in stage_events} == {"first", "second"}
    assert {event["correlation_id"] for event in stage_events} == {"pipeline-correlation"}


def test_analysis_pipeline_skips_conditioned_stage_without_failing_run() -> None:
    pipeline = AnalysisPipeline()
    pipeline.add_stage(RecordingStage("always"))
    pipeline.add_stage(
        RecordingStage("skipped", condition=lambda _context: False, result={"skipped": {"x": 1}})
    )

    results = pipeline.execute()

    assert "always" in results
    assert "skipped" not in results


def test_analysis_pipeline_marks_timeout_as_failed_result() -> None:
    pipeline = AnalysisPipeline(max_workers=1)
    pipeline.add_stage(SlowStage("slow", delay=0.05, timeout=0.001))

    results = pipeline.execute(parallel=True)

    assert results["slow"]["success"] is False
    assert "timeout" in results["slow"]["error"].lower()


def test_analysis_pipeline_progress_callback_failures_do_not_abort_execution() -> None:
    pipeline = AnalysisPipeline()
    pipeline.add_stage(RecordingStage("first"))
    pipeline.add_stage(RecordingStage("second"))
    seen: list[str] = []

    def progress(name: str, _idx: int, _total: int) -> None:
        seen.append(name)
        if name == "first":
            raise RuntimeError("ignore progress failure")

    pipeline.set_progress_callback(progress)
    results = pipeline.execute()

    assert results["first"]["success"] is True
    assert results["second"]["success"] is True
    assert seen == ["first", "second"]


def test_analysis_pipeline_raises_when_no_parallel_stage_can_run() -> None:
    pipeline = AnalysisPipeline()
    pipeline.add_stage(RecordingStage("blocked", dependencies=["missing"]))

    try:
        pipeline.execute(parallel=True)
    except RuntimeError as exc:
        message = str(exc).lower()
        assert "dependencies" in message or "conditions" in message or "ready" in message
    else:
        raise AssertionError("expected RuntimeError for unsatisfied dependencies")


def test_analysis_pipeline_clear_and_get_stage_cover_basic_management() -> None:
    pipeline = AnalysisPipeline()
    stage = RecordingStage("only")
    pipeline.add_stage(stage)

    assert pipeline.get_stage("only") is stage
    assert pipeline.get_stage("missing") is None
    pipeline.clear()
    assert len(pipeline) == 0
