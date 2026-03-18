from __future__ import annotations

import time
from typing import Any

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


def test_analysis_pipeline_executes_dependencies_before_dependents() -> None:
    execution_order: list[str] = []
    pipeline = AnalysisPipeline(max_workers=2)
    pipeline.add_stage(RecordingStage("collect", sink=execution_order))
    pipeline.add_stage(RecordingStage("hash", dependencies=["collect"], sink=execution_order))

    results = pipeline.execute(parallel=True)

    assert execution_order == ["collect", "hash"]
    assert results["collect"]["success"] is True
    assert results["hash"]["success"] is True


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
