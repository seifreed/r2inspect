from __future__ import annotations

import os
import time
from collections.abc import Callable

import pytest

from r2inspect.pipeline.analysis_pipeline import AnalysisPipeline, AnalysisStage, ThreadSafeContext


class _ResultStage(AnalysisStage):
    def __init__(
        self,
        name: str,
        result: dict[str, object] | None = None,
        *,
        condition: Callable[[dict[str, object]], bool] | None = None,
        dependencies: list[str] | None = None,
        timeout: float | None = None,
    ) -> None:
        super().__init__(
            name=name,
            condition=condition,
            dependencies=dependencies,
            timeout=timeout,
        )
        self._result = result if result is not None else {name: {"success": True}}

    def _execute(self, _context: dict[str, object]) -> dict[str, object]:
        return self._result


class _ErrorStage(AnalysisStage):
    def _execute(self, _context: dict[str, object]) -> dict[str, object]:
        raise RuntimeError("boom")


class _SleepStage(AnalysisStage):
    def __init__(self, name: str, delay: float, *, timeout: float | None = None) -> None:
        super().__init__(name=name, timeout=timeout)
        self._delay = delay

    def _execute(self, _context: dict[str, object]) -> dict[str, object]:
        time.sleep(self._delay)
        return {self.name: {"success": True}}


def test_threadsafe_context_basic() -> None:
    ctx = ThreadSafeContext({"a": 1})
    ctx.update({"b": 2})
    assert ctx.get("a") == 1
    assert ctx.get("b") == 2
    assert ctx.get("missing", 3) == 3
    ctx.set("c", 4)
    snapshot = ctx.get_all()
    assert snapshot["c"] == 4


def test_stage_conditions_and_errors() -> None:
    def _raising_condition(_ctx: dict[str, object]) -> bool:
        raise ValueError("bad condition")

    stage = _ResultStage("ok", condition=lambda _ctx: False)
    assert stage.should_execute({}) is False
    assert stage.execute({"results": {}}) == {}

    stage_bad = _ResultStage("bad", condition=_raising_condition)
    assert stage_bad.should_execute({}) is False

    error_stage = _ErrorStage("err")
    context: dict[str, object] = {"results": {}}
    result = error_stage.execute(context)
    assert result["err"]["success"] is False
    assert "err" in context["results"]


def test_effective_workers_env() -> None:
    pipeline = AnalysisPipeline(max_workers=4)
    original = os.environ.get("R2INSPECT_MAX_WORKERS")
    try:
        os.environ["R2INSPECT_MAX_WORKERS"] = ""
        assert pipeline._get_effective_workers() == 4
        os.environ["R2INSPECT_MAX_WORKERS"] = "not-int"
        assert pipeline._get_effective_workers() == 4
        os.environ["R2INSPECT_MAX_WORKERS"] = "0"
        assert pipeline._get_effective_workers() == 4
        os.environ["R2INSPECT_MAX_WORKERS"] = "2"
        assert pipeline._get_effective_workers() == 2
    finally:
        if original is None:
            os.environ.pop("R2INSPECT_MAX_WORKERS", None)
        else:
            os.environ["R2INSPECT_MAX_WORKERS"] = original


def test_sequential_execution_and_progress_callback() -> None:
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_ResultStage("a"))
    pipeline.add_stage(_ResultStage("b", result={}))
    pipeline.add_stage(_ResultStage("c", result={"c": {"success": False}}))

    calls: list[tuple[str, int, int]] = []

    def _progress(name: str, idx: int, total: int) -> None:
        calls.append((name, idx, total))
        if name == "a":
            raise RuntimeError("ignore")

    pipeline.set_progress_callback(_progress)
    result = pipeline.execute()
    assert "a" in result
    assert "c" in result
    assert calls[0][0] == "a"


def test_execute_with_progress() -> None:
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_ResultStage("first"))
    pipeline.add_stage(_ResultStage("second"))
    seen: list[str] = []

    def _progress(name: str, _idx: int, _total: int) -> None:
        seen.append(name)

    result = pipeline.execute_with_progress(_progress)
    assert result["first"]["success"] is True
    assert seen == ["first", "second"]


def test_parallel_execution_branches() -> None:
    pipeline = AnalysisPipeline(max_workers=2)
    pipeline.add_stage(_ResultStage("start"))
    pipeline.add_stage(_ResultStage("skip", condition=lambda _ctx: False))
    pipeline.add_stage(_ErrorStage("bad"))
    pipeline.add_stage(_SleepStage("slow", delay=0.05, timeout=0.01))
    pipeline.add_stage(_ResultStage("after", dependencies=["start"]))

    results = pipeline.execute_parallel()
    assert "start" in results
    assert "skip" not in results
    assert results["bad"]["success"] is False
    assert results["slow"]["success"] is False
    assert "after" in results


def test_parallel_no_ready_stages_raises() -> None:
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_ResultStage("blocked", dependencies=["missing"]))

    with pytest.raises(RuntimeError):
        pipeline.execute_parallel()
