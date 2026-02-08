from __future__ import annotations

from r2inspect.pipeline.analysis_pipeline import AnalysisPipeline, AnalysisStage, ThreadSafeContext


class _NoopStage(AnalysisStage):
    def _execute(self, _context: dict[str, object]) -> dict[str, object]:
        return {self.name: {"success": True}}


class _TimeoutStage(AnalysisStage):
    def _execute(self, _context: dict[str, object]) -> dict[str, object]:
        return {self.name: {"success": True}}


class _RaisingStage(AnalysisStage):
    def _execute(self, _context: dict[str, object]) -> dict[str, object]:
        raise RuntimeError("boom")


class _BadExecuteStage(AnalysisStage):
    def execute(self, _context: dict[str, object]) -> dict[str, object]:
        raise RuntimeError("execute boom")


class _BadExecuteTimeoutStage(AnalysisStage):
    def execute(self, _context: dict[str, object]) -> dict[str, object]:
        raise RuntimeError("timeout execute boom")


def test_pipeline_internal_helpers() -> None:
    pipeline = AnalysisPipeline()
    stage = _NoopStage("stage", dependencies=["missing"])
    remaining = [stage]
    completed: set[str] = {"done"}

    context = {"results": {}}
    ready = pipeline._get_ready_stages(remaining, completed, context)
    skipped = pipeline._get_skipped_stages(remaining, completed, context)
    assert ready == []
    assert skipped == []

    assert pipeline._handle_no_ready_stages(remaining, completed) is True

    ts_context = ThreadSafeContext({"results": {}})
    pipeline._merge_stage_results(ts_context, {})
    pipeline._merge_stage_results(ts_context, {"stage": {"success": True}})
    assert ts_context.get("results")["stage"]["success"] is True


def test_pipeline_branch_coverage() -> None:
    pipeline = AnalysisPipeline()
    s1 = _NoopStage("s1")
    s2 = _NoopStage("s2")
    pipeline.add_stage(s1).add_stage(s2)
    assert pipeline.list_stages() == ["s1", "s2"]
    assert pipeline.get_stage("s1") is s1
    assert pipeline.get_stage("missing") is None
    assert pipeline.remove_stage("s2") is True
    assert pipeline.remove_stage("missing") is False

    pipeline.clear()
    assert len(pipeline) == 0
    assert "AnalysisPipeline" in repr(pipeline)


def test_execute_parallel_break_path() -> None:
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_NoopStage("skip", condition=lambda _ctx: False))
    results = pipeline.execute_parallel()
    assert results == {}


def test_collect_futures_exception_path() -> None:
    pipeline = AnalysisPipeline()
    ts_context = ThreadSafeContext({"results": {}})
    completed: set[str] = set()
    remaining: list[AnalysisStage] = []

    def _raise() -> None:
        raise RuntimeError("boom")

    import threading
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_raise)
        stage = _NoopStage("stage")
        remaining.append(stage)
        stats = pipeline._collect_futures(
            {future: stage}, ts_context, remaining, completed, threading.Lock()
        )
    assert stats["failed"] == 1
    assert "stage" in ts_context.get("results", {})


def test_execute_stage_with_timeout_paths() -> None:
    pipeline = AnalysisPipeline()
    ts_context = ThreadSafeContext({"results": {}})
    stage = _TimeoutStage("ok", timeout=0.1)
    result, success = pipeline._execute_stage_with_timeout(stage, ts_context)
    assert success is True
    assert result["ok"]["success"] is True

    stage_timeout_error = _RaisingStage("err", timeout=0.1)
    result, success = pipeline._execute_stage_with_timeout(stage_timeout_error, ts_context)
    assert success is False

    stage_execute_error = _BadExecuteStage("exec")
    result, success = pipeline._execute_stage_with_timeout(stage_execute_error, ts_context)
    assert success is False

    stage_timeout_exec_error = _BadExecuteTimeoutStage("timeout_exec", timeout=0.1)
    result, success = pipeline._execute_stage_with_timeout(stage_timeout_exec_error, ts_context)
    assert success is False


def test_execute_parallel_flag() -> None:
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_NoopStage("only"))
    results = pipeline.execute(parallel=True)
    assert results["only"]["success"] is True
