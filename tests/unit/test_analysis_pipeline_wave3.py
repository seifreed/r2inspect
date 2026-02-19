"""Tests covering missing lines in r2inspect/pipeline/analysis_pipeline.py."""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

from r2inspect.pipeline.analysis_pipeline import AnalysisPipeline, AnalysisStage, ThreadSafeContext


# ---------------------------------------------------------------------------
# Concrete stage helpers (no mocks)
# ---------------------------------------------------------------------------


class _OkStage(AnalysisStage):
    """Stage that returns a successful result dict."""

    def __init__(
        self,
        name: str,
        result: dict[str, Any] | None = None,
        *,
        condition=None,
        dependencies: list[str] | None = None,
        timeout: float | None = None,
    ) -> None:
        super().__init__(name=name, condition=condition, dependencies=dependencies, timeout=timeout)
        self._result: dict[str, Any] = result if result is not None else {name: {"success": True}}

    def _execute(self, _context: dict[str, Any]) -> dict[str, Any]:
        return self._result


class _FailResultStage(AnalysisStage):
    """Stage that returns a failure result (success: False) without raising."""

    def _execute(self, _context: dict[str, Any]) -> dict[str, Any]:
        return {self.name: {"success": False, "error": "deliberate failure"}}


class _RaiseStage(AnalysisStage):
    """Stage that raises an exception inside _execute."""

    def __init__(self, name: str, *, timeout: float | None = None) -> None:
        super().__init__(name=name, timeout=timeout)

    def _execute(self, _context: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError("stage error")


class _EmptyStage(AnalysisStage):
    """Stage that returns an empty dict (treated as skipped by sequential executor)."""

    def _execute(self, _context: dict[str, Any]) -> dict[str, Any]:
        return {}


class _SlowStage(AnalysisStage):
    """Stage that sleeps — useful for timeout testing."""

    def __init__(self, name: str, delay: float, *, timeout: float | None = None) -> None:
        super().__init__(name=name, timeout=timeout)
        self._delay = delay

    def _execute(self, _context: dict[str, Any]) -> dict[str, Any]:
        time.sleep(self._delay)
        return {self.name: {"success": True}}


class _ExecuteRaiseStage(AnalysisStage):
    """Stage that overrides execute() itself to raise (bypasses normal exception handling)."""

    def __init__(self, name: str, *, timeout: float | None = None) -> None:
        super().__init__(name=name, timeout=timeout)

    def execute(self, _context: dict[str, Any]) -> dict[str, Any]:  # type: ignore[override]
        raise RuntimeError("execute raise")

    def _execute(self, _context: dict[str, Any]) -> dict[str, Any]:  # pragma: no cover
        return {}


# ---------------------------------------------------------------------------
# remove_stage — lines 55-64
# ---------------------------------------------------------------------------


def test_remove_stage_existing_stage_returns_true() -> None:
    """remove_stage returns True and filters out the stage when the name exists."""
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_OkStage("alpha"))
    pipeline.add_stage(_OkStage("beta"))

    removed = pipeline.remove_stage("alpha")

    assert removed is True
    assert pipeline.list_stages() == ["beta"]


def test_remove_stage_missing_name_returns_false() -> None:
    """remove_stage returns False and logs a warning when the name is not found."""
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_OkStage("alpha"))

    removed = pipeline.remove_stage("nonexistent")

    assert removed is False
    assert pipeline.list_stages() == ["alpha"]


# ---------------------------------------------------------------------------
# get_stage — line 79 (None return path)
# ---------------------------------------------------------------------------


def test_get_stage_returns_none_when_not_found() -> None:
    """get_stage returns None for an unknown name."""
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_OkStage("known"))

    result = pipeline.get_stage("unknown")

    assert result is None


# ---------------------------------------------------------------------------
# set_progress_callback — line 92
# ---------------------------------------------------------------------------


def test_set_progress_callback_stores_callable() -> None:
    """set_progress_callback stores the provided callable on the pipeline."""
    pipeline = AnalysisPipeline()

    def my_callback(name: str, idx: int, total: int) -> None:
        pass

    pipeline.set_progress_callback(my_callback)
    assert pipeline._progress_callback is my_callback


def test_set_progress_callback_accepts_none() -> None:
    """set_progress_callback can clear the callback by passing None."""
    pipeline = AnalysisPipeline()

    def my_callback(name: str, idx: int, total: int) -> None:
        pass

    pipeline.set_progress_callback(my_callback)
    pipeline.set_progress_callback(None)
    assert pipeline._progress_callback is None


# ---------------------------------------------------------------------------
# execute_parallel — lines 111-184
# ---------------------------------------------------------------------------


def test_execute_parallel_increments_execution_count() -> None:
    """execute_parallel increments the internal execution counter."""
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_OkStage("s1"))

    assert pipeline._execution_count == 0
    pipeline.execute_parallel()
    assert pipeline._execution_count == 1
    pipeline.execute_parallel()
    assert pipeline._execution_count == 2


def test_execute_parallel_passes_options_in_context() -> None:
    """execute_parallel places the supplied options dict into the context."""
    captured: list[dict[str, Any]] = []

    class _CapturingStage(AnalysisStage):
        def _execute(self, context: dict[str, Any]) -> dict[str, Any]:
            captured.append(dict(context))
            return {self.name: {"success": True}}

    pipeline = AnalysisPipeline()
    pipeline.add_stage(_CapturingStage("capture"))
    pipeline.execute_parallel(options={"key": "value"})

    assert len(captured) == 1
    assert captured[0]["options"]["key"] == "value"


def test_execute_parallel_returns_results_dict() -> None:
    """execute_parallel returns the aggregated results from all stages."""
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_OkStage("a", {"a": {"x": 1}}))
    pipeline.add_stage(_OkStage("b", {"b": {"x": 2}}))

    results = pipeline.execute_parallel()

    assert results["a"]["x"] == 1
    assert results["b"]["x"] == 2


def test_execute_parallel_skipped_stage_not_in_results() -> None:
    """Stages whose condition evaluates to False are skipped and absent from results."""
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_OkStage("normal"))
    pipeline.add_stage(_OkStage("skipped", condition=lambda _ctx: False))

    results = pipeline.execute_parallel()

    assert "normal" in results
    assert "skipped" not in results


def test_execute_parallel_failed_stage_marked_in_results() -> None:
    """A raising stage produces an error entry with success=False in results."""
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_RaiseStage("broken"))
    pipeline.add_stage(_OkStage("fine"))

    results = pipeline.execute_parallel()

    assert results["broken"]["success"] is False
    assert "fine" in results


def test_execute_parallel_dependency_ordering() -> None:
    """Stages with declared dependencies execute after their dependencies complete."""
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_OkStage("root"))
    pipeline.add_stage(_OkStage("child", dependencies=["root"]))
    pipeline.add_stage(_OkStage("leaf", dependencies=["child"]))

    results = pipeline.execute_parallel()

    assert results["root"]["success"] is True
    assert results["child"]["success"] is True
    assert results["leaf"]["success"] is True


def test_execute_parallel_timeout_stage_returns_error() -> None:
    """A stage that exceeds its timeout is recorded as failed."""
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_SlowStage("slow", delay=0.5, timeout=0.05))

    results = pipeline.execute_parallel()

    assert "slow" in results
    assert results["slow"]["success"] is False


def test_execute_parallel_breaks_when_unsatisfied_after_completion() -> None:
    """
    When a stage completes but remaining stages have unsatisfied deps,
    the pipeline breaks cleanly without raising.
    """
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_OkStage("done"))
    # "ghost" is a dependency that will never be satisfied
    pipeline.add_stage(_OkStage("blocked", dependencies=["ghost"]))

    # Should not raise — warning is logged instead, pipeline breaks the loop
    results = pipeline.execute_parallel()

    # "done" completes, "blocked" never runs
    assert "done" in results
    assert "blocked" not in results


def test_execute_parallel_raises_when_nothing_can_ever_execute() -> None:
    """If no stage can ever execute (all deps unsatisfied and nothing done yet), raise."""
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_OkStage("orphan", dependencies=["ghost"]))

    with pytest.raises(RuntimeError, match="No stages can execute"):
        pipeline.execute_parallel()


def test_execute_parallel_empty_pipeline_returns_empty_dict() -> None:
    """An empty pipeline returns an empty results dict."""
    pipeline = AnalysisPipeline()

    results = pipeline.execute_parallel()

    assert results == {}


# ---------------------------------------------------------------------------
# _get_ready_stages / _get_skipped_stages — lines 191, 204
# ---------------------------------------------------------------------------


def test_get_ready_stages_excludes_unmet_dependencies() -> None:
    """_get_ready_stages excludes stages whose dependencies are not yet complete."""
    pipeline = AnalysisPipeline()
    stage_ok = _OkStage("a")
    stage_blocked = _OkStage("b", dependencies=["missing"])
    remaining = [stage_ok, stage_blocked]
    completed: set[str] = set()

    ready = pipeline._get_ready_stages(remaining, completed, {})

    assert stage_ok in ready
    assert stage_blocked not in ready


def test_get_skipped_stages_finds_false_condition_stages() -> None:
    """_get_skipped_stages identifies stages whose condition evaluates to False."""
    pipeline = AnalysisPipeline()
    stage_skip = _OkStage("skip", condition=lambda _ctx: False)
    stage_run = _OkStage("run")
    remaining = [stage_skip, stage_run]
    completed: set[str] = set()

    skipped = pipeline._get_skipped_stages(remaining, completed, {})

    assert stage_skip in skipped
    assert stage_run not in skipped


# ---------------------------------------------------------------------------
# _apply_skipped_stages — lines 218-225
# ---------------------------------------------------------------------------


def test_apply_skipped_stages_removes_from_remaining_and_marks_completed() -> None:
    """_apply_skipped_stages removes skipped stages from remaining and adds to completed."""
    pipeline = AnalysisPipeline()
    stage = _OkStage("skipped")
    remaining: list[AnalysisStage] = [stage]
    completed: set[str] = set()
    lock = threading.Lock()

    count = pipeline._apply_skipped_stages([stage], remaining, completed, lock)

    assert count == 1
    assert remaining == []
    assert "skipped" in completed


# ---------------------------------------------------------------------------
# _handle_no_ready_stages — lines 229-238
# ---------------------------------------------------------------------------


def test_handle_no_ready_stages_raises_when_completed_empty() -> None:
    """_handle_no_ready_stages raises RuntimeError when nothing has completed yet."""
    pipeline = AnalysisPipeline()
    stage = _OkStage("s", dependencies=["x"])

    with pytest.raises(RuntimeError, match="No stages can execute"):
        pipeline._handle_no_ready_stages([stage], set())


def test_handle_no_ready_stages_returns_true_with_unsatisfied_remaining() -> None:
    """_handle_no_ready_stages returns True and logs a warning when deps remain unsatisfied."""
    pipeline = AnalysisPipeline()
    stage = _OkStage("s", dependencies=["ghost"])
    completed = {"already_done"}

    result = pipeline._handle_no_ready_stages([stage], completed)

    assert result is True


def test_handle_no_ready_stages_returns_true_with_empty_remaining() -> None:
    """_handle_no_ready_stages returns True when remaining list is empty."""
    pipeline = AnalysisPipeline()

    result = pipeline._handle_no_ready_stages([], {"some_stage"})

    assert result is True


# ---------------------------------------------------------------------------
# _submit_ready_stages — lines 247-251
# ---------------------------------------------------------------------------


def test_submit_ready_stages_returns_future_map() -> None:
    """_submit_ready_stages maps futures to their corresponding stage objects."""
    pipeline = AnalysisPipeline()
    stage = _OkStage("s")
    ts_context = ThreadSafeContext({"results": {}})

    with ThreadPoolExecutor(max_workers=1) as executor:
        future_map = pipeline._submit_ready_stages(executor, [stage], ts_context)
        # Drain futures before exiting the executor
        for f in future_map:
            f.result()

    assert len(future_map) == 1
    assert stage in future_map.values()


# ---------------------------------------------------------------------------
# _merge_stage_results — lines 256-258
# ---------------------------------------------------------------------------


def test_merge_stage_results_empty_dict_is_noop() -> None:
    """_merge_stage_results does nothing when stage_result is empty."""
    ts_context = ThreadSafeContext({"results": {"existing": True}})

    AnalysisPipeline._merge_stage_results(ts_context, {})

    assert ts_context.get("results") == {"existing": True}


def test_merge_stage_results_merges_into_context() -> None:
    """_merge_stage_results merges a non-empty stage_result into the context results."""
    ts_context = ThreadSafeContext({"results": {"a": 1}})

    AnalysisPipeline._merge_stage_results(ts_context, {"b": 2})

    assert ts_context.get("results") == {"a": 1, "b": 2}


# ---------------------------------------------------------------------------
# _stage_success — lines 270-271
# ---------------------------------------------------------------------------


def test_stage_success_returns_true_for_success_result() -> None:
    """_stage_success returns True when the stage result indicates success."""
    result = {"my_stage": {"success": True, "data": "x"}}

    assert AnalysisPipeline._stage_success(result, "my_stage") is True


def test_stage_success_returns_false_for_failure_result() -> None:
    """_stage_success returns False when the stage result has success=False."""
    result = {"my_stage": {"success": False, "error": "oops"}}

    assert AnalysisPipeline._stage_success(result, "my_stage") is False


def test_stage_success_returns_true_when_key_absent() -> None:
    """_stage_success returns True when the stage name is not in the result dict."""
    assert AnalysisPipeline._stage_success({}, "missing_stage") is True


# ---------------------------------------------------------------------------
# _error_result — line 276
# ---------------------------------------------------------------------------


def test_error_result_structure() -> None:
    """_error_result returns the standard error payload structure."""
    payload = AnalysisPipeline._error_result("my_stage", "something went wrong")

    assert payload == {"my_stage": {"error": "something went wrong", "success": False}}


# ---------------------------------------------------------------------------
# _collect_futures — lines 287-311
# ---------------------------------------------------------------------------


def test_collect_futures_success_path() -> None:
    """_collect_futures counts executed stages and merges results on success."""
    pipeline = AnalysisPipeline()
    stage = _OkStage("s")
    ts_context = ThreadSafeContext({"results": {}})
    completed: set[str] = set()
    remaining: list[AnalysisStage] = [stage]
    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(pipeline._execute_stage_with_timeout, stage, ts_context)
        stats = pipeline._collect_futures({future: stage}, ts_context, remaining, completed, lock)

    assert stats["executed"] == 1
    assert stats["failed"] == 0
    assert "s" in ts_context.get("results", {})
    assert "s" in completed
    assert remaining == []


def test_collect_futures_failed_stage_counted() -> None:
    """_collect_futures counts a stage that returns success=False as failed."""
    pipeline = AnalysisPipeline()
    stage = _FailResultStage("fail_stage")
    ts_context = ThreadSafeContext({"results": {}})
    completed: set[str] = set()
    remaining: list[AnalysisStage] = [stage]
    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(pipeline._execute_stage_with_timeout, stage, ts_context)
        stats = pipeline._collect_futures({future: stage}, ts_context, remaining, completed, lock)

    assert stats["failed"] == 1
    assert stats["executed"] == 0


def test_collect_futures_exception_in_future_counted_as_failed() -> None:
    """_collect_futures handles futures that raise uncaught exceptions as failed."""
    pipeline = AnalysisPipeline()
    ts_context = ThreadSafeContext({"results": {}})
    stage = _OkStage("ex_stage")
    remaining: list[AnalysisStage] = [stage]
    completed: set[str] = set()
    lock = threading.Lock()

    def _raise() -> None:
        raise RuntimeError("future boom")

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_raise)
        stats = pipeline._collect_futures({future: stage}, ts_context, remaining, completed, lock)

    assert stats["failed"] == 1
    assert "ex_stage" in ts_context.get("results", {})


# ---------------------------------------------------------------------------
# _execute_stage_with_timeout — lines 327-351
# ---------------------------------------------------------------------------


def test_execute_stage_with_timeout_success_within_limit() -> None:
    """A fast stage with a generous timeout completes successfully."""
    pipeline = AnalysisPipeline()
    stage = _OkStage("fast", timeout=5.0)
    ts_context = ThreadSafeContext({"results": {}})

    result, success = pipeline._execute_stage_with_timeout(stage, ts_context)

    assert success is True
    assert result["fast"]["success"] is True


def test_execute_stage_with_timeout_exceeded() -> None:
    """A slow stage whose timeout is exceeded returns a timeout error result."""
    pipeline = AnalysisPipeline()
    stage = _SlowStage("turtle", delay=0.5, timeout=0.05)
    ts_context = ThreadSafeContext({"results": {}})

    result, success = pipeline._execute_stage_with_timeout(stage, ts_context)

    assert success is False
    assert "Timeout" in result["turtle"]["error"]


def test_execute_stage_with_timeout_exception_in_stage() -> None:
    """A stage that raises inside a timeout executor returns an error result."""
    pipeline = AnalysisPipeline()
    stage = _ExecuteRaiseStage("boom", timeout=5.0)
    ts_context = ThreadSafeContext({"results": {}})

    result, success = pipeline._execute_stage_with_timeout(stage, ts_context)

    assert success is False
    assert result["boom"]["success"] is False


def test_execute_stage_without_timeout_success() -> None:
    """A stage without a timeout executes normally and returns its result."""
    pipeline = AnalysisPipeline()
    stage = _OkStage("notimeout")
    ts_context = ThreadSafeContext({"results": {}})

    result, success = pipeline._execute_stage_with_timeout(stage, ts_context)

    assert success is True
    assert result["notimeout"]["success"] is True


def test_execute_stage_without_timeout_exception() -> None:
    """A stage that raises without a timeout returns an error result."""
    pipeline = AnalysisPipeline()
    stage = _ExecuteRaiseStage("errnotimeout")
    ts_context = ThreadSafeContext({"results": {}})

    result, success = pipeline._execute_stage_with_timeout(stage, ts_context)

    assert success is False
    assert result["errnotimeout"]["success"] is False


# ---------------------------------------------------------------------------
# execute() dispatch — line 377
# ---------------------------------------------------------------------------


def test_execute_defaults_to_sequential() -> None:
    """execute() without parallel=True runs the sequential path."""
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_OkStage("seq"))

    results = pipeline.execute()

    assert results["seq"]["success"] is True


def test_execute_parallel_flag_uses_parallel_path() -> None:
    """execute(parallel=True) routes to execute_parallel."""
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_OkStage("par"))

    results = pipeline.execute(parallel=True)

    assert results["par"]["success"] is True


def test_execute_with_options_sequential() -> None:
    """execute() passes options dict through to stages in sequential mode."""
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_OkStage("opt"))

    results = pipeline.execute(options={"flag": True})

    assert "opt" in results


# ---------------------------------------------------------------------------
# _execute_sequential — lines 413-416, 435, 439
# ---------------------------------------------------------------------------


def test_sequential_progress_callback_exception_is_swallowed() -> None:
    """A throwing progress callback does not abort sequential pipeline execution."""
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_OkStage("x"))
    pipeline.add_stage(_OkStage("y"))

    raised_for: list[str] = []

    def bad_callback(name: str, idx: int, total: int) -> None:
        raised_for.append(name)
        raise ValueError("callback error")

    pipeline.set_progress_callback(bad_callback)
    results = pipeline.execute()

    assert "x" in results
    assert "y" in results
    assert "x" in raised_for


def test_sequential_failed_stage_counted_not_executed() -> None:
    """A stage returning success=False increments the failed counter, not executed."""
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_FailResultStage("fail"))

    results = pipeline.execute()

    assert results["fail"]["success"] is False


def test_sequential_empty_result_counted_as_skipped() -> None:
    """A stage returning an empty dict is treated as skipped in sequential mode."""
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_EmptyStage("empty"))
    pipeline.add_stage(_OkStage("normal"))

    results = pipeline.execute()

    # "empty" returned {}, so its key is not in results
    assert "empty" not in results
    assert "normal" in results


# ---------------------------------------------------------------------------
# execute_with_progress — lines 463-495
# ---------------------------------------------------------------------------


def test_execute_with_progress_calls_callback_for_each_stage() -> None:
    """execute_with_progress calls the callback once per stage with correct args."""
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_OkStage("p1"))
    pipeline.add_stage(_OkStage("p2"))
    pipeline.add_stage(_OkStage("p3"))

    calls: list[tuple[str, int, int]] = []

    def cb(name: str, idx: int, total: int) -> None:
        calls.append((name, idx, total))

    results = pipeline.execute_with_progress(cb)

    assert results["p1"]["success"] is True
    assert results["p2"]["success"] is True
    assert results["p3"]["success"] is True
    assert calls == [("p1", 1, 3), ("p2", 2, 3), ("p3", 3, 3)]


def test_execute_with_progress_increments_execution_count() -> None:
    """execute_with_progress increments the pipeline execution counter."""
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_OkStage("q"))

    before = pipeline._execution_count
    pipeline.execute_with_progress(lambda *_: None)

    assert pipeline._execution_count == before + 1


def test_execute_with_progress_empty_pipeline() -> None:
    """execute_with_progress on an empty pipeline returns an empty dict."""
    pipeline = AnalysisPipeline()

    results = pipeline.execute_with_progress(lambda *_: None)

    assert results == {}


def test_execute_with_progress_with_options() -> None:
    """execute_with_progress accepts and threads through an options dict."""
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_OkStage("opt"))

    results = pipeline.execute_with_progress(lambda *_: None, options={"k": "v"})

    assert "opt" in results


def test_execute_with_progress_merges_stage_results() -> None:
    """execute_with_progress accumulates results from multiple stages."""
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_OkStage("r1", {"r1": {"v": 10}}))
    pipeline.add_stage(_OkStage("r2", {"r2": {"v": 20}}))

    results = pipeline.execute_with_progress(lambda *_: None)

    assert results["r1"]["v"] == 10
    assert results["r2"]["v"] == 20


# ---------------------------------------------------------------------------
# clear — lines 494-495
# ---------------------------------------------------------------------------


def test_clear_removes_all_stages() -> None:
    """clear() removes every stage from the pipeline."""
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_OkStage("a"))
    pipeline.add_stage(_OkStage("b"))
    pipeline.add_stage(_OkStage("c"))

    pipeline.clear()

    assert len(pipeline) == 0
    assert pipeline.list_stages() == []


def test_clear_allows_re_adding_stages() -> None:
    """After clear(), new stages can be added and executed normally."""
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_OkStage("old"))
    pipeline.clear()
    pipeline.add_stage(_OkStage("new"))

    results = pipeline.execute()

    assert "new" in results
    assert "old" not in results
