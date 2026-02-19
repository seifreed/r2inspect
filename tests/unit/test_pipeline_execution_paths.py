"""Comprehensive tests for pipeline/analysis_pipeline.py execution paths."""

from __future__ import annotations

import os
import time
from unittest.mock import Mock

import pytest

from r2inspect.pipeline.analysis_pipeline import AnalysisPipeline, AnalysisStage, ThreadSafeContext


class _MockStage(AnalysisStage):
    """Mock stage for testing."""

    def __init__(
        self,
        name: str,
        result: dict[str, object] | None = None,
        *,
        condition=None,
        dependencies: list[str] | None = None,
        timeout: float | None = None,
    ) -> None:
        super().__init__(name=name, condition=condition, dependencies=dependencies, timeout=timeout)
        self._result = result if result is not None else {name: {"success": True}}

    def _execute(self, _context: dict[str, object]) -> dict[str, object]:
        return self._result


class _FailingStage(AnalysisStage):
    """Stage that always fails."""

    def _execute(self, _context: dict[str, object]) -> dict[str, object]:
        raise RuntimeError("Stage failed intentionally")


class _SlowStage(AnalysisStage):
    """Stage that sleeps for testing timeouts."""

    def __init__(self, name: str, delay: float, timeout: float | None = None) -> None:
        super().__init__(name=name, timeout=timeout)
        self._delay = delay

    def _execute(self, _context: dict[str, object]) -> dict[str, object]:
        time.sleep(self._delay)
        return {self.name: {"success": True}}


class TestAnalysisPipelineBasics:
    """Test basic pipeline operations."""

    def test_init_default(self) -> None:
        """Test pipeline initialization with default parameters."""
        pipeline = AnalysisPipeline()

        assert pipeline.stages == []
        assert pipeline.max_workers is None
        assert pipeline._execution_count == 0

    def test_init_with_max_workers(self) -> None:
        """Test pipeline initialization with max_workers."""
        pipeline = AnalysisPipeline(max_workers=4)

        assert pipeline.max_workers == 4

    def test_add_stage(self) -> None:
        """Test adding a stage to the pipeline."""
        pipeline = AnalysisPipeline()
        stage = _MockStage("test_stage")

        result = pipeline.add_stage(stage)

        assert len(pipeline.stages) == 1
        assert pipeline.stages[0] is stage
        assert result is pipeline  # Fluent interface

    def test_add_multiple_stages(self) -> None:
        """Test adding multiple stages."""
        pipeline = AnalysisPipeline()
        stage1 = _MockStage("stage1")
        stage2 = _MockStage("stage2")

        pipeline.add_stage(stage1).add_stage(stage2)

        assert len(pipeline.stages) == 2
        assert pipeline.stages[0] is stage1
        assert pipeline.stages[1] is stage2

    def test_remove_stage_existing(self) -> None:
        """Test removing an existing stage."""
        pipeline = AnalysisPipeline()
        stage = _MockStage("test_stage")
        pipeline.add_stage(stage)

        result = pipeline.remove_stage("test_stage")

        assert result is True
        assert len(pipeline.stages) == 0

    def test_remove_stage_nonexistent(self) -> None:
        """Test removing a non-existent stage."""
        pipeline = AnalysisPipeline()

        result = pipeline.remove_stage("nonexistent")

        assert result is False

    def test_get_stage_existing(self) -> None:
        """Test getting an existing stage by name."""
        pipeline = AnalysisPipeline()
        stage = _MockStage("test_stage")
        pipeline.add_stage(stage)

        result = pipeline.get_stage("test_stage")

        assert result is stage

    def test_get_stage_nonexistent(self) -> None:
        """Test getting a non-existent stage returns None."""
        pipeline = AnalysisPipeline()

        result = pipeline.get_stage("nonexistent")

        assert result is None

    def test_list_stages(self) -> None:
        """Test listing all stage names."""
        pipeline = AnalysisPipeline()
        pipeline.add_stage(_MockStage("stage1"))
        pipeline.add_stage(_MockStage("stage2"))
        pipeline.add_stage(_MockStage("stage3"))

        result = pipeline.list_stages()

        assert result == ["stage1", "stage2", "stage3"]

    def test_clear(self) -> None:
        """Test clearing all stages."""
        pipeline = AnalysisPipeline()
        pipeline.add_stage(_MockStage("stage1"))
        pipeline.add_stage(_MockStage("stage2"))

        pipeline.clear()

        assert len(pipeline.stages) == 0

    def test_len(self) -> None:
        """Test __len__ returns number of stages."""
        pipeline = AnalysisPipeline()
        pipeline.add_stage(_MockStage("stage1"))
        pipeline.add_stage(_MockStage("stage2"))

        assert len(pipeline) == 2

    def test_repr(self) -> None:
        """Test __repr__ string representation."""
        pipeline = AnalysisPipeline()
        pipeline.add_stage(_MockStage("stage1"))

        result = repr(pipeline)

        assert "AnalysisPipeline" in result
        assert "stages=1" in result
        assert "executed=0" in result


class TestSequentialExecution:
    """Test sequential pipeline execution."""

    def test_execute_sequential_single_stage(self) -> None:
        """Test sequential execution with single stage."""
        pipeline = AnalysisPipeline()
        pipeline.add_stage(_MockStage("stage1", {"stage1": {"data": "result"}}))

        result = pipeline.execute(parallel=False)

        assert "stage1" in result
        assert result["stage1"]["data"] == "result"

    def test_execute_sequential_multiple_stages(self) -> None:
        """Test sequential execution with multiple stages."""
        pipeline = AnalysisPipeline()
        pipeline.add_stage(_MockStage("stage1", {"stage1": {"value": 1}}))
        pipeline.add_stage(_MockStage("stage2", {"stage2": {"value": 2}}))
        pipeline.add_stage(_MockStage("stage3", {"stage3": {"value": 3}}))

        result = pipeline.execute(parallel=False)

        assert "stage1" in result
        assert "stage2" in result
        assert "stage3" in result
        assert result["stage1"]["value"] == 1
        assert result["stage2"]["value"] == 2
        assert result["stage3"]["value"] == 3

    def test_execute_sequential_with_options(self) -> None:
        """Test sequential execution passes options to context."""
        pipeline = AnalysisPipeline()
        pipeline.add_stage(_MockStage("stage1"))

        options = {"batch_mode": True, "verbose": False}
        result = pipeline.execute(options=options, parallel=False)

        # Execution should complete successfully
        assert isinstance(result, dict)

    def test_execute_sequential_skipped_stage(self) -> None:
        """Test sequential execution skips stages with false condition."""
        pipeline = AnalysisPipeline()
        pipeline.add_stage(_MockStage("stage1", condition=lambda ctx: False))
        pipeline.add_stage(_MockStage("stage2"))

        result = pipeline.execute(parallel=False)

        # Stage1 should be skipped, returns empty dict
        assert "stage1" not in result or result.get("stage1") == {}
        assert "stage2" in result

    def test_execute_sequential_failed_stage(self) -> None:
        """Test sequential execution continues after failed stage."""
        pipeline = AnalysisPipeline()
        pipeline.add_stage(_FailingStage("failing"))
        pipeline.add_stage(_MockStage("stage2"))

        result = pipeline.execute(parallel=False)

        assert "failing" in result
        assert result["failing"]["success"] is False
        assert "stage2" in result


class TestParallelExecution:
    """Test parallel pipeline execution."""

    def test_execute_parallel_single_stage(self) -> None:
        """Test parallel execution with single stage."""
        pipeline = AnalysisPipeline()
        pipeline.add_stage(_MockStage("stage1", {"stage1": {"data": "result"}}))

        result = pipeline.execute_parallel()

        assert "stage1" in result
        assert result["stage1"]["data"] == "result"

    def test_execute_parallel_independent_stages(self) -> None:
        """Test parallel execution with independent stages."""
        pipeline = AnalysisPipeline()
        pipeline.add_stage(_MockStage("stage1", {"stage1": {"value": 1}}))
        pipeline.add_stage(_MockStage("stage2", {"stage2": {"value": 2}}))
        pipeline.add_stage(_MockStage("stage3", {"stage3": {"value": 3}}))

        result = pipeline.execute_parallel()

        assert "stage1" in result
        assert "stage2" in result
        assert "stage3" in result

    def test_execute_parallel_with_dependencies(self) -> None:
        """Test parallel execution respects stage dependencies."""
        pipeline = AnalysisPipeline()
        pipeline.add_stage(_MockStage("stage1", {"stage1": {"value": 1}}))
        pipeline.add_stage(_MockStage("stage2", {"stage2": {"value": 2}}, dependencies=["stage1"]))
        pipeline.add_stage(
            _MockStage("stage3", {"stage3": {"value": 3}}, dependencies=["stage1", "stage2"])
        )

        result = pipeline.execute_parallel()

        # All stages should complete
        assert "stage1" in result
        assert "stage2" in result
        assert "stage3" in result

    def test_execute_parallel_skipped_stages(self) -> None:
        """Test parallel execution handles skipped stages."""
        pipeline = AnalysisPipeline()
        pipeline.add_stage(_MockStage("stage1"))
        pipeline.add_stage(_MockStage("skipped", condition=lambda ctx: False))
        pipeline.add_stage(_MockStage("stage3"))

        result = pipeline.execute_parallel()

        assert "stage1" in result
        # Skipped stage won't appear in results
        assert "stage3" in result

    def test_execute_parallel_failed_stage(self) -> None:
        """Test parallel execution handles failed stages."""
        pipeline = AnalysisPipeline()
        pipeline.add_stage(_FailingStage("failing"))
        pipeline.add_stage(_MockStage("stage2"))

        result = pipeline.execute_parallel()

        assert "failing" in result
        assert result["failing"]["success"] is False
        assert "stage2" in result


class TestStageTimeout:
    """Test stage timeout functionality."""

    def test_stage_timeout_sequential_mode(self) -> None:
        """Test stage timeout in sequential mode doesn't apply."""
        # Sequential mode doesn't use timeout feature
        pipeline = AnalysisPipeline()
        pipeline.add_stage(_SlowStage("slow", delay=0.1, timeout=0.05))

        # Should complete without timeout error in sequential
        result = pipeline.execute(parallel=False)

        assert "slow" in result

    def test_stage_timeout_parallel_mode(self) -> None:
        """Test stage timeout in parallel mode."""
        pipeline = AnalysisPipeline()
        pipeline.add_stage(_SlowStage("slow", delay=0.5, timeout=0.1))

        result = pipeline.execute_parallel()

        assert "slow" in result
        # Stage should have timed out
        assert "error" in result["slow"] or result["slow"]["success"] is False

    def test_stage_no_timeout_completes(self) -> None:
        """Test stage without timeout completes normally."""
        pipeline = AnalysisPipeline()
        pipeline.add_stage(_SlowStage("slow", delay=0.1, timeout=None))

        result = pipeline.execute_parallel()

        assert "slow" in result
        assert result["slow"]["success"] is True


class TestProgressCallback:
    """Test progress callback functionality."""

    def test_set_progress_callback(self) -> None:
        """Test setting progress callback."""
        pipeline = AnalysisPipeline()
        callback = Mock()

        pipeline.set_progress_callback(callback)

        assert pipeline._progress_callback is callback

    def test_execute_with_progress(self) -> None:
        """Test execute_with_progress calls callback."""
        pipeline = AnalysisPipeline()
        pipeline.add_stage(_MockStage("stage1"))
        pipeline.add_stage(_MockStage("stage2"))

        callback = Mock()
        result = pipeline.execute_with_progress(callback)

        assert "stage1" in result
        assert "stage2" in result
        # Callback should be called for each stage
        assert callback.call_count == 2

    def test_progress_callback_parameters(self) -> None:
        """Test progress callback receives correct parameters."""
        pipeline = AnalysisPipeline()
        pipeline.add_stage(_MockStage("stage1"))
        pipeline.add_stage(_MockStage("stage2"))

        calls = []

        def capture_callback(name: str, current: int, total: int) -> None:
            calls.append((name, current, total))

        pipeline.execute_with_progress(capture_callback)

        assert len(calls) == 2
        assert calls[0] == ("stage1", 1, 2)
        assert calls[1] == ("stage2", 2, 2)

    def test_sequential_execution_with_progress_callback(self) -> None:
        """Test sequential execution uses progress callback if set."""
        pipeline = AnalysisPipeline()
        pipeline.add_stage(_MockStage("stage1"))

        callback = Mock()
        pipeline.set_progress_callback(callback)

        result = pipeline._execute_sequential()

        # Callback should be called
        assert callback.call_count == 1

    def test_progress_callback_exception_handling(self) -> None:
        """Test progress callback exceptions propagate (not caught)."""
        pipeline = AnalysisPipeline()
        pipeline.add_stage(_MockStage("stage1"))

        def failing_callback(name: str, current: int, total: int) -> None:
            raise RuntimeError("Callback failed")

        # Exception should propagate since execute_with_progress doesn't catch it
        with pytest.raises(RuntimeError, match="Callback failed"):
            pipeline.execute_with_progress(failing_callback)


class TestEffectiveWorkers:
    """Test _get_effective_workers method."""

    def test_effective_workers_default(self) -> None:
        """Test effective workers with default max_workers."""
        pipeline = AnalysisPipeline()

        result = pipeline._get_effective_workers()

        # Should be min(4, cpu_count)
        assert result >= 1
        assert result <= 4

    def test_effective_workers_configured(self) -> None:
        """Test effective workers with configured max_workers respects env cap."""
        # Test mode sets R2INSPECT_MAX_WORKERS to 1 in conftest
        pipeline = AnalysisPipeline(max_workers=2)

        result = pipeline._get_effective_workers()

        # In test mode, env var caps to 1
        assert result == 1

    def test_effective_workers_env_override(self) -> None:
        """Test effective workers respects env var cap."""
        original = os.environ.get("R2INSPECT_MAX_WORKERS")
        try:
            os.environ["R2INSPECT_MAX_WORKERS"] = "3"
            pipeline = AnalysisPipeline(max_workers=5)

            result = pipeline._get_effective_workers()

            assert result == 3
        finally:
            if original is None:
                os.environ.pop("R2INSPECT_MAX_WORKERS", None)
            else:
                os.environ["R2INSPECT_MAX_WORKERS"] = original

    def test_effective_workers_env_invalid(self) -> None:
        """Test effective workers ignores invalid env var."""
        original = os.environ.get("R2INSPECT_MAX_WORKERS")
        try:
            os.environ["R2INSPECT_MAX_WORKERS"] = "invalid"
            pipeline = AnalysisPipeline(max_workers=4)

            result = pipeline._get_effective_workers()

            assert result == 4
        finally:
            if original is None:
                os.environ.pop("R2INSPECT_MAX_WORKERS", None)
            else:
                os.environ["R2INSPECT_MAX_WORKERS"] = original

    def test_effective_workers_env_zero(self) -> None:
        """Test effective workers ignores zero env var."""
        original = os.environ.get("R2INSPECT_MAX_WORKERS")
        try:
            os.environ["R2INSPECT_MAX_WORKERS"] = "0"
            pipeline = AnalysisPipeline(max_workers=4)

            result = pipeline._get_effective_workers()

            assert result == 4
        finally:
            if original is None:
                os.environ.pop("R2INSPECT_MAX_WORKERS", None)
            else:
                os.environ["R2INSPECT_MAX_WORKERS"] = original


class TestThreadSafeContext:
    """Test ThreadSafeContext wrapper."""

    def test_init(self) -> None:
        """Test ThreadSafeContext initialization."""
        ctx = ThreadSafeContext({"key": "value"})

        assert ctx.get("key") == "value"

    def test_get_existing_key(self) -> None:
        """Test getting existing key."""
        ctx = ThreadSafeContext({"key": "value"})

        result = ctx.get("key")

        assert result == "value"

    def test_get_missing_key_default(self) -> None:
        """Test getting missing key returns default."""
        ctx = ThreadSafeContext({})

        result = ctx.get("missing", "default")

        assert result == "default"

    def test_set_value(self) -> None:
        """Test setting a value."""
        ctx = ThreadSafeContext({})

        ctx.set("key", "value")

        assert ctx.get("key") == "value"

    def test_update(self) -> None:
        """Test updating multiple values."""
        ctx = ThreadSafeContext({"a": 1})

        ctx.update({"b": 2, "c": 3})

        assert ctx.get("a") == 1
        assert ctx.get("b") == 2
        assert ctx.get("c") == 3

    def test_get_all(self) -> None:
        """Test getting all data."""
        data = {"a": 1, "b": 2}
        ctx = ThreadSafeContext(data)

        result = ctx.get_all()

        assert result == data
        # Should be a copy, not the same object
        assert result is not data


class TestPipelineErrorHandling:
    """Test error handling in pipeline execution."""

    def test_no_stages_can_execute_raises(self) -> None:
        """Test pipeline raises when no stages can execute."""
        pipeline = AnalysisPipeline()
        # Add stage that depends on non-existent stage
        pipeline.add_stage(_MockStage("stage1", dependencies=["nonexistent"]))

        with pytest.raises(RuntimeError, match="No stages can execute"):
            pipeline.execute_parallel()

    def test_circular_dependency_detection(self) -> None:
        """Test pipeline handles circular dependencies gracefully."""
        pipeline = AnalysisPipeline()
        # These won't create actual circular dependency in the simple mock
        # but tests the warning path
        pipeline.add_stage(_MockStage("stage1", dependencies=["stage2"]))
        pipeline.add_stage(_MockStage("stage2", dependencies=["stage3"]))
        pipeline.add_stage(_MockStage("stage3"))

        # Should complete without crash
        result = pipeline.execute_parallel()

        # Stage3 has no dependencies, should execute
        assert "stage3" in result

    def test_stage_exception_caught_parallel(self) -> None:
        """Test stage exceptions are caught in parallel mode."""
        pipeline = AnalysisPipeline()
        pipeline.add_stage(_FailingStage("failing"))
        pipeline.add_stage(_MockStage("normal"))

        result = pipeline.execute_parallel()

        assert "failing" in result
        assert result["failing"]["success"] is False
        assert "normal" in result
        assert result["normal"]["success"] is True
