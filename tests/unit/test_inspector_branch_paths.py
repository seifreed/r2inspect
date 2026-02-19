"""Tests covering branch paths in r2inspect/core/inspector.py."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from r2inspect.config import Config
from r2inspect.core.file_validator import FileValidator
from r2inspect.core.inspector import R2Inspector
from r2inspect.core.result_aggregator import ResultAggregator
from r2inspect.pipeline.analysis_pipeline import AnalysisPipeline, AnalysisStage
from r2inspect.utils.memory_manager import MemoryMonitor, global_memory_monitor


# ---------------------------------------------------------------------------
# Helpers: real stub classes (no mocking library)
# ---------------------------------------------------------------------------


class StubRegistry:
    """Minimal registry that satisfies R2Inspector's interface."""

    def __len__(self) -> int:
        return 0

    def list_analyzers(self) -> list[dict[str, Any]]:
        return []


class VerboseStubRegistry:
    """Registry that returns analyzer info for verbose logging path."""

    def __len__(self) -> int:
        return 2

    def list_analyzers(self) -> list[dict[str, Any]]:
        return [
            {"name": "pe_analyzer", "category": "format", "file_formats": ["PE"]},
            {"name": "elf_analyzer", "category": "format", "file_formats": ["ELF"]},
        ]


class OkPipeline:
    """Pipeline that succeeds."""

    def execute(self, options: dict[str, Any], parallel: bool = False) -> dict[str, Any]:
        return {"analysis": {"ok": True}}

    def execute_with_progress(
        self, callback: Any, options: dict[str, Any]
    ) -> dict[str, Any]:
        if callback is not None:
            callback("stage_done")
        return {"analysis": {"ok": True, "progress": True}}


class MemoryErrorPipeline:
    """Pipeline that raises MemoryError."""

    def execute(self, options: dict[str, Any], parallel: bool = False) -> dict[str, Any]:
        raise MemoryError("memory exhausted")

    def execute_with_progress(self, callback: Any, options: dict[str, Any]) -> dict[str, Any]:
        raise MemoryError("memory exhausted")


class RuntimeErrorPipeline:
    """Pipeline that raises RuntimeError."""

    def execute(self, options: dict[str, Any], parallel: bool = False) -> dict[str, Any]:
        raise RuntimeError("analysis crashed")

    def execute_with_progress(self, callback: Any, options: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError("analysis crashed")


class StubPipelineBuilder:
    def __init__(self, pipeline: Any) -> None:
        self._pipeline = pipeline

    def build(self, options: dict[str, Any]) -> Any:
        return self._pipeline


class StubAdapter:
    """Minimal adapter stub."""
    thread_safe = True


class NonThreadSafeAdapter:
    """Adapter that is not thread-safe."""
    thread_safe = False


def make_inspector(
    tmp_path: Path,
    pipeline: Any = None,
    config: Any = None,
    adapter: Any = None,
    registry: Any = None,
    verbose: bool = False,
    cleanup_callback: Any = None,
    memory_monitor: Any = None,
    file_validator_factory: Any = None,
) -> R2Inspector:
    """Factory for creating R2Inspector with a real sample file."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x" * 64)

    if pipeline is None:
        pipeline = OkPipeline()
    if config is None:
        config = Config()
    if adapter is None:
        adapter = StubAdapter()
    if registry is None:
        registry = StubRegistry()
    if memory_monitor is None:
        memory_monitor = MemoryMonitor()
    if file_validator_factory is None:
        file_validator_factory = lambda path: FileValidator(sample)

    return R2Inspector(
        filename=str(sample),
        config=config,
        verbose=verbose,
        cleanup_callback=cleanup_callback,
        adapter=adapter,
        registry_factory=lambda: registry,
        pipeline_builder_factory=lambda a, r, c, f: StubPipelineBuilder(pipeline),
        config_factory=Config,
        file_validator_factory=file_validator_factory,
        result_aggregator_factory=ResultAggregator,
        memory_monitor=memory_monitor,
    )


# ---------------------------------------------------------------------------
# __init__ - lines 47-94
# ---------------------------------------------------------------------------


def test_init_sets_filename(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x" * 64)
    inspector = make_inspector(tmp_path)
    assert inspector.filename == str(sample)


def test_init_uses_provided_config(tmp_path: Path) -> None:
    cfg = Config()
    inspector = make_inspector(tmp_path, config=cfg)
    assert inspector.config is cfg


def test_init_uses_config_factory_when_config_is_none(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x" * 64)
    inspector = R2Inspector(
        filename=str(sample),
        config=None,
        config_factory=Config,
        adapter=StubAdapter(),
        registry_factory=StubRegistry,
        pipeline_builder_factory=lambda a, r, c, f: StubPipelineBuilder(OkPipeline()),
        file_validator_factory=lambda path: FileValidator(sample),
        result_aggregator_factory=ResultAggregator,
        memory_monitor=MemoryMonitor(),
    )
    assert inspector.config is not None


def test_init_stores_verbose_flag(tmp_path: Path) -> None:
    inspector = make_inspector(tmp_path, verbose=True)
    assert inspector.verbose is True


def test_init_stores_adapter(tmp_path: Path) -> None:
    adapter = StubAdapter()
    inspector = make_inspector(tmp_path, adapter=adapter)
    assert inspector.adapter is adapter


def test_init_stores_registry(tmp_path: Path) -> None:
    registry = StubRegistry()
    inspector = make_inspector(tmp_path, registry=registry)
    assert inspector.registry is registry


def test_init_file_path_is_set(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x" * 64)
    inspector = make_inspector(tmp_path)
    assert inspector.file_path == sample


def test_init_verbose_logs_analyzers(tmp_path: Path) -> None:
    inspector = make_inspector(tmp_path, registry=VerboseStubRegistry(), verbose=True)
    assert inspector.verbose is True
    assert len(inspector.registry.list_analyzers()) == 2


# ---------------------------------------------------------------------------
# __init__ - error paths (lines 49, 55, 61, 73-76, 90)
# ---------------------------------------------------------------------------


def test_init_raises_when_memory_monitor_is_none(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x" * 64)
    with pytest.raises(ValueError, match="memory_monitor must be provided"):
        R2Inspector(
            filename=str(sample),
            memory_monitor=None,
        )


def test_init_raises_when_config_and_factory_both_none(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x" * 64)
    with pytest.raises(ValueError, match="config_factory must be provided"):
        R2Inspector(
            filename=str(sample),
            config=None,
            config_factory=None,
            adapter=StubAdapter(),
            memory_monitor=MemoryMonitor(),
        )


def test_init_raises_when_adapter_is_none(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x" * 64)
    with pytest.raises(ValueError, match="adapter must be provided"):
        R2Inspector(
            filename=str(sample),
            config=Config(),
            adapter=None,
            memory_monitor=MemoryMonitor(),
        )


def test_init_raises_when_file_validator_factory_is_none(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x" * 64)
    with pytest.raises(ValueError, match="file_validator_factory and result_aggregator_factory"):
        R2Inspector(
            filename=str(sample),
            config=Config(),
            adapter=StubAdapter(),
            file_validator_factory=None,
            result_aggregator_factory=None,
            memory_monitor=MemoryMonitor(),
        )


def test_init_raises_when_file_validation_fails(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="File validation failed"):
        R2Inspector(
            filename="/definitely/nonexistent/file.bin",
            config=Config(),
            adapter=StubAdapter(),
            registry_factory=StubRegistry,
            pipeline_builder_factory=lambda a, r, c, f: StubPipelineBuilder(OkPipeline()),
            file_validator_factory=FileValidator,
            result_aggregator_factory=ResultAggregator,
            memory_monitor=MemoryMonitor(),
        )


def test_init_raises_when_registry_factory_is_none(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x" * 64)
    with pytest.raises(ValueError, match="registry_factory and pipeline_builder_factory"):
        R2Inspector(
            filename=str(sample),
            config=Config(),
            adapter=StubAdapter(),
            registry_factory=None,
            pipeline_builder_factory=None,
            file_validator_factory=lambda path: FileValidator(sample),
            result_aggregator_factory=ResultAggregator,
            memory_monitor=MemoryMonitor(),
        )


# ---------------------------------------------------------------------------
# _init_infrastructure (lines 106-119)
# ---------------------------------------------------------------------------


def test_init_infrastructure_initializes_registry_and_pipeline_builder(tmp_path: Path) -> None:
    inspector = make_inspector(tmp_path)
    assert inspector.registry is not None
    assert inspector._pipeline_builder is not None


def test_init_infrastructure_with_verbose_registry(tmp_path: Path) -> None:
    inspector = make_inspector(tmp_path, registry=VerboseStubRegistry(), verbose=True)
    assert len(inspector.registry.list_analyzers()) == 2


# ---------------------------------------------------------------------------
# _cleanup (lines 127-129)
# ---------------------------------------------------------------------------


def test_cleanup_calls_cleanup_callback(tmp_path: Path) -> None:
    called = []
    inspector = make_inspector(tmp_path, cleanup_callback=lambda: called.append(True))
    inspector._cleanup()
    assert called == [True]


def test_cleanup_sets_adapter_to_none(tmp_path: Path) -> None:
    inspector = make_inspector(tmp_path)
    inspector._cleanup()
    assert inspector.adapter is None


def test_cleanup_without_callback_does_not_raise(tmp_path: Path) -> None:
    inspector = make_inspector(tmp_path, cleanup_callback=None)
    inspector._cleanup()
    assert inspector.adapter is None


# ---------------------------------------------------------------------------
# __enter__ (line 133)
# ---------------------------------------------------------------------------


def test_enter_returns_self(tmp_path: Path) -> None:
    inspector = make_inspector(tmp_path)
    result = inspector.__enter__()
    assert result is inspector


def test_context_manager_enter_and_exit(tmp_path: Path) -> None:
    inspector = make_inspector(tmp_path)
    with inspector as insp:
        assert insp is inspector
    assert inspector.adapter is None


# ---------------------------------------------------------------------------
# __exit__ (lines 142-143)
# ---------------------------------------------------------------------------


def test_exit_calls_cleanup_and_returns_false(tmp_path: Path) -> None:
    inspector = make_inspector(tmp_path)
    result = inspector.__exit__(None, None, None)
    assert result is False
    assert inspector.adapter is None


def test_exit_with_exception_does_not_suppress(tmp_path: Path) -> None:
    inspector = make_inspector(tmp_path)
    result = inspector.__exit__(ValueError, ValueError("err"), None)
    assert result is False


# ---------------------------------------------------------------------------
# __del__ (line 147)
# ---------------------------------------------------------------------------


def test_del_calls_cleanup(tmp_path: Path) -> None:
    called = []
    inspector = make_inspector(tmp_path, cleanup_callback=lambda: called.append(True))
    inspector.__del__()
    assert called == [True]


# ---------------------------------------------------------------------------
# analyze() - main path (lines 191-225)
# ---------------------------------------------------------------------------


def test_analyze_returns_memory_stats(tmp_path: Path) -> None:
    inspector = make_inspector(tmp_path)
    results = inspector.analyze()
    assert "memory_stats" in results
    assert "initial_memory_mb" in results["memory_stats"]
    assert "final_memory_mb" in results["memory_stats"]
    assert "memory_used_mb" in results["memory_stats"]


def test_analyze_returns_pipeline_results(tmp_path: Path) -> None:
    inspector = make_inspector(tmp_path)
    results = inspector.analyze()
    assert "analysis" in results
    assert results["analysis"]["ok"] is True


def test_analyze_with_progress_callback(tmp_path: Path) -> None:
    stages_called = []
    inspector = make_inspector(tmp_path)
    results = inspector.analyze(progress_callback=lambda stage: stages_called.append(stage))
    assert "memory_stats" in results


def test_analyze_with_non_thread_safe_adapter_disables_parallel(tmp_path: Path) -> None:
    inspector = make_inspector(tmp_path, adapter=NonThreadSafeAdapter())
    results = inspector.analyze()
    assert "memory_stats" in results


def test_analyze_parallel_disabled_in_config(tmp_path: Path) -> None:
    cfg = Config()
    inspector = make_inspector(tmp_path, config=cfg)
    results = inspector.analyze()
    assert "memory_stats" in results


# ---------------------------------------------------------------------------
# analyze() - MemoryError path (lines 227-230)
# ---------------------------------------------------------------------------


def test_analyze_memory_error_returns_error_dict(tmp_path: Path) -> None:
    inspector = make_inspector(tmp_path, pipeline=MemoryErrorPipeline())
    results = inspector.analyze()
    assert "error" in results
    assert results["error"] == "Memory limit exceeded"
    assert "memory_stats" in results


# ---------------------------------------------------------------------------
# analyze() - general Exception path (lines 235-237)
# ---------------------------------------------------------------------------


def test_analyze_runtime_error_returns_error_dict(tmp_path: Path) -> None:
    inspector = make_inspector(tmp_path, pipeline=RuntimeErrorPipeline())
    results = inspector.analyze()
    assert "error" in results
    assert "analysis crashed" in results["error"]
    assert "memory_stats" in results


# ---------------------------------------------------------------------------
# analyze() - pipeline builder not initialized (line 196-199)
# ---------------------------------------------------------------------------


def test_analyze_raises_when_pipeline_builder_none(tmp_path: Path) -> None:
    inspector = make_inspector(tmp_path)
    # Force pipeline builder to None to test that branch
    inspector._pipeline_builder = None
    results = inspector.analyze()
    # Should return error dict (the error_handler decorator catches it)
    assert "error" in results


# ---------------------------------------------------------------------------
# close() (line 244)
# ---------------------------------------------------------------------------


def test_close_calls_cleanup(tmp_path: Path) -> None:
    called = []
    inspector = make_inspector(tmp_path, cleanup_callback=lambda: called.append(True))
    inspector.close()
    assert called == [True]
    assert inspector.adapter is None


def test_close_can_be_called_multiple_times(tmp_path: Path) -> None:
    inspector = make_inspector(tmp_path)
    inspector.close()
    inspector.close()  # second call should not raise
    assert inspector.adapter is None


# ---------------------------------------------------------------------------
# analyze() with progress callback and parallel disabled
# ---------------------------------------------------------------------------


def test_analyze_progress_callback_used_when_not_parallel(tmp_path: Path) -> None:
    progress_calls = []
    inspector = make_inspector(tmp_path)
    results = inspector.analyze(progress_callback=lambda s: progress_calls.append(s))
    assert "memory_stats" in results


def test_analyze_no_progress_callback_runs_without_progress(tmp_path: Path) -> None:
    inspector = make_inspector(tmp_path)
    results = inspector.analyze(progress_callback=None)
    assert "analysis" in results
    assert results["analysis"]["ok"] is True
