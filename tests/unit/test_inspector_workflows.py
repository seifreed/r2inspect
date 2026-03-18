"""Comprehensive tests for core/inspector.py workflows and execution paths."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.config import Config
from r2inspect.config_schemas.schemas import PipelineConfig, R2InspectConfig
from r2inspect.core.file_validator import FileValidator
from r2inspect.core.inspector import R2Inspector
from r2inspect.core.result_aggregator import ResultAggregator
from r2inspect.infrastructure.memory import MemoryMonitor
from r2inspect.pipeline.analysis_pipeline import AnalysisPipeline
from r2inspect.registry.analyzer_registry import AnalyzerRegistry


# ---------------------------------------------------------------------------
# Lightweight fakes that satisfy the real interfaces without spawning r2pipe
# ---------------------------------------------------------------------------


class FakeR2:
    """Minimal r2pipe stand-in."""

    def __init__(
        self, cmdj_map: dict[str, Any] | None = None, cmd_map: dict[str, Any] | None = None
    ):
        self.cmdj_map = cmdj_map or {}
        self.cmd_map = cmd_map or {}

    def cmdj(self, command: str) -> Any:
        return self.cmdj_map.get(command, {})

    def cmd(self, command: str) -> str:
        return self.cmd_map.get(command, "")


class FakeFileValidator:
    """FileValidator substitute whose validate() result is configurable."""

    def __init__(self, result: bool = True):
        self._result = result
        self.validate_called = False

    def validate(self) -> bool:
        self.validate_called = True
        return self._result

    def _file_size_mb(self) -> float:
        return 0.01


class FakePipeline:
    """Minimal pipeline that records calls and returns canned results."""

    def __init__(self, result: dict[str, Any] | None = None, *, error: Exception | None = None):
        self._result = result or {}
        self._error = error
        self.execute_calls: list[tuple[dict, bool]] = []
        self.execute_with_progress_calls: list[tuple[Any, dict]] = []

    def execute(
        self, options: dict[str, Any] | None = None, parallel: bool = False
    ) -> dict[str, Any]:
        if self._error is not None:
            raise self._error
        self.execute_calls.append((options or {}, parallel))
        return dict(self._result)

    def execute_with_progress(
        self, progress_callback: Any, options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        if self._error is not None:
            raise self._error
        self.execute_with_progress_calls.append((progress_callback, options or {}))
        return dict(self._result)


class FakePipelineBuilder:
    """PipelineBuilder substitute that yields a FakePipeline."""

    def __init__(self, pipeline: FakePipeline | None = None):
        self._pipeline = pipeline or FakePipeline()
        self.build_calls: list[dict] = []

    def build(self, options: dict[str, Any]) -> FakePipeline:
        self.build_calls.append(options)
        return self._pipeline


class FakeAdapter:
    """Lightweight adapter that does not require a live r2pipe session."""

    thread_safe = False

    def __init__(self):
        self._cache: dict[str, Any] = {}
        import threading

        self._cache_lock = threading.Lock()

    def cmd(self, command: str) -> str:
        return ""

    def cmdj(self, command: str) -> Any:
        return {}

    def execute_command(self, command: str) -> Any:
        return None


class ThreadSafeFakeAdapter(FakeAdapter):
    """Adapter variant that reports itself as thread-safe."""

    thread_safe = True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_registry() -> AnalyzerRegistry:
    """Return a real (empty) registry."""
    registry = AnalyzerRegistry(lazy_loading=False)
    return registry


def _make_memory_monitor() -> MemoryMonitor:
    """Return a real memory monitor."""
    return MemoryMonitor()


def _make_config(parallel_execution: bool = True) -> Config:
    """Return a real Config with default settings and optional pipeline overrides."""
    config = Config(config_path="/dev/null")
    new_pipeline = dataclasses.replace(
        config.typed_config.pipeline, parallel_execution=parallel_execution
    )
    config._typed_config = dataclasses.replace(config.typed_config, pipeline=new_pipeline)
    return config


def _make_inspector(
    *,
    adapter: Any | None = None,
    config: Config | None = None,
    verbose: bool = False,
    cleanup_callback: Any = None,
    file_validator_result: bool = True,
    pipeline_builder: FakePipelineBuilder | None = None,
    registry: AnalyzerRegistry | None = None,
    memory_monitor: MemoryMonitor | None = None,
) -> R2Inspector:
    """Build an R2Inspector wired to real lightweight objects."""
    adapter = adapter if adapter is not None else FakeAdapter()
    config = config if config is not None else _make_config()
    memory_monitor = memory_monitor if memory_monitor is not None else _make_memory_monitor()
    registry = registry if registry is not None else _make_registry()
    pipeline_builder = pipeline_builder if pipeline_builder is not None else FakePipelineBuilder()

    fv = FakeFileValidator(result=file_validator_result)

    return R2Inspector(
        filename="/tmp/test.bin",
        config=config,
        verbose=verbose,
        adapter=adapter,
        memory_monitor=memory_monitor,
        cleanup_callback=cleanup_callback,
        file_validator_factory=lambda _f: fv,
        result_aggregator_factory=ResultAggregator,
        registry_factory=lambda: registry,
        pipeline_builder_factory=lambda _a, _r, _c, _f: pipeline_builder,
    )


# ===========================================================================
# Tests
# ===========================================================================


class TestInspectorInitialization:
    """Test R2Inspector initialization and dependency injection."""

    def test_init_with_all_dependencies(self) -> None:
        """Test successful initialization with all required dependencies."""
        adapter = FakeAdapter()
        memory = _make_memory_monitor()
        config = _make_config(parallel_execution=False)

        fv = FakeFileValidator(result=True)
        aggregator = ResultAggregator()
        registry = _make_registry()
        pb = FakePipelineBuilder()

        inspector = R2Inspector(
            filename="/tmp/test.bin",
            config=config,
            verbose=False,
            adapter=adapter,
            memory_monitor=memory,
            file_validator_factory=lambda _: fv,
            result_aggregator_factory=lambda: aggregator,
            registry_factory=lambda: registry,
            pipeline_builder_factory=lambda a, r, c, f: pb,
        )

        assert inspector.filename == "/tmp/test.bin"
        assert inspector.adapter is adapter
        assert inspector.config is config
        assert inspector.verbose is False
        assert inspector.registry is registry
        assert fv.validate_called

    def test_init_without_memory_monitor_raises(self) -> None:
        """Test initialization fails without memory monitor."""
        adapter = FakeAdapter()
        with pytest.raises(ValueError, match="memory_monitor must be provided"):
            R2Inspector(
                filename="/tmp/test.bin",
                adapter=adapter,
                memory_monitor=None,
                registry_factory=lambda: _make_registry(),
                pipeline_builder_factory=lambda a, r, c, f: FakePipelineBuilder(),
            )

    def test_init_without_adapter_raises(self) -> None:
        """Test initialization fails without adapter."""
        memory = _make_memory_monitor()
        config = _make_config()
        with pytest.raises(ValueError, match="adapter must be provided"):
            R2Inspector(
                filename="/tmp/test.bin",
                memory_monitor=memory,
                config=config,
                adapter=None,
            )

    def test_init_without_config_uses_factory(self) -> None:
        """Test config is created from factory when not provided."""
        adapter = FakeAdapter()
        memory = _make_memory_monitor()
        config = _make_config(parallel_execution=False)

        fv = FakeFileValidator(result=True)
        aggregator = ResultAggregator()
        registry = _make_registry()
        pb = FakePipelineBuilder()

        inspector = R2Inspector(
            filename="/tmp/test.bin",
            adapter=adapter,
            memory_monitor=memory,
            config=None,
            config_factory=lambda: config,
            file_validator_factory=lambda _: fv,
            result_aggregator_factory=lambda: aggregator,
            registry_factory=lambda: registry,
            pipeline_builder_factory=lambda a, r, c, f: pb,
        )

        assert inspector.config is config

    def test_init_without_config_factory_raises(self) -> None:
        """Test initialization fails when config is None and no factory provided."""
        adapter = FakeAdapter()
        memory = _make_memory_monitor()
        with pytest.raises(ValueError, match="config_factory must be provided when config is None"):
            R2Inspector(
                filename="/tmp/test.bin",
                adapter=adapter,
                memory_monitor=memory,
                config=None,
                config_factory=None,
                registry_factory=lambda: _make_registry(),
                pipeline_builder_factory=lambda a, r, c, f: FakePipelineBuilder(),
            )

    def test_init_without_factories_raises(self) -> None:
        """Test initialization fails without required factories."""
        adapter = FakeAdapter()
        memory = _make_memory_monitor()
        config = _make_config()

        with pytest.raises(
            ValueError,
            match="file_validator_factory and result_aggregator_factory must be provided",
        ):
            R2Inspector(
                filename="/tmp/test.bin",
                adapter=adapter,
                memory_monitor=memory,
                config=config,
                registry_factory=lambda: _make_registry(),
                pipeline_builder_factory=lambda a, r, c, f: FakePipelineBuilder(),
                file_validator_factory=None,
                result_aggregator_factory=None,
            )

    def test_init_file_validation_failure(self) -> None:
        """Test initialization fails when file validation fails."""
        adapter = FakeAdapter()
        memory = _make_memory_monitor()
        config = _make_config()

        fv = FakeFileValidator(result=False)

        with pytest.raises(ValueError, match="File validation failed"):
            R2Inspector(
                filename="/tmp/nonexistent.bin",
                adapter=adapter,
                memory_monitor=memory,
                config=config,
                file_validator_factory=lambda _: fv,
                result_aggregator_factory=ResultAggregator,
                registry_factory=_make_registry,
                pipeline_builder_factory=lambda a, r, c, f: FakePipelineBuilder(),
            )

    def test_init_without_registry_factory_raises(self) -> None:
        """Test initialization fails without registry_factory."""
        adapter = FakeAdapter()
        memory = _make_memory_monitor()
        config = _make_config()
        fv = FakeFileValidator(result=True)

        with pytest.raises(
            ValueError, match="registry_factory and pipeline_builder_factory must be provided"
        ):
            R2Inspector(
                filename="/tmp/test.bin",
                adapter=adapter,
                memory_monitor=memory,
                config=config,
                file_validator_factory=lambda _: fv,
                result_aggregator_factory=ResultAggregator,
                registry_factory=None,
                pipeline_builder_factory=None,
            )


class TestInspectorInfrastructure:
    """Test _init_infrastructure method."""

    def test_init_infrastructure_success(self) -> None:
        """Test infrastructure initialization with registry and pipeline builder."""
        registry = _make_registry()
        pb = FakePipelineBuilder()

        inspector = _make_inspector(registry=registry, pipeline_builder=pb)

        assert inspector.registry is registry
        assert inspector._pipeline_builder is pb

    def test_init_infrastructure_verbose_logging(self) -> None:
        """Test infrastructure initialization with verbose mode runs without error."""
        registry = _make_registry()
        pb = FakePipelineBuilder()

        inspector = _make_inspector(verbose=True, registry=registry, pipeline_builder=pb)

        # Verbose mode should complete without error; registry is usable.
        assert inspector.registry is registry


class TestInspectorAnalyze:
    """Test analyze method and execution workflows."""

    def test_analyze_sequential_execution(self) -> None:
        """Test analyze method with sequential pipeline execution."""
        pipeline = FakePipeline(result={"test": "result"})
        pb = FakePipelineBuilder(pipeline=pipeline)
        config = _make_config(parallel_execution=False)

        inspector = _make_inspector(config=config, pipeline_builder=pb)

        options = {"batch_mode": True}
        result = inspector.analyze(**options)

        assert "test" in result
        assert result["test"] == "result"
        assert "memory_stats" in result
        assert isinstance(result["memory_stats"]["initial_memory_mb"], float)
        assert len(pb.build_calls) == 1
        assert pb.build_calls[0] == options
        assert len(pipeline.execute_calls) == 1
        assert pipeline.execute_calls[0] == (options, False)

    def test_analyze_parallel_execution_thread_safe(self) -> None:
        """Test analyze method with parallel execution when adapter is thread-safe."""
        pipeline = FakePipeline(result={"parallel": "result"})
        pb = FakePipelineBuilder(pipeline=pipeline)
        config = _make_config(parallel_execution=True)
        adapter = ThreadSafeFakeAdapter()

        inspector = _make_inspector(adapter=adapter, config=config, pipeline_builder=pb)

        result = inspector.analyze()

        assert len(pipeline.execute_calls) == 1
        assert pipeline.execute_calls[0][1] is True  # parallel=True
        assert "parallel" in result

    def test_analyze_parallel_disabled_when_not_thread_safe(self) -> None:
        """Test parallel execution is disabled when adapter is not thread-safe."""
        pipeline = FakePipeline(result={})
        pb = FakePipelineBuilder(pipeline=pipeline)
        config = _make_config(parallel_execution=True)
        adapter = FakeAdapter()  # thread_safe = False

        inspector = _make_inspector(adapter=adapter, config=config, pipeline_builder=pb)
        inspector.analyze()

        assert len(pipeline.execute_calls) == 1
        assert pipeline.execute_calls[0][1] is False  # parallel forced to False

    def test_analyze_with_progress_callback(self) -> None:
        """Test analyze method with progress callback in sequential mode."""
        pipeline = FakePipeline(result={"progress": "tracked"})
        pb = FakePipelineBuilder(pipeline=pipeline)
        config = _make_config(parallel_execution=False)

        inspector = _make_inspector(config=config, pipeline_builder=pb)

        callback_calls: list[str] = []

        def progress_callback(msg: str, *_args: Any) -> None:
            callback_calls.append(msg)

        options = {"detect_packer": True}
        result = inspector.analyze(progress_callback=progress_callback, **options)

        assert result["progress"] == "tracked"
        assert len(pipeline.execute_with_progress_calls) == 1
        cb_arg, opts_arg = pipeline.execute_with_progress_calls[0]
        assert cb_arg is progress_callback
        assert opts_arg == options

    def test_analyze_memory_error_handling(self) -> None:
        """Test analyze handles MemoryError gracefully."""
        pipeline = FakePipeline(error=MemoryError("Out of memory"))
        pb = FakePipelineBuilder(pipeline=pipeline)
        config = _make_config(parallel_execution=False)

        inspector = _make_inspector(config=config, pipeline_builder=pb)

        result = inspector.analyze()

        assert "error" in result
        assert "Memory limit exceeded" in result["error"]
        assert "memory_stats" in result

    def test_analyze_generic_exception_handling(self) -> None:
        """Test analyze handles generic exceptions gracefully."""
        pipeline = FakePipeline(error=RuntimeError("Pipeline failed"))
        pb = FakePipelineBuilder(pipeline=pipeline)
        config = _make_config(parallel_execution=False)

        inspector = _make_inspector(config=config, pipeline_builder=pb)

        result = inspector.analyze()

        assert "error" in result
        assert "Pipeline failed" in result["error"]

    def test_analyze_pipeline_builder_not_initialized(self) -> None:
        """Test analyze raises when pipeline builder is not initialized."""
        config = _make_config(parallel_execution=False)

        inspector = _make_inspector(config=config)
        inspector._pipeline_builder = None

        result = inspector.analyze()

        assert "error" in result
        assert "Pipeline builder is not initialized" in result["error"]


class TestInspectorCleanup:
    """Test cleanup and context manager functionality."""

    def test_cleanup_with_callback(self) -> None:
        """Test cleanup calls cleanup callback."""
        cleanup_called: list[bool] = []

        def cleanup_callback() -> None:
            cleanup_called.append(True)

        inspector = _make_inspector(cleanup_callback=cleanup_callback)
        inspector._cleanup()

        assert len(cleanup_called) == 1
        assert inspector.adapter is None

    def test_cleanup_without_callback(self) -> None:
        """Test cleanup without callback doesn't crash."""
        inspector = _make_inspector(cleanup_callback=None)
        inspector._cleanup()

        assert inspector.adapter is None

    def test_context_manager_enter(self) -> None:
        """Test context manager __enter__ returns self."""
        inspector = _make_inspector()
        result = inspector.__enter__()

        assert result is inspector

    def test_context_manager_exit_cleanup(self) -> None:
        """Test context manager __exit__ calls cleanup."""
        cleanup_called: list[bool] = []

        def cleanup_callback() -> None:
            cleanup_called.append(True)

        inspector = _make_inspector(cleanup_callback=cleanup_callback)
        result = inspector.__exit__(None, None, None)

        assert result is False
        assert len(cleanup_called) == 1

    def test_destructor_cleanup(self) -> None:
        """Test __del__ calls cleanup."""
        cleanup_called: list[bool] = []

        def cleanup_callback() -> None:
            cleanup_called.append(True)

        inspector = _make_inspector(cleanup_callback=cleanup_callback)
        inspector.__del__()

        assert len(cleanup_called) == 1

    def test_close_method(self) -> None:
        """Test close method calls cleanup."""
        cleanup_called: list[bool] = []

        def cleanup_callback() -> None:
            cleanup_called.append(True)

        inspector = _make_inspector(cleanup_callback=cleanup_callback)
        inspector.close()

        assert len(cleanup_called) == 1
