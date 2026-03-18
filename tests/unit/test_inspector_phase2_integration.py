"""Phase 2 inspector integration tests with stubbed dependencies."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from r2inspect.core.inspector import R2Inspector


class _DummyMemoryMonitor:
    def __init__(self) -> None:
        self.gc_calls: list[bool] = []

    def check_memory(self, force: bool = False) -> dict[str, float | int]:
        return {
            "process_memory_mb": 100.0,
            "peak_memory_mb": 120.0,
            "gc_count": 2,
        }

    def is_memory_available(self, required_mb: float) -> bool:
        return True

    def _trigger_gc(self, aggressive: bool = False) -> None:
        self.gc_calls.append(aggressive)


class _DummyValidator:
    def __init__(self, valid: bool = True) -> None:
        self._valid = valid

    def validate(self) -> bool:
        return self._valid

    def _file_size_mb(self) -> float:
        return 1.0


class _DummyAdapter:
    def __init__(self, thread_safe: bool = True) -> None:
        self.thread_safe = thread_safe


class _DummyPipeline:
    def __init__(self, analysis_result: dict[str, Any]) -> None:
        self.analysis_result = analysis_result
        self.executed_without_progress: list[tuple[bool]] = []
        self.executed_with_progress: list[tuple[bool]] = []

    def execute(self, _options: dict[str, Any], parallel: bool = False) -> dict[str, Any]:
        self.executed_without_progress.append((parallel,))
        return dict(self.analysis_result)

    def execute_with_progress(
        self,
        _callback: Any,
        _options: dict[str, Any],
    ) -> dict[str, Any]:
        self.executed_with_progress.append((True,))
        return dict(self.analysis_result)

    def build(self, _options: dict[str, Any]) -> _DummyPipeline:
        return self


class _DummyPipelineBuilder:
    def __init__(self, pipeline: _DummyPipeline) -> None:
        self.pipeline = pipeline
        self.build_called = 0

    def __call__(self, *_args: Any, **_kwargs: Any) -> _DummyPipeline:
        self.build_called += 1
        return self.pipeline

    def build(self, _options: dict[str, Any]) -> _DummyPipeline:
        self.build_called += 1
        return self.pipeline


class _DummyRegistry:
    def __len__(self) -> int:
        return 1

    def list_analyzers(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "pe_analyzer",
                "category": "format",
                "file_formats": ["PE", "ELF", "Mach-O"],
            }
        ]


class _DummyConfig:
    def __init__(self, parallel_execution: bool) -> None:
        self.typed_config = SimpleNamespace(
            pipeline=SimpleNamespace(parallel_execution=parallel_execution)
        )


class _DummyAggregator:
    def __init__(self) -> None:
        self.indicator_calls = 0
        self.summary_calls = 0

    def generate_indicators(self, analysis_results: dict[str, Any]) -> list[dict[str, Any]]:
        self.indicator_calls += 1
        return [
            {"type": "stub", "severity": "low", "description": analysis_results.get("marker", "")}
        ]

    def generate_executive_summary(self, analysis_results: dict[str, Any]) -> dict[str, Any]:
        self.summary_calls += 1
        return {"marker": analysis_results.get("marker", "unknown")}


def _build_inspector(
    *,
    memory_monitor: _DummyMemoryMonitor,
    config: _DummyConfig,
    adapter: _DummyAdapter,
    builder: _DummyPipelineBuilder,
    aggregator: _DummyAggregator,
    validator: _DummyValidator | None = None,
    cleanup: tuple[bool] | None = None,
) -> R2Inspector:
    if cleanup is None:
        cleanup = (False,)

    called = {"done": False}

    def cleanup_fn() -> None:
        called["done"] = True

    inspector = R2Inspector(
        filename="sample.bin",
        config=config,
        verbose=False,
        cleanup_callback=cleanup_fn if cleanup[0] else None,
        adapter=adapter,
        registry_factory=_DummyRegistry,
        pipeline_builder_factory=builder,
        config_factory=None,
        file_validator_factory=lambda _: validator or _DummyValidator(),
        result_aggregator_factory=lambda: aggregator,
        memory_monitor=memory_monitor,
    )
    inspector._test_cleanup_state = called
    return inspector


def test_inspector_init_validation_paths() -> None:
    """Cover constructor validation branches without launching external processes."""
    monitor = _DummyMemoryMonitor()

    with pytest.raises(ValueError, match="memory_monitor must be provided"):
        _ = R2Inspector(filename="sample.bin", memory_monitor=None)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="config_factory must be provided when config is None"):
        R2Inspector(
            filename="sample.bin",
            config=None,
            adapter=_DummyAdapter(),
            registry_factory=_DummyRegistry,
            pipeline_builder_factory=_DummyPipelineBuilder(_DummyPipeline({})),
            file_validator_factory=_DummyValidator,
            result_aggregator_factory=_DummyAggregator,
            memory_monitor=monitor,
        )

    with pytest.raises(ValueError, match="adapter must be provided"):
        R2Inspector(
            filename="sample.bin",
            config=_DummyConfig(True),
            adapter=None,  # type: ignore[arg-type]
            registry_factory=_DummyRegistry,
            pipeline_builder_factory=_DummyPipelineBuilder(_DummyPipeline({})),
            file_validator_factory=_DummyValidator,
            result_aggregator_factory=_DummyAggregator,
            memory_monitor=monitor,
        )

    with pytest.raises(ValueError, match="file_validator_factory and result_aggregator_factory"):
        R2Inspector(
            filename="sample.bin",
            config=_DummyConfig(True),
            adapter=_DummyAdapter(),
            registry_factory=_DummyRegistry,
            pipeline_builder_factory=_DummyPipelineBuilder(_DummyPipeline({})),
            result_aggregator_factory=_DummyAggregator,
            memory_monitor=monitor,
            file_validator_factory=None,  # type: ignore[arg-type]
        )

    with pytest.raises(ValueError, match="registry_factory and pipeline_builder_factory"):
        R2Inspector(
            filename="sample.bin",
            config=_DummyConfig(True),
            adapter=_DummyAdapter(),
            registry_factory=None,  # type: ignore[arg-type]
            pipeline_builder_factory=None,  # type: ignore[arg-type]
            file_validator_factory=_DummyValidator,
            result_aggregator_factory=_DummyAggregator,
            memory_monitor=monitor,
        )


def test_inspector_init_validation_failed_file() -> None:
    """Cover file-validator failure path in constructor."""
    monitor = _DummyMemoryMonitor()
    with pytest.raises(ValueError, match="File validation failed"):
        R2Inspector(
            filename="invalid.bin",
            config=_DummyConfig(True),
            adapter=_DummyAdapter(),
            registry_factory=_DummyRegistry,
            pipeline_builder_factory=_DummyPipelineBuilder(_DummyPipeline({})),
            file_validator_factory=lambda _: _DummyValidator(False),
            result_aggregator_factory=_DummyAggregator,
            memory_monitor=monitor,
        )


def test_inspector_analyze_with_progress_and_context_manager() -> None:
    """Cover progress callback path, memory stats, and cleanup callback flow."""
    memory = _DummyMemoryMonitor()
    agg = _DummyAggregator()
    pipeline = _DummyPipeline({"file_info": {"name": "sample.bin"}, "marker": "ok"})
    builder = _DummyPipelineBuilder(pipeline)
    inspector = _build_inspector(
        memory_monitor=memory,
        config=_DummyConfig(False),
        adapter=_DummyAdapter(thread_safe=True),
        builder=builder,
        aggregator=agg,
        validator=_DummyValidator(),
        cleanup=(True,),
    )

    progress_calls: list[str] = []

    with inspector as active:
        results = active.analyze(progress_callback=lambda stage: progress_calls.append(stage))

    assert progress_calls == []
    assert results["memory_stats"]["peak_memory_mb"] == 120.0
    assert pipeline.executed_with_progress == [(True,)]
    assert active._test_cleanup_state["done"] is True


def test_inspector_analyze_without_progress_and_parallel_disabled_for_thread_unsafe_adapter() -> (
    None
):
    """Cover non-progress branch and thread-safe override branch when configured parallel is enabled."""
    memory = _DummyMemoryMonitor()
    agg = _DummyAggregator()
    pipeline = _DummyPipeline({"file_info": {"name": "sample.bin"}, "marker": "ok"})
    builder = _DummyPipelineBuilder(pipeline)
    inspector = _build_inspector(
        memory_monitor=memory,
        config=_DummyConfig(True),
        adapter=_DummyAdapter(thread_safe=False),
        builder=builder,
        aggregator=agg,
        validator=_DummyValidator(),
    )

    results = inspector.analyze()

    assert pipeline.executed_without_progress == [(False,)]
    assert results["memory_stats"]["final_memory_mb"] == 100.0


def test_inspector_analyze_memory_error_fallback() -> None:
    """Cover MemoryError handling branch in analyze() path."""
    memory = _DummyMemoryMonitor()
    agg = _DummyAggregator()
    pipeline = _DummyPipeline({"file_info": {"name": "sample.bin"}})

    def execute_with_error(_options: dict[str, Any], parallel: bool = False) -> dict[str, Any]:
        raise MemoryError("out of memory")

    pipeline.execute = execute_with_error

    inspector = _build_inspector(
        memory_monitor=memory,
        config=_DummyConfig(False),
        adapter=_DummyAdapter(),
        builder=_DummyPipelineBuilder(pipeline),
        aggregator=agg,
        validator=_DummyValidator(),
    )
    result = inspector.analyze()

    assert result["error"] == "Memory limit exceeded"
    assert memory.gc_calls == [True]


def test_inspector_analyze_generic_error_and_aggregator_delegation() -> None:
    """Cover generic exception recovery and wrapper methods to result aggregator."""
    memory = _DummyMemoryMonitor()
    agg = _DummyAggregator()
    pipeline = _DummyPipeline({"file_info": {"name": "sample.bin"}})

    def execute_with_error(_options: dict[str, Any], parallel: bool = False) -> dict[str, Any]:
        raise RuntimeError("boom")

    pipeline.execute = execute_with_error

    inspector = _build_inspector(
        memory_monitor=memory,
        config=_DummyConfig(False),
        adapter=_DummyAdapter(),
        builder=_DummyPipelineBuilder(pipeline),
        aggregator=agg,
        validator=_DummyValidator(),
    )
    result = inspector.analyze()
    assert result["error"] == "boom"

    indicators = inspector.generate_indicators({"marker": "custom"})
    summary = inspector.generate_executive_summary({"marker": "custom"})

    assert indicators == [{"type": "stub", "severity": "low", "description": "custom"}]
    assert summary == {"marker": "custom"}
    assert agg.indicator_calls == 1
    assert agg.summary_calls == 1
