#!/usr/bin/env python3
"""Phase 2 regression tests for r2inspect/core/inspector.py."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from r2inspect.core.inspector import R2Inspector
from r2inspect.core.result_aggregator import ResultAggregator


class DummyMemoryMonitor:
    def __init__(self) -> None:
        self.memory_mb = 12.5
        self.gc_called = False

    def check_memory(self, force: bool = False) -> dict[str, Any]:
        return {
            "process_memory_mb": self.memory_mb,
            "peak_memory_mb": self.memory_mb,
            "gc_count": 0,
        }

    def is_memory_available(self, _estimated: float) -> bool:
        return True

    def _trigger_gc(self, aggressive: bool = False) -> None:
        self.gc_called = True


class DummyFileValidator:
    def __init__(self, _filename: str, valid: bool = True) -> None:
        self._valid = valid

    def validate(self) -> bool:
        return self._valid


class DummyAdapter:
    thread_safe = True

    def __init__(self) -> None:
        pass


class DummyPipeline:
    def __init__(
        self, result: dict[str, Any] | None = None, raise_error: Exception | None = None
    ) -> None:
        self.result = result or {"ok": True}
        self.raise_error = raise_error
        self.called: list[Any] = []

    def execute_with_progress(self, _callback: Any, _options: dict[str, Any]) -> dict[str, Any]:
        self.called.append("progress")
        if self.raise_error:
            raise self.raise_error
        return dict(self.result)

    def execute(self, _options: dict[str, Any], parallel: bool = False) -> dict[str, Any]:
        self.called.append(("execute", parallel))
        if self.raise_error:
            raise self.raise_error
        return dict(self.result)


class DummyPipelineBuilder:
    def __init__(self, pipeline: DummyPipeline) -> None:
        self.pipeline = pipeline

    def build(self, _options: dict[str, Any]) -> DummyPipeline:
        return self.pipeline


class DummyRegistry:
    def __len__(self) -> int:
        return 0

    def list_analyzers(self) -> list[dict[str, Any]]:
        return []


class DummyConfig:
    class _Pipeline:
        def __init__(self, parallel: bool) -> None:
            self.parallel_execution = parallel

    class _Typed:
        def __init__(self, parallel: bool) -> None:
            self.pipeline = DummyConfig._Pipeline(parallel)

    def __init__(self, parallel: bool) -> None:
        self.typed_config = DummyConfig._Typed(parallel)


class _VerboseRegistry:
    """Registry helper for verbose branch coverage."""

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


class _HookPipeline:
    """Pipeline helper that records execute calls."""

    def __init__(self, result: dict[str, Any] | None = None) -> None:
        self.result = result or {"ok": True}
        self.calls: list[tuple[dict[str, Any], bool]] = []

    def execute(self, _options: dict[str, Any], parallel: bool = False) -> dict[str, Any]:
        self.calls.append((_options, parallel))
        return dict(self.result)

    def execute_with_progress(self, _callback: Any, _options: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((_options, True))
        return dict(self.result)


class _HookPipelineBuilder:
    def __init__(self, pipeline: _HookPipeline) -> None:
        self._pipeline = pipeline
        self.build_count = 0

    def build(self, options: dict[str, Any]) -> _HookPipeline:
        self.build_count += 1
        return self._pipeline


class _MemoryErrorPipeline:
    def execute(self, _options: dict[str, Any], parallel: bool = False) -> dict[str, Any]:
        raise MemoryError("mem limit reached")

    def execute_with_progress(self, _callback: Any, _options: dict[str, Any]) -> dict[str, Any]:
        raise MemoryError("mem limit reached")


class _BoomPipeline:
    def __init__(self, error: Exception) -> None:
        self.error = error

    def execute(self, _options: dict[str, Any], parallel: bool = False) -> dict[str, Any]:
        raise self.error

    def execute_with_progress(self, _callback: Any, _options: dict[str, Any]) -> dict[str, Any]:
        raise self.error


def _make_inspector(
    sample: Path,
    *,
    parallel: bool = False,
    adapter: DummyAdapter | None = None,
    pipeline: DummyPipeline | None = None,
    cleanup_callback: Any | None = None,
    file_valid: bool = True,
    memory_monitor: DummyMemoryMonitor | None = None,
) -> R2Inspector:
    monitor = memory_monitor if memory_monitor is not None else DummyMemoryMonitor()
    return R2Inspector(
        filename=str(sample),
        config=DummyConfig(parallel=parallel),
        verbose=False,
        cleanup_callback=cleanup_callback,
        adapter=adapter or DummyAdapter(),
        registry_factory=DummyRegistry,
        pipeline_builder_factory=lambda _adapter, _registry, _config, _filename: DummyPipelineBuilder(
            pipeline or DummyPipeline()
        ),
        config_factory=lambda: DummyConfig(parallel=parallel),
        file_validator_factory=lambda _f: DummyFileValidator(_f, valid=file_valid),
        result_aggregator_factory=ResultAggregator,
        memory_monitor=monitor,
    )


def test_inspector_context_manager_triggers_cleanup_callback(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample-data")

    cleanup_calls: list[str] = []
    with _make_inspector(
        sample, cleanup_callback=lambda: cleanup_calls.append("closed")
    ) as inspector:
        assert inspector is not None
        assert not cleanup_calls

    assert cleanup_calls == ["closed"]


def test_inspector_parallel_mode_disables_non_threadsafe_backend(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample-data")
    pipeline = DummyPipeline()
    adapter = DummyAdapter()
    adapter.thread_safe = False
    inspector = _make_inspector(sample, parallel=True, adapter=adapter, pipeline=pipeline)

    result = inspector.analyze()
    assert result["ok"] is True
    assert ("execute", False) in pipeline.called


def test_init_uses_config_factory_and_runs_verbose_path(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample-data")

    inspector = R2Inspector(
        filename=str(sample),
        config=None,
        config_factory=lambda: DummyConfig(parallel=False),
        verbose=True,
        adapter=DummyAdapter(),
        registry_factory=lambda: _VerboseRegistry(),
        pipeline_builder_factory=lambda _adapter, _registry, _config, _filename: _HookPipelineBuilder(
            _HookPipeline()
        ),
        file_validator_factory=lambda _path: DummyFileValidator(_path),
        result_aggregator_factory=ResultAggregator,
        memory_monitor=DummyMemoryMonitor(),
    )

    assert isinstance(inspector.config, DummyConfig)


def test_init_infrastructure_missing_factories_raises(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample-data")

    inspector = _make_inspector(sample, parallel=True, pipeline=_HookPipeline())
    inspector._registry_factory = None

    with pytest.raises(ValueError, match="registry_factory and pipeline_builder_factory"):
        inspector._init_infrastructure()


def test_analyze_without_pipeline_builder_returns_error(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample-data")

    inspector = _make_inspector(sample, parallel=False, pipeline=_HookPipeline())
    inspector._pipeline_builder = None

    result = inspector.analyze()
    assert result["error"] == "Pipeline builder is not initialized"
    assert "memory_stats" in result


def test_init_requires_memory_monitor(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample-data")

    with pytest.raises(ValueError, match="memory_monitor must be provided"):
        R2Inspector(
            filename=str(sample),
            config=DummyConfig(parallel=False),
            verbose=False,
            adapter=DummyAdapter(),
            registry_factory=DummyRegistry,
            pipeline_builder_factory=lambda _adapter, _registry, _config, _filename: _HookPipelineBuilder(
                _HookPipeline()
            ),
            config_factory=lambda: DummyConfig(parallel=False),
            file_validator_factory=lambda _path: DummyFileValidator(_path),
            result_aggregator_factory=ResultAggregator,
            memory_monitor=None,  # type: ignore[arg-type]
        )


def test_init_requires_config_factory_when_config_is_none(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample-data")

    with pytest.raises(ValueError, match="config_factory must be provided"):
        R2Inspector(
            filename=str(sample),
            config=None,
            verbose=False,
            adapter=DummyAdapter(),
            registry_factory=DummyRegistry,
            pipeline_builder_factory=lambda _adapter, _registry, _config, _filename: _HookPipelineBuilder(
                _HookPipeline()
            ),
            file_validator_factory=lambda _path: DummyFileValidator(_path),
            result_aggregator_factory=ResultAggregator,
            memory_monitor=DummyMemoryMonitor(),
        )


def test_init_requires_adapter(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample-data")

    with pytest.raises(ValueError, match="adapter must be provided"):
        R2Inspector(
            filename=str(sample),
            config=DummyConfig(parallel=False),
            verbose=False,
            adapter=None,  # type: ignore[arg-type]
            registry_factory=DummyRegistry,
            pipeline_builder_factory=lambda _adapter, _registry, _config, _filename: _HookPipelineBuilder(
                _HookPipeline()
            ),
            file_validator_factory=lambda _path: DummyFileValidator(_path),
            result_aggregator_factory=ResultAggregator,
            memory_monitor=DummyMemoryMonitor(),
        )


def test_init_requires_factories(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample-data")

    with pytest.raises(ValueError, match="file_validator_factory and result_aggregator_factory"):
        R2Inspector(
            filename=str(sample),
            config=DummyConfig(parallel=False),
            verbose=False,
            adapter=DummyAdapter(),
            registry_factory=DummyRegistry,
            pipeline_builder_factory=lambda _adapter, _registry, _config, _filename: _HookPipelineBuilder(
                _HookPipeline()
            ),
            config_factory=lambda: DummyConfig(parallel=False),
            result_aggregator_factory=ResultAggregator,
            memory_monitor=DummyMemoryMonitor(),
        )


def test_analyze_handles_memory_error_and_triggers_gc(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample-data")

    monitor = DummyMemoryMonitor()
    inspector = _make_inspector(
        sample,
        pipeline=_MemoryErrorPipeline(),  # type: ignore[arg-type]
        memory_monitor=monitor,
    )

    result = inspector.analyze()
    assert result["error"] == "Memory limit exceeded"
    assert monitor.gc_called is True
    assert "memory_stats" in result


def test_analyze_handles_general_exception(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample-data")
    inspector = _make_inspector(
        sample, parallel=False, pipeline=_BoomPipeline(RuntimeError("crash"))
    )

    result = inspector.analyze()
    assert result["error"] == "crash"
    assert "memory_stats" in result


def test_close_runs_cleanup_and_unsets_adapter(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample-data")

    cleanup_calls: list[str] = []

    inspector = _make_inspector(
        sample,
        cleanup_callback=lambda: cleanup_calls.append("closed"),
    )
    inspector.close()

    assert cleanup_calls == ["closed"]
    assert inspector.adapter is None
