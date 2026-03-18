"""Comprehensive tests for inspector.py - 100% coverage target.

No unittest.mock usage; all tests use real stub objects.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from r2inspect.core.inspector import R2Inspector


class _DummyMemoryMonitor:
    def check_memory(self, force: bool = False) -> dict[str, float | int]:
        return {"process_memory_mb": 100.0, "peak_memory_mb": 120.0, "gc_count": 2}

    def is_memory_available(self, required_mb: float) -> bool:
        return True

    def _trigger_gc(self, aggressive: bool = False) -> None:
        pass


class _DummyValidator:
    def __init__(self, valid: bool = True) -> None:
        self._valid = valid

    def validate(self) -> bool:
        return self._valid

    def _file_size_mb(self) -> float:
        return 1.0


class _DummyAdapter:
    def __init__(self) -> None:
        self.thread_safe = True


class _DummyPipeline:
    def execute(self, _options: dict[str, Any], parallel: bool = False) -> dict[str, Any]:
        return {"marker": "test"}

    def execute_with_progress(self, _callback: Any, _options: dict[str, Any]) -> dict[str, Any]:
        return {"marker": "test"}

    def build(self, _options: dict[str, Any]) -> _DummyPipeline:
        return self


class _DummyPipelineBuilder:
    def __call__(self, *_args: Any, **_kwargs: Any) -> _DummyPipeline:
        return _DummyPipeline()

    def build(self, _options: dict[str, Any]) -> _DummyPipeline:
        return _DummyPipeline()


class _DummyRegistry:
    def __len__(self) -> int:
        return 1

    def list_analyzers(self) -> list[dict[str, Any]]:
        return [{"name": "pe_analyzer", "category": "format", "file_formats": ["PE"]}]


class _DummyConfig:
    def __init__(self) -> None:
        self.typed_config = SimpleNamespace(pipeline=SimpleNamespace(parallel_execution=False))


class _DummyAggregator:
    def generate_indicators(self, analysis_results: dict[str, Any]) -> list[dict[str, Any]]:
        return []

    def generate_executive_summary(self, analysis_results: dict[str, Any]) -> dict[str, Any]:
        return {}


def _build_inspector(**overrides: Any) -> R2Inspector:
    defaults: dict[str, Any] = {
        "filename": "sample.bin",
        "config": _DummyConfig(),
        "verbose": False,
        "cleanup_callback": None,
        "adapter": _DummyAdapter(),
        "registry_factory": _DummyRegistry,
        "pipeline_builder_factory": _DummyPipelineBuilder(),
        "config_factory": None,
        "file_validator_factory": lambda _: _DummyValidator(),
        "result_aggregator_factory": _DummyAggregator,
        "memory_monitor": _DummyMemoryMonitor(),
    }
    defaults.update(overrides)
    return R2Inspector(**defaults)


def test_inspector_init():
    """Test R2Inspector initialization with all required dependencies."""
    inspector = _build_inspector()
    assert inspector is not None


def test_inspector_basic_functionality():
    """Test basic functionality of inspector."""
    inspector = _build_inspector()
    assert hasattr(inspector, "analyze")


def test_inspector_with_config():
    """Test inspector with explicit Config object."""
    config = _DummyConfig()
    inspector = _build_inspector(config=config)
    assert inspector.config is config


def test_inspector_requires_memory_monitor():
    """Test that inspector raises ValueError without memory_monitor."""
    with pytest.raises(ValueError, match="memory_monitor"):
        R2Inspector(filename="sample.bin", memory_monitor=None)  # type: ignore[arg-type]


def test_inspector_multiple_instances():
    """Test creating multiple inspector instances."""
    i1 = _build_inspector()
    i2 = _build_inspector()
    assert i1 is not i2
