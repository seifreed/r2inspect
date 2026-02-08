from __future__ import annotations

import json
from pathlib import Path

import pytest

from r2inspect.config import Config
from r2inspect.core.file_validator import FileValidator
from r2inspect.core.inspector import R2Inspector
from r2inspect.core.pipeline_builder import PipelineBuilder
from r2inspect.core.result_aggregator import ResultAggregator
from r2inspect.factory import create_inspector
from r2inspect.registry.default_registry import create_default_registry
from r2inspect.utils.memory_manager import MemoryMonitor


def _sample_path() -> Path:
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("sample binary missing")
    return sample


@pytest.mark.unit
def test_r2_inspector_init_validation_errors(tmp_path: Path) -> None:
    sample = tmp_path / "tiny.bin"
    sample.write_bytes(b"A" * 4)

    with pytest.raises(ValueError):
        R2Inspector(
            filename=str(sample),
            config=Config(),
            adapter=object(),
            registry_factory=create_default_registry,
            pipeline_builder_factory=lambda adapter, registry, cfg, path: PipelineBuilder(
                adapter, registry, cfg, path
            ),
            config_factory=Config,
            file_validator_factory=FileValidator,
            result_aggregator_factory=ResultAggregator,
            memory_monitor=None,
        )

    with pytest.raises(ValueError):
        R2Inspector(
            filename=str(sample),
            config=None,
            adapter=object(),
            registry_factory=create_default_registry,
            pipeline_builder_factory=lambda adapter, registry, cfg, path: PipelineBuilder(
                adapter, registry, cfg, path
            ),
            config_factory=None,
            file_validator_factory=FileValidator,
            result_aggregator_factory=ResultAggregator,
            memory_monitor=MemoryMonitor(),
        )

    # config_factory path exercised (config None)
    sample_valid = tmp_path / "valid_factory.bin"
    sample_valid.write_bytes(b"A" * 64)
    inspector = R2Inspector(
        filename=str(sample_valid),
        config=None,
        adapter=object(),
        registry_factory=create_default_registry,
        pipeline_builder_factory=lambda adapter, registry, cfg, path: PipelineBuilder(
            adapter, registry, cfg, path
        ),
        config_factory=Config,
        file_validator_factory=FileValidator,
        result_aggregator_factory=ResultAggregator,
        memory_monitor=MemoryMonitor(),
    )
    inspector.close()

    with pytest.raises(ValueError):
        R2Inspector(
            filename=str(sample),
            config=Config(),
            adapter=None,
            registry_factory=create_default_registry,
            pipeline_builder_factory=lambda adapter, registry, cfg, path: PipelineBuilder(
                adapter, registry, cfg, path
            ),
            config_factory=Config,
            file_validator_factory=FileValidator,
            result_aggregator_factory=ResultAggregator,
            memory_monitor=MemoryMonitor(),
        )

    with pytest.raises(ValueError):
        R2Inspector(
            filename=str(sample),
            config=Config(),
            adapter=object(),
            registry_factory=create_default_registry,
            pipeline_builder_factory=lambda adapter, registry, cfg, path: PipelineBuilder(
                adapter, registry, cfg, path
            ),
            config_factory=Config,
            file_validator_factory=None,
            result_aggregator_factory=ResultAggregator,
            memory_monitor=MemoryMonitor(),
        )

    # File validation fails (too small)
    with pytest.raises(ValueError):
        R2Inspector(
            filename=str(sample),
            config=Config(),
            adapter=object(),
            registry_factory=create_default_registry,
            pipeline_builder_factory=lambda adapter, registry, cfg, path: PipelineBuilder(
                adapter, registry, cfg, path
            ),
            config_factory=Config,
            file_validator_factory=FileValidator,
            result_aggregator_factory=ResultAggregator,
            memory_monitor=MemoryMonitor(),
        )


@pytest.mark.unit
def test_r2_inspector_missing_factories(tmp_path: Path) -> None:
    sample = tmp_path / "valid.bin"
    sample.write_bytes(b"A" * 64)
    with pytest.raises(ValueError):
        R2Inspector(
            filename=str(sample),
            config=Config(),
            adapter=object(),
            registry_factory=None,
            pipeline_builder_factory=None,
            config_factory=Config,
            file_validator_factory=FileValidator,
            result_aggregator_factory=ResultAggregator,
            memory_monitor=MemoryMonitor(),
        )


@pytest.mark.unit
def test_r2_inspector_analyze_paths(tmp_path: Path) -> None:
    sample = _sample_path()

    config_path = tmp_path / "config.json"
    config_data = Config.DEFAULT_CONFIG.copy()
    config_data["pipeline"] = {**config_data.get("pipeline", {}), "parallel_execution": False}
    config_path.write_text(json.dumps(config_data))
    config = Config(str(config_path))

    with create_inspector(str(sample), config=config) as inspector:
        inspector.adapter.thread_safe = False

        result = inspector.analyze()
        assert "memory_stats" in result

        progress: list[str] = []

        def _progress(stage: str, *_args: object) -> None:
            progress.append(stage)

        inspector.analyze(progress_callback=_progress, batch_mode=False)
        assert progress

        inspector._pipeline_builder = None
        error_result = inspector.analyze()
        assert "error" in error_result

        inspector.close()
        inspector.__del__()

    with create_inspector(str(sample), verbose=True) as inspector:
        inspector._registry_factory = None
        inspector._pipeline_builder_factory = None
        with pytest.raises(ValueError):
            inspector._init_infrastructure()


@pytest.mark.unit
def test_r2_inspector_memory_error_path(tmp_path: Path) -> None:
    sample = tmp_path / "valid.bin"
    sample.write_bytes(b"A" * 64)

    class _ExplodingBuilder:
        def build(self, _options: dict[str, object]) -> object:
            raise MemoryError("boom")

    inspector = R2Inspector(
        filename=str(sample),
        config=Config(),
        adapter=object(),
        registry_factory=create_default_registry,
        pipeline_builder_factory=lambda adapter, registry, cfg, path: _ExplodingBuilder(),
        config_factory=Config,
        file_validator_factory=FileValidator,
        result_aggregator_factory=ResultAggregator,
        memory_monitor=MemoryMonitor(),
    )

    result = inspector.analyze()
    assert result.get("error") == "Memory limit exceeded"
