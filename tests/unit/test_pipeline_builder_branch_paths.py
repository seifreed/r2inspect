from __future__ import annotations

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.config import Config
from r2inspect.core.pipeline_builder import PipelineBuilder
from r2inspect.pipeline.analysis_pipeline import AnalysisPipeline
from r2inspect.pipeline.stages import FileInfoStage, FormatDetectionStage
from r2inspect.registry.default_registry import create_default_registry


class _FakeR2:
    def cmdj(self, _command: str) -> dict:
        return {}

    def cmd(self, _command: str) -> str:
        return ""


def _make_builder(filename: str = "test.bin") -> PipelineBuilder:
    adapter = R2PipeAdapter(_FakeR2())
    registry = create_default_registry()
    config = Config()
    return PipelineBuilder(adapter, registry, config, filename)


def test_pipeline_builder_build_returns_analysis_pipeline() -> None:
    builder = _make_builder()
    pipeline = builder.build({})
    assert isinstance(pipeline, AnalysisPipeline)


def test_pipeline_builder_build_has_eight_stages() -> None:
    builder = _make_builder()
    pipeline = builder.build({})
    assert len(pipeline.list_stages()) == 8


def test_pipeline_builder_build_contains_all_expected_stages() -> None:
    builder = _make_builder()
    pipeline = builder.build({})
    stages = pipeline.list_stages()
    expected = [
        "file_info", "format_detection", "format_analysis",
        "metadata", "security", "hashing", "detection", "indicators",
    ]
    for name in expected:
        assert name in stages


def test_pipeline_builder_add_stage_to_pipeline() -> None:
    builder = _make_builder()
    pipeline = AnalysisPipeline(max_workers=1)
    adapter = R2PipeAdapter(_FakeR2())
    builder._add_stage_to_pipeline(pipeline, FileInfoStage, adapter, "test.bin")
    assert "file_info" in pipeline.list_stages()


def test_pipeline_builder_add_stage_sets_timeout() -> None:
    builder = _make_builder()
    pipeline = AnalysisPipeline(max_workers=1)
    adapter = R2PipeAdapter(_FakeR2())
    builder._add_stage_to_pipeline(pipeline, FileInfoStage, adapter, "test.bin")
    stage = pipeline.get_stage("file_info")
    assert stage is not None
    assert stage.timeout == builder.config.typed_config.pipeline.stage_timeout


def test_pipeline_builder_max_workers_from_config() -> None:
    builder = _make_builder()
    pipeline = builder.build({})
    assert pipeline.max_workers == builder.config.typed_config.pipeline.max_workers


def test_pipeline_builder_build_multiple_times_creates_distinct_pipelines() -> None:
    builder = _make_builder()
    p1 = builder.build({})
    p2 = builder.build({})
    assert p1 is not p2


def test_pipeline_builder_debug_message_logged(capsys) -> None:
    builder = _make_builder("debug_test.bin")
    pipeline = builder.build({})
    assert len(pipeline.list_stages()) == 8


def test_add_two_stages_to_pipeline() -> None:
    builder = _make_builder()
    pipeline = AnalysisPipeline(max_workers=1)
    adapter = R2PipeAdapter(_FakeR2())
    builder._add_stage_to_pipeline(pipeline, FileInfoStage, adapter, "test.bin")
    builder._add_stage_to_pipeline(pipeline, FormatDetectionStage, adapter, "test.bin")
    stages = pipeline.list_stages()
    assert len(stages) == 2
    assert "file_info" in stages
    assert "format_detection" in stages
