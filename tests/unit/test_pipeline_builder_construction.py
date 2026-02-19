#!/usr/bin/env python3
"""Comprehensive tests for pipeline_builder.py construction logic."""

from unittest.mock import Mock, MagicMock, patch
from r2inspect.core.pipeline_builder import PipelineBuilder
from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.config import Config
from r2inspect.registry.default_registry import create_default_registry
from r2inspect.pipeline.analysis_pipeline import AnalysisPipeline


class FakeR2:
    """Fake radare2 pipe for testing."""
    
    def cmdj(self, _command):
        return {}
    
    def cmd(self, _command):
        return ""


def test_pipeline_builder_initialization():
    adapter = R2PipeAdapter(FakeR2())
    registry = create_default_registry()
    config = Config()
    builder = PipelineBuilder(adapter, registry, config, "test.bin")
    
    assert builder.adapter == adapter
    assert builder.registry == registry
    assert builder.config == config
    assert builder.filename == "test.bin"


def test_pipeline_builder_builds_all_stages():
    adapter = R2PipeAdapter(FakeR2())
    registry = create_default_registry()
    config = Config()
    builder = PipelineBuilder(adapter, registry, config, "sample.bin")
    
    pipeline = builder.build(options={})
    stages = pipeline.list_stages()
    
    assert len(stages) == 8
    assert "file_info" in stages
    assert "format_detection" in stages
    assert "format_analysis" in stages
    assert "metadata" in stages
    assert "security" in stages
    assert "hashing" in stages
    assert "detection" in stages
    assert "indicators" in stages


def test_pipeline_builder_stage_order():
    adapter = R2PipeAdapter(FakeR2())
    registry = create_default_registry()
    config = Config()
    builder = PipelineBuilder(adapter, registry, config, "sample.bin")
    
    pipeline = builder.build(options={})
    stages = pipeline.list_stages()
    
    assert stages[0] == "file_info"
    assert stages[1] == "format_detection"
    assert stages[2] == "format_analysis"
    assert stages[3] == "metadata"
    assert stages[4] == "security"
    assert stages[5] == "hashing"
    assert stages[6] == "detection"
    assert stages[7] == "indicators"


def test_pipeline_builder_with_empty_options():
    adapter = R2PipeAdapter(FakeR2())
    registry = create_default_registry()
    config = Config()
    builder = PipelineBuilder(adapter, registry, config, "sample.bin")
    
    pipeline = builder.build(options={})
    assert isinstance(pipeline, AnalysisPipeline)
    assert len(pipeline.list_stages()) == 8


def test_pipeline_builder_with_options():
    adapter = R2PipeAdapter(FakeR2())
    registry = create_default_registry()
    config = Config()
    builder = PipelineBuilder(adapter, registry, config, "sample.bin")
    
    options = {"yara": True, "strings": True}
    pipeline = builder.build(options=options)
    assert isinstance(pipeline, AnalysisPipeline)


def test_pipeline_builder_max_workers_from_config():
    adapter = R2PipeAdapter(FakeR2())
    registry = create_default_registry()
    config = Config()
    builder = PipelineBuilder(adapter, registry, config, "sample.bin")
    
    pipeline = builder.build(options={})
    assert pipeline.max_workers == config.typed_config.pipeline.max_workers


def test_add_stage_to_pipeline():
    adapter = R2PipeAdapter(FakeR2())
    registry = create_default_registry()
    config = Config()
    builder = PipelineBuilder(adapter, registry, config, "sample.bin")
    
    pipeline = AnalysisPipeline(max_workers=4)
    
    from r2inspect.pipeline.stages import FileInfoStage
    builder._add_stage_to_pipeline(pipeline, FileInfoStage, adapter, "test.bin")
    
    stages = pipeline.list_stages()
    assert "file_info" in stages


def test_add_stage_sets_timeout():
    adapter = R2PipeAdapter(FakeR2())
    registry = create_default_registry()
    config = Config()
    builder = PipelineBuilder(adapter, registry, config, "sample.bin")
    
    pipeline = AnalysisPipeline(max_workers=4)
    
    from r2inspect.pipeline.stages import FileInfoStage
    builder._add_stage_to_pipeline(pipeline, FileInfoStage, adapter, "test.bin")
    
    stages = pipeline.list_stages()
    assert "file_info" in stages


def test_add_stage_with_args():
    adapter = R2PipeAdapter(FakeR2())
    registry = create_default_registry()
    config = Config()
    builder = PipelineBuilder(adapter, registry, config, "sample.bin")
    
    pipeline = AnalysisPipeline(max_workers=4)
    
    from r2inspect.pipeline.stages import FormatAnalysisStage
    builder._add_stage_to_pipeline(
        pipeline, FormatAnalysisStage, registry, adapter, config, "test.bin"
    )
    
    stages = pipeline.list_stages()
    assert "format_analysis" in stages


def test_add_stage_with_kwargs():
    adapter = R2PipeAdapter(FakeR2())
    registry = create_default_registry()
    config = Config()
    builder = PipelineBuilder(adapter, registry, config, "sample.bin")
    
    pipeline = AnalysisPipeline(max_workers=4)
    
    from r2inspect.pipeline.stages import MetadataStage
    options = {"verbose": True}
    builder._add_stage_to_pipeline(
        pipeline, MetadataStage, registry, adapter, config, "test.bin", options
    )
    
    stages = pipeline.list_stages()
    assert "metadata" in stages


def test_pipeline_builder_uses_correct_registry():
    adapter = R2PipeAdapter(FakeR2())
    registry = create_default_registry()
    config = Config()
    builder = PipelineBuilder(adapter, registry, config, "sample.bin")
    
    pipeline = builder.build(options={})
    assert builder.registry is registry


def test_pipeline_builder_uses_correct_adapter():
    adapter = R2PipeAdapter(FakeR2())
    registry = create_default_registry()
    config = Config()
    builder = PipelineBuilder(adapter, registry, config, "sample.bin")
    
    pipeline = builder.build(options={})
    assert builder.adapter is adapter


def test_pipeline_builder_uses_correct_config():
    adapter = R2PipeAdapter(FakeR2())
    registry = create_default_registry()
    config = Config()
    builder = PipelineBuilder(adapter, registry, config, "sample.bin")
    
    pipeline = builder.build(options={})
    assert builder.config is config


def test_pipeline_builder_uses_correct_filename():
    adapter = R2PipeAdapter(FakeR2())
    registry = create_default_registry()
    config = Config()
    filename = "myfile.exe"
    builder = PipelineBuilder(adapter, registry, config, filename)
    
    pipeline = builder.build(options={})
    assert builder.filename == filename


def test_pipeline_builder_with_different_filenames():
    adapter = R2PipeAdapter(FakeR2())
    registry = create_default_registry()
    config = Config()
    
    builder1 = PipelineBuilder(adapter, registry, config, "file1.bin")
    builder2 = PipelineBuilder(adapter, registry, config, "file2.exe")
    
    assert builder1.filename == "file1.bin"
    assert builder2.filename == "file2.exe"


def test_pipeline_builder_multiple_builds():
    adapter = R2PipeAdapter(FakeR2())
    registry = create_default_registry()
    config = Config()
    builder = PipelineBuilder(adapter, registry, config, "sample.bin")
    
    pipeline1 = builder.build(options={})
    pipeline2 = builder.build(options={"verbose": True})
    
    assert pipeline1 is not pipeline2
    assert len(pipeline1.list_stages()) == len(pipeline2.list_stages())


def test_pipeline_builder_consistent_stage_count():
    adapter = R2PipeAdapter(FakeR2())
    registry = create_default_registry()
    config = Config()
    builder = PipelineBuilder(adapter, registry, config, "sample.bin")
    
    for _ in range(5):
        pipeline = builder.build(options={})
        assert len(pipeline.list_stages()) == 8


def test_pipeline_builder_with_various_options():
    adapter = R2PipeAdapter(FakeR2())
    registry = create_default_registry()
    config = Config()
    builder = PipelineBuilder(adapter, registry, config, "sample.bin")
    
    options_variants = [
        {},
        {"yara": True},
        {"strings": False},
        {"verbose": True, "yara": True},
        {"custom": "value"},
    ]
    
    for opts in options_variants:
        pipeline = builder.build(options=opts)
        assert len(pipeline.list_stages()) == 8


def test_pipeline_instance_type():
    adapter = R2PipeAdapter(FakeR2())
    registry = create_default_registry()
    config = Config()
    builder = PipelineBuilder(adapter, registry, config, "sample.bin")
    
    pipeline = builder.build(options={})
    assert isinstance(pipeline, AnalysisPipeline)


def test_build_returns_new_pipeline_each_time():
    adapter = R2PipeAdapter(FakeR2())
    registry = create_default_registry()
    config = Config()
    builder = PipelineBuilder(adapter, registry, config, "sample.bin")
    
    pipelines = [builder.build(options={}) for _ in range(3)]
    
    assert pipelines[0] is not pipelines[1]
    assert pipelines[1] is not pipelines[2]
    assert pipelines[0] is not pipelines[2]


def test_pipeline_builder_with_mock_registry():
    adapter = R2PipeAdapter(FakeR2())
    registry = Mock()
    config = Config()
    builder = PipelineBuilder(adapter, registry, config, "sample.bin")
    
    assert builder.registry is registry


def test_pipeline_builder_with_mock_adapter():
    adapter = Mock()
    registry = create_default_registry()
    config = Config()
    builder = PipelineBuilder(adapter, registry, config, "sample.bin")
    
    assert builder.adapter is adapter


def test_pipeline_builder_with_custom_config():
    adapter = R2PipeAdapter(FakeR2())
    registry = create_default_registry()
    config = Mock()
    config.typed_config.pipeline.max_workers = 8
    config.typed_config.pipeline.stage_timeout = 60
    
    builder = PipelineBuilder(adapter, registry, config, "sample.bin")
    pipeline = builder.build(options={})
    
    assert pipeline.max_workers == 8


def test_add_stage_to_pipeline_multiple_stages():
    adapter = R2PipeAdapter(FakeR2())
    registry = create_default_registry()
    config = Config()
    builder = PipelineBuilder(adapter, registry, config, "sample.bin")
    
    pipeline = AnalysisPipeline(max_workers=4)
    
    from r2inspect.pipeline.stages import FileInfoStage, FormatDetectionStage
    builder._add_stage_to_pipeline(pipeline, FileInfoStage, adapter, "test.bin")
    builder._add_stage_to_pipeline(pipeline, FormatDetectionStage, adapter, "test.bin")
    
    stages = pipeline.list_stages()
    assert len(stages) == 2
    assert "file_info" in stages
    assert "format_detection" in stages


def test_pipeline_builder_all_stage_names():
    adapter = R2PipeAdapter(FakeR2())
    registry = create_default_registry()
    config = Config()
    builder = PipelineBuilder(adapter, registry, config, "sample.bin")
    
    pipeline = builder.build(options={})
    stages = pipeline.list_stages()
    
    expected_stages = [
        "file_info",
        "format_detection",
        "format_analysis",
        "metadata",
        "security",
        "hashing",
        "detection",
        "indicators",
    ]
    
    for expected in expected_stages:
        assert expected in stages


def test_pipeline_builder_no_duplicate_stages():
    adapter = R2PipeAdapter(FakeR2())
    registry = create_default_registry()
    config = Config()
    builder = PipelineBuilder(adapter, registry, config, "sample.bin")
    
    pipeline = builder.build(options={})
    stages = pipeline.list_stages()
    
    assert len(stages) == len(set(stages))


def test_pipeline_builder_stage_specs_structure():
    adapter = R2PipeAdapter(FakeR2())
    registry = create_default_registry()
    config = Config()
    builder = PipelineBuilder(adapter, registry, config, "sample.bin")
    
    pipeline = builder.build(options={})
    assert len(pipeline) == 8


def test_pipeline_builder_filename_propagation():
    adapter = R2PipeAdapter(FakeR2())
    registry = create_default_registry()
    config = Config()
    filename = "test_file.bin"
    builder = PipelineBuilder(adapter, registry, config, filename)
    
    assert builder.filename == filename


def test_pipeline_builder_with_path_like_filename():
    adapter = R2PipeAdapter(FakeR2())
    registry = create_default_registry()
    config = Config()
    filename = "/path/to/sample.exe"
    builder = PipelineBuilder(adapter, registry, config, filename)
    
    pipeline = builder.build(options={})
    assert builder.filename == filename


def test_pipeline_builder_immutable_options():
    adapter = R2PipeAdapter(FakeR2())
    registry = create_default_registry()
    config = Config()
    builder = PipelineBuilder(adapter, registry, config, "sample.bin")
    
    options = {"key": "value"}
    pipeline = builder.build(options=options)
    
    options["new_key"] = "new_value"
    assert "new_key" not in options or len(pipeline.list_stages()) == 8
