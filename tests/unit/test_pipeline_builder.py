from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.config import Config
from r2inspect.core.pipeline_builder import PipelineBuilder
from r2inspect.registry.default_registry import create_default_registry
from r2inspect.testing.fake_r2 import FakeR2


def test_pipeline_builder_builds_expected_stages():
    adapter = R2PipeAdapter(FakeR2())
    registry = create_default_registry()
    config = Config()
    builder = PipelineBuilder(adapter, registry, config, "sample.bin")

    pipeline = builder.build(options={})
    stages = pipeline.list_stages()

    assert stages == [
        "file_info",
        "format_detection",
        "format_analysis",
        "metadata",
        "security",
        "hashing",
        "detection",
        "indicators",
    ]
