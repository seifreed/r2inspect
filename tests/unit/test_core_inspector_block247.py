from pathlib import Path

from r2inspect.core.file_validator import FileValidator
from r2inspect.core.inspector import R2Inspector
from r2inspect.core.result_aggregator import ResultAggregator
from r2inspect.pipeline.analysis_pipeline import AnalysisPipeline, AnalysisStage
from r2inspect.utils.memory_manager import global_memory_monitor

FIXTURE = Path("samples/fixtures/hello_pe.exe")


class DummyConfig:
    def __init__(self):
        self.typed_config = type("Cfg", (), {})()
        self.typed_config.pipeline = type("Pipe", (), {})()
        self.typed_config.pipeline.parallel_execution = False
        self.typed_config.pipeline.max_workers = 1
        self.typed_config.pipeline.stage_timeout = None


class DummyAdapter:
    thread_safe = True


class DummyRegistry:
    def __len__(self):
        return 0

    def list_analyzers(self):
        return []


class DummyPipelineBuilder:
    def __init__(self, _adapter, _registry, _config, _filename):
        pass

    def build(self, _options):
        pipeline = AnalysisPipeline()

        class Stage(AnalysisStage):
            def __init__(self):
                super().__init__(name="stage")

            def _execute(self, _context):
                return {"stage": {"ok": True}}

        pipeline.add_stage(Stage())
        return pipeline


def test_inspector_analyze_and_cleanup():
    inspector = R2Inspector(
        filename=str(FIXTURE),
        config=DummyConfig(),
        verbose=False,
        cleanup_callback=lambda: None,
        adapter=DummyAdapter(),
        registry_factory=DummyRegistry,
        pipeline_builder_factory=lambda a, r, c, f: DummyPipelineBuilder(a, r, c, f),
        config_factory=DummyConfig,
        file_validator_factory=FileValidator,
        result_aggregator_factory=ResultAggregator,
        memory_monitor=global_memory_monitor,
    )

    results = inspector.analyze()
    assert results["stage"]["ok"] is True
    assert "memory_stats" in results

    inspector.close()
