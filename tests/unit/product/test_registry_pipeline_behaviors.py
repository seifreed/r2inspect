from __future__ import annotations

from r2inspect.pipeline.analysis_pipeline import AnalysisPipeline
from r2inspect.pipeline.stage_models import AnalysisStage
from r2inspect.registry.analyzer_registry import AnalyzerRegistry
from r2inspect.registry.categories import AnalyzerCategory


class FakeStage(AnalysisStage):
    def __init__(self, name: str, result: dict[str, object], **kwargs):
        super().__init__(name, **kwargs)
        self._result = result

    def _execute(self, _context: dict[str, object]) -> dict[str, object]:
        return self._result


class FakeAnalyzer:
    pass


def test_analysis_pipeline_executes_added_stages_and_tracks_names() -> None:
    pipeline = AnalysisPipeline()
    pipeline.add_stage(FakeStage("file", {"file": {"ok": True}}))
    pipeline.add_stage(FakeStage("hash", {"hash": {"sha256": "abc"}}, dependencies=["file"]))

    result = pipeline.execute()

    assert pipeline.list_stages() == ["file", "hash"]
    assert result["file"]["ok"] is True
    assert result["hash"]["sha256"] == "abc"


def test_analysis_pipeline_can_remove_stages_by_name() -> None:
    pipeline = AnalysisPipeline()
    pipeline.add_stage(FakeStage("a", {"a": 1}))
    pipeline.add_stage(FakeStage("b", {"b": 2}))
    assert pipeline.remove_stage("a") is True
    assert pipeline.list_stages() == ["b"]


def test_registry_registers_metadata_and_resolves_dependencies_in_order() -> None:
    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register(
        name="base",
        analyzer_class=FakeAnalyzer,
        category=AnalyzerCategory.METADATA,
        file_formats={"PE"},
        required=True,
    )
    registry.register(
        name="hash",
        analyzer_class=FakeAnalyzer,
        category=AnalyzerCategory.HASHING,
        file_formats={"PE"},
        dependencies={"base"},
    )

    ordered = registry.resolve_execution_order(["hash", "base"])

    assert ordered == ["base", "hash"]
    assert set(registry.get_analyzers_for_format("PE")) == {"base", "hash"}
