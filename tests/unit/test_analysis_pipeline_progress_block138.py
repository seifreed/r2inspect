from __future__ import annotations

from r2inspect.pipeline.analysis_pipeline import AnalysisPipeline, AnalysisStage


class _CallableStage(AnalysisStage):
    def __init__(self, name, fn, **kwargs):
        super().__init__(name=name, **kwargs)
        self._fn = fn

    def _execute(self, _context):
        return {self.name: self._fn()}


def test_execute_with_progress_reports_all_stages():
    called = []

    def progress(name, idx, total):
        called.append((name, idx, total))

    pipeline = AnalysisPipeline()
    pipeline.add_stage(_CallableStage("a", lambda: {"a": 1}))
    pipeline.add_stage(_CallableStage("b", lambda: {"b": 2}))

    results = pipeline.execute_with_progress(progress)
    assert results["a"]["a"] == 1
    assert results["b"]["b"] == 2
    assert len(called) == 2
    assert called[0][2] == 2
