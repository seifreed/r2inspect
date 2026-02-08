from __future__ import annotations

from r2inspect.pipeline.analysis_pipeline import AnalysisPipeline, AnalysisStage


class _CallableStage(AnalysisStage):
    def __init__(self, name, fn, **kwargs):
        super().__init__(name=name, **kwargs)
        self._fn = fn

    def _execute(self, _context):
        return {self.name: self._fn()}


def test_pipeline_progress_callback_error_does_not_break_execution():
    def ok():
        return {"ok": True}

    pipeline = AnalysisPipeline()
    pipeline.add_stage(_CallableStage("stage1", ok))

    def bad_callback(_name, _idx, _total):
        raise RuntimeError("progress error")

    pipeline.set_progress_callback(bad_callback)
    results = pipeline.execute(parallel=False)
    assert results["stage1"]["ok"] is True
