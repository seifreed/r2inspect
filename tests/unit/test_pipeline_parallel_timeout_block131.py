from __future__ import annotations

import time

from r2inspect.pipeline.analysis_pipeline import AnalysisPipeline, AnalysisStage


class _CallableStage(AnalysisStage):
    def __init__(self, name, fn, **kwargs):
        super().__init__(name=name, **kwargs)
        self._fn = fn

    def _execute(self, _context):
        return {self.name: self._fn()}


def test_pipeline_parallel_timeout():
    def slow():
        time.sleep(0.05)
        return {"value": 1}

    pipeline = AnalysisPipeline(max_workers=2)
    pipeline.add_stage(_CallableStage("slow", slow, timeout=0.01))

    results = pipeline.execute(parallel=True)
    assert "slow" in results
    assert results["slow"].get("success") is False
    assert "Timeout" in results["slow"].get("error", "")
