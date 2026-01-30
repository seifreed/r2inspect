import time

from r2inspect.pipeline.analysis_pipeline import AnalysisPipeline, AnalysisStage


class _ContextStage(AnalysisStage):
    def __init__(self, name: str, *, dependencies=None, condition=None, timeout=None):
        super().__init__(
            name=name,
            description=f"stage {name}",
            optional=False,
            dependencies=dependencies or [],
            condition=condition,
            timeout=timeout,
        )

    def _execute(self, context):
        context.setdefault("results", {})
        if self.dependencies:
            for dep in self.dependencies:
                assert dep in context["results"]
        return {self.name: {"ok": True}}


class _SleepStage(AnalysisStage):
    def __init__(self, name: str, sleep_s: float, timeout: float | None):
        super().__init__(name=name, timeout=timeout)
        self.sleep_s = sleep_s

    def _execute(self, context):
        time.sleep(self.sleep_s)
        return {self.name: {"ok": True}}


class _FailStage(AnalysisStage):
    def __init__(self, name: str):
        super().__init__(name=name)

    def _execute(self, context):
        raise RuntimeError("boom")


def test_parallel_dependencies_and_skips():
    pipeline = AnalysisPipeline(max_workers=2)
    pipeline.add_stage(_ContextStage("a"))
    pipeline.add_stage(_ContextStage("b", dependencies=["a"]))
    pipeline.add_stage(_ContextStage("c", condition=lambda ctx: False))

    results = pipeline.execute(parallel=True)
    assert "a" in results
    assert "b" in results
    assert "c" not in results


def test_parallel_timeout_marks_failure():
    pipeline = AnalysisPipeline(max_workers=2)
    pipeline.add_stage(_SleepStage("slow", sleep_s=0.05, timeout=0.01))

    results = pipeline.execute(parallel=True)
    assert results["slow"]["success"] is False
    assert "Timeout" in results["slow"]["error"]


def test_parallel_failure_isolated():
    pipeline = AnalysisPipeline(max_workers=2)
    pipeline.add_stage(_FailStage("bad"))
    pipeline.add_stage(_ContextStage("good"))

    results = pipeline.execute(parallel=True)
    assert results["bad"]["success"] is False
    assert results["good"]["ok"] is True
