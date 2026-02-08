import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from r2inspect.pipeline.analysis_pipeline import AnalysisPipeline, AnalysisStage, ThreadSafeContext
from r2inspect.pipeline.stages_common import AnalyzerStage, IndicatorStage


class _SimpleStage(AnalysisStage):
    def __init__(self, name: str, *, payload: dict | None = None, **kwargs) -> None:
        super().__init__(name=name, **kwargs)
        self._payload = payload or {name: {"success": True}}

    def _execute(self, _context: dict) -> dict:
        return self._payload


def test_analyzer_stage_successful_run():
    class Analyzer:
        def __init__(self, adapter=None, config=None, filename=None) -> None:
            self.adapter = adapter
            self.config = config
            self.filename = filename

        def analyze(self):
            return {"adapter": self.adapter, "filename": self.filename}

    stage = AnalyzerStage(
        name="analyzer",
        analyzer_class=Analyzer,
        adapter="backend",
        config={"mode": "real"},
        filename="sample.bin",
    )
    context = {"results": {}}
    result = stage.execute(context)

    assert result["results"]["analyzer"]["adapter"] == "backend"
    assert result["results"]["analyzer"]["filename"] == "sample.bin"
    assert context["results"]["analyzer"]["adapter"] == "backend"


def test_analyzer_stage_error_is_recorded():
    class Analyzer:
        def analyze(self):
            raise ValueError("boom")

    stage = AnalyzerStage(
        name="analyzer",
        analyzer_class=Analyzer,
        adapter=None,
        config=None,
        filename="sample.bin",
    )
    context = {"results": {}}
    result = stage.execute(context)

    assert "error" in result["results"]["analyzer"]
    assert "boom" in result["results"]["analyzer"]["error"]


def test_indicator_stage_builds_indicators():
    stage = IndicatorStage()
    context = {
        "results": {
            "packer": {"is_packed": True, "packer_type": "UPX"},
            "anti_analysis": {"anti_debug": True, "anti_vm": True},
            "imports": [{"name": "VirtualAlloc"}],
            "yara_matches": [{"rule": "Rule"}],
            "sections": [{"entropy": 7.2}],
            "crypto": {"matches": ["AES"]},
            "file_info": {"name": "sample.bin"},
            "pe_info": {},
            "security": {},
            "functions": {},
            "rich_header": {},
        }
    }
    result = stage.execute(context)

    assert "indicators" in result
    assert result["indicators"]


def test_stage_condition_exception_returns_false():
    stage = _SimpleStage(
        "cond",
        condition=lambda _ctx: (_ for _ in ()).throw(RuntimeError("bad condition")),
    )
    assert stage.should_execute({}) is False


def test_stage_execute_exception_records_error():
    class BadStage(AnalysisStage):
        def _execute(self, _context: dict) -> dict:
            raise RuntimeError("stage failed")

    stage = BadStage(name="bad")
    context = {"results": {}}
    result = stage.execute(context)

    assert result["bad"]["success"] is False
    assert "stage failed" in result["bad"]["error"]
    assert context["results"]["bad"]["success"] is False


def test_pipeline_no_ready_stages_raises():
    pipeline = AnalysisPipeline(max_workers=1)
    pipeline.add_stage(_SimpleStage("needs_dep", dependencies=["missing"]))

    with pytest.raises(RuntimeError):
        pipeline.execute(parallel=True)


def test_pipeline_unsatisfied_dependencies_logged():
    pipeline = AnalysisPipeline(max_workers=1)
    pipeline.add_stage(_SimpleStage("ok"))
    pipeline.add_stage(_SimpleStage("blocked", dependencies=["missing"]))

    results = pipeline.execute(parallel=True)
    assert "ok" in results


def test_pipeline_collect_futures_exception_path():
    pipeline = AnalysisPipeline(max_workers=1)
    stage = _SimpleStage("boom")
    ts_context = ThreadSafeContext({"results": {}})
    completed = set()
    remaining = [stage]

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(lambda: (_ for _ in ()).throw(ValueError("fail")))
        stats = pipeline._collect_futures(
            {future: stage}, ts_context, remaining, completed, threading.Lock()
        )

    assert stats["failed"] == 1
    assert ts_context.get("results")["boom"]["success"] is False


def test_execute_stage_with_timeout_success_and_timeout():
    class SlowStage(AnalysisStage):
        def _execute(self, _context: dict) -> dict:
            time.sleep(0.01)
            return {self.name: {"success": True}}

    pipeline = AnalysisPipeline(max_workers=1)

    ok_stage = SlowStage(name="ok", timeout=0.2)
    result, success = pipeline._execute_stage_with_timeout(ok_stage, ThreadSafeContext())
    assert success is True
    assert result["ok"]["success"] is True

    timeout_stage = SlowStage(name="timeout", timeout=0.001)
    result, success = pipeline._execute_stage_with_timeout(timeout_stage, ThreadSafeContext())
    assert success is False
    assert result["timeout"]["success"] is False


def test_execute_stage_with_timeout_exception_path():
    class ExplodingStage(AnalysisStage):
        def execute(self, _context: dict) -> dict:
            raise RuntimeError("explode")

        def _execute(self, _context: dict) -> dict:
            return {}

    pipeline = AnalysisPipeline(max_workers=1)
    stage = ExplodingStage(name="explode", timeout=0.2)
    result, success = pipeline._execute_stage_with_timeout(stage, ThreadSafeContext())
    assert success is False
    assert "explode" in result["explode"]["error"]


def test_execute_stage_without_timeout_exception():
    class ExplodingStage(AnalysisStage):
        def execute(self, _context: dict) -> dict:
            raise RuntimeError("explode")

        def _execute(self, _context: dict) -> dict:
            return {}

    pipeline = AnalysisPipeline(max_workers=1)
    stage = ExplodingStage(name="explode")
    result, success = pipeline._execute_stage_with_timeout(stage, ThreadSafeContext())
    assert success is False
    assert "explode" in result["explode"]["error"]


def test_sequential_progress_callback_failure_does_not_abort():
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_SimpleStage("ok"))

    def progress(_name: str, _idx: int, _total: int) -> None:
        raise RuntimeError("progress failed")

    pipeline.set_progress_callback(progress)
    results = pipeline.execute()
    assert "ok" in results


def test_sequential_failed_stage_counts_and_clear():
    pipeline = AnalysisPipeline()
    pipeline.add_stage(_SimpleStage("ok"))
    pipeline.add_stage(_SimpleStage("bad", payload={"bad": {"success": False}}))

    results = pipeline.execute()
    assert results["bad"]["success"] is False

    pipeline.clear()
    assert len(pipeline) == 0


def test_pipeline_remove_get_stage_and_context_set():
    pipeline = AnalysisPipeline()
    stage = _SimpleStage("alpha")
    pipeline.add_stage(stage)

    assert pipeline.get_stage("alpha") is stage
    assert pipeline.get_stage("missing") is None
    assert pipeline.remove_stage("alpha") is True
    assert pipeline.remove_stage("missing") is False

    ctx = ThreadSafeContext()
    ctx.set("key", "value")
    assert ctx.get("key") == "value"


def test_merge_stage_results_empty_is_noop():
    ctx = ThreadSafeContext({"results": {"existing": 1}})
    AnalysisPipeline._merge_stage_results(ctx, {})
    assert ctx.get("results") == {"existing": 1}
