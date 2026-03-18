from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from r2inspect.lazy_loader import LazyAnalyzerLoader
from r2inspect.lazy_loader_stats import build_stats, print_stats
from r2inspect.pipeline.stage_models import AnalysisStage, ThreadSafeContext


class MinimalStage(AnalysisStage):
    def __init__(self, name: str, result: dict[str, object], **kwargs) -> None:
        super().__init__(name, **kwargs)
        self._result = result

    def _execute(self, _context: dict[str, object]) -> dict[str, object]:
        return self._result


def test_build_stats_and_print_stats_report_registered_and_loaded_analyzers(capsys) -> None:
    loader = LazyAnalyzerLoader()
    loader.register("base", "r2inspect.schemas.base", "AnalysisResultBase")

    before = build_stats(loader)
    assert before["registered"] == 1
    assert before["loaded"] == 0
    assert before["unloaded"] == 1

    loader.get_analyzer_class("base")
    after = build_stats(loader)
    assert after["loaded"] == 1
    assert "base" in after["load_times"]

    print_stats(loader)
    out = capsys.readouterr().out
    assert "Lazy Loader Statistics" in out
    assert "Registered analyzers:" in out
    assert "Load Times" in out


def test_analysis_stage_behaviors_cover_dependencies_conditions_and_error_capture() -> None:
    ready_stage = MinimalStage("ready", {"ok": True}, dependencies=["metadata"])
    assert ready_stage.can_execute({"metadata"}) is True
    assert ready_stage.can_execute(set()) is False

    skipped = MinimalStage("skipped", {"ignored": True}, condition=lambda _ctx: False)
    assert skipped.execute({"results": {}}) == {}

    broken_condition = MinimalStage(
        "broken-condition",
        {"ignored": True},
        condition=lambda _ctx: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    assert broken_condition.should_execute({}) is False

    class FailingStage(AnalysisStage):
        def _execute(self, _context: dict[str, object]) -> dict[str, object]:
            raise RuntimeError("stage failed")

    context: dict[str, object] = {"results": {}}
    result = FailingStage("failing").execute(context)
    assert result["failing"]["success"] is False
    assert context["results"]["failing"]["success"] is False


def test_thread_safe_context_exposes_copy_based_snapshot_and_updates_values() -> None:
    ctx = ThreadSafeContext({"value": 1})
    assert ctx.get("value") == 1
    assert ctx.get("missing", "fallback") == "fallback"

    snapshot = ctx.get_all()
    ctx.set("value", 2)
    ctx.update({"extra": True})

    assert snapshot == {"value": 1}
    assert ctx.get("value") == 2
    assert ctx.get("extra") is True
