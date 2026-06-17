#!/usr/bin/env python3
"""A stage timeout must abort the pipeline, not block on the hung stage.

Regression guard: execute_stage_with_timeout used a `with ThreadPoolExecutor`
block, whose exit calls shutdown(wait=True) — that blocked until the hung
stage finished, defeating the timeout. The pipeline must return the timeout
result while the runaway stage is still running.
"""

from __future__ import annotations

import threading

from r2inspect.pipeline.analysis_pipeline import AnalysisPipeline, AnalysisStage


class _CallableStage(AnalysisStage):
    def __init__(self, name, fn, **kwargs):
        super().__init__(name=name, **kwargs)
        self._fn = fn

    def _execute(self, _context):
        return {self.name: self._fn()}


def test_timeout_returns_without_waiting_for_hung_stage():
    release = threading.Event()
    completed = threading.Event()

    def hung():
        # Bounded so the worker can never leak past the test even on old code.
        release.wait(10.0)
        completed.set()
        return {"value": 1}

    pipeline = AnalysisPipeline(max_workers=2)
    pipeline.add_stage(_CallableStage("hung", hung, timeout=0.05))

    try:
        results = pipeline.execute(parallel=True)
        # The fix: execute() returned while the stage is still blocked on
        # `release`. On the old (wait=True) code this assertion only ran after
        # the stage finished, so `completed` would be set.
        assert not completed.is_set()
        assert results["hung"].get("success") is False
        assert "Timeout" in results["hung"].get("error", "")
    finally:
        release.set()  # let the orphaned worker finish so no thread lingers


def test_timeout_stage_succeeds_within_timeout():
    pipeline = AnalysisPipeline(max_workers=2)
    pipeline.add_stage(_CallableStage("fast", lambda: {"value": 1}, timeout=5.0))

    results = pipeline.execute(parallel=True)
    assert results["fast"] == {"value": 1}


class _RaisingStage(AnalysisStage):
    """A stage whose execute() raises directly (bypasses the base catch)."""

    def execute(self, _context):
        raise RuntimeError("kaboom")

    def _execute(self, _context):
        return {}


def test_timeout_stage_exception_becomes_error():
    pipeline = AnalysisPipeline(max_workers=2)
    pipeline.add_stage(_RaisingStage("boom", timeout=5.0))

    results = pipeline.execute(parallel=True)
    assert results["boom"].get("success") is False
    assert "kaboom" in results["boom"].get("error", "")
