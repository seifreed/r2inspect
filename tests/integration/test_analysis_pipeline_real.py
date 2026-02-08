from __future__ import annotations

import time
from typing import Any

import pytest

from r2inspect.pipeline.analysis_pipeline import AnalysisPipeline, AnalysisStage


class _Stage(AnalysisStage):
    def __init__(
        self,
        name: str,
        *,
        dependencies: list[str] | None = None,
        condition=None,
        timeout: float | None = None,
    ) -> None:
        super().__init__(
            name=name,
            description="test stage",
            optional=False,
            dependencies=dependencies,
            condition=condition,
            timeout=timeout,
        )

    def _execute(self, context: dict[str, Any]) -> dict[str, Any]:
        order = context.setdefault("order", [])
        order.append(self.name)
        context["results"][self.name] = {"success": True}
        return {self.name: {"success": True}}


class _DependentStage(_Stage):
    def __init__(self, name: str, required_key: str, **kwargs: Any) -> None:
        super().__init__(name, **kwargs)
        self.required_key = required_key

    def _execute(self, context: dict[str, Any]) -> dict[str, Any]:
        if self.required_key not in context.get("results", {}):
            raise RuntimeError("missing dependency data")
        return super()._execute(context)


class _TimeoutStage(AnalysisStage):
    def __init__(self, name: str, timeout: float) -> None:
        super().__init__(name=name, optional=False, timeout=timeout)

    def _execute(self, context: dict[str, Any]) -> dict[str, Any]:
        time.sleep(self.timeout + 0.2)
        return {self.name: {"success": True}}


def test_pipeline_parallel_dependency_order():
    pipeline = AnalysisPipeline(max_workers=2)
    stage_a = _Stage("stage_a")
    stage_b = _DependentStage("stage_b", required_key="stage_a", dependencies=["stage_a"])
    pipeline.add_stage(stage_a).add_stage(stage_b)

    results = pipeline.execute(parallel=True)

    assert results["stage_a"]["success"] is True
    assert results["stage_b"]["success"] is True


def test_pipeline_parallel_condition_skip():
    pipeline = AnalysisPipeline(max_workers=2)
    stage_a = _Stage("stage_a")
    stage_skip = _Stage("stage_skip", condition=lambda ctx: False)
    pipeline.add_stage(stage_a).add_stage(stage_skip)

    results = pipeline.execute(parallel=True)

    assert "stage_a" in results
    assert "stage_skip" not in results


def test_pipeline_parallel_timeout_error():
    pipeline = AnalysisPipeline(max_workers=2)
    pipeline.add_stage(_TimeoutStage("slow", timeout=0.1))

    results = pipeline.execute(parallel=True)

    assert results["slow"]["success"] is False
    assert "Timeout" in results["slow"]["error"]
