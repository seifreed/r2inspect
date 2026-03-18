"""Pipeline orchestration for analysis stages."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .pipeline_parallel_runtime import execute_parallel_pipeline
from .pipeline_sequential_runtime import (
    execute_sequential_pipeline,
    execute_with_progress_pipeline,
)
from .stage_models import AnalysisStage, ThreadSafeContext

__all__ = ["AnalysisPipeline", "AnalysisStage", "ThreadSafeContext"]


class AnalysisPipeline:
    """Configurable pipeline for orchestrating analysis stages."""

    def __init__(self, max_workers: int | None = None):
        self.stages: list[AnalysisStage] = []
        self.max_workers = max_workers
        self._execution_count = 0
        self._progress_callback: Callable[[str, int, int], None] | None = None

    def add_stage(self, stage: AnalysisStage) -> AnalysisPipeline:
        self.stages.append(stage)
        return self

    def remove_stage(self, name: str) -> bool:
        original_length = len(self.stages)
        self.stages = [s for s in self.stages if s.name != name]
        return len(self.stages) < original_length

    def get_stage(self, name: str) -> AnalysisStage | None:
        for stage in self.stages:
            if stage.name == name:
                return stage
        return None

    def list_stages(self) -> list[str]:
        return [stage.name for stage in self.stages]

    def set_progress_callback(self, callback: Callable[[str, int, int], None] | None) -> None:
        self._progress_callback = callback

    def execute(
        self, options: dict[str, Any] | None = None, parallel: bool = False
    ) -> dict[str, Any]:
        return self.execute_parallel(options) if parallel else self._execute_sequential(options)

    def execute_parallel(self, options: dict[str, Any] | None = None) -> dict[str, Any]:
        return execute_parallel_pipeline(self, options)

    def _execute_sequential(self, options: dict[str, Any] | None = None) -> dict[str, Any]:
        return execute_sequential_pipeline(self, options)

    def execute_with_progress(
        self,
        progress_callback: Callable[[str, int, int], None],
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return execute_with_progress_pipeline(self, progress_callback, options)

    def clear(self) -> None:
        self.stages.clear()

    def __len__(self) -> int:
        return len(self.stages)

    def __repr__(self) -> str:
        return f"AnalysisPipeline(stages={len(self.stages)}, executed={self._execution_count})"
