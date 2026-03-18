from __future__ import annotations

from typing import Any

from r2inspect.pipeline.stage_models import AnalysisStage


def make_stage_context() -> dict[str, Any]:
    return {"options": {}, "results": {}, "metadata": {}}


class StaticResultStage(AnalysisStage):
    def __init__(
        self,
        name: str,
        result: dict[str, Any],
        *,
        dependencies: list[str] | None = None,
        condition=None,
        timeout: float | None = None,
    ) -> None:
        super().__init__(
            name=name,
            dependencies=dependencies,
            condition=condition,
            timeout=timeout,
        )
        self._result = result

    def _execute(self, _context: dict[str, Any]) -> dict[str, Any]:
        return self._result
