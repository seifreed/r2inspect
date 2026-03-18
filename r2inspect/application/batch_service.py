#!/usr/bin/env python3
"""Application service facade for batch analysis orchestration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..domain.analysis_runtime import BatchRunResult
from .batch_models import BatchDependencies
from .use_cases.run_batch_analysis import RunBatchAnalysisUseCase, RunBatchRequest


class BatchAnalysisService:
    """Coordinate batch analysis and return a pure result for the CLI.

    This is now a thin wrapper that delegates to
    :class:`RunBatchAnalysisUseCase` for backward compatibility.
    """

    def __init__(self, use_case: RunBatchAnalysisUseCase | None = None) -> None:
        self._use_case = use_case or RunBatchAnalysisUseCase()

    def run_batch_analysis(
        self,
        batch_dir: str,
        options: dict[str, Any],
        deps: BatchDependencies,
        output_json: bool = False,
        output_csv: bool = False,
        output_dir: str | None = None,
        recursive: bool = True,
        extensions: str | None = None,
        verbose: bool = False,
        config_obj: Any = None,
        auto_detect: bool = True,
        threads: int = 10,
        quiet: bool = False,
        output_path: Path | None = None,
    ) -> BatchRunResult | None:
        return self._use_case.execute(
            RunBatchRequest(
                batch_dir=batch_dir,
                deps=deps,
                options=options,
                output_dir=output_dir,
                output_json=output_json,
                output_csv=output_csv,
                extensions=extensions,
                recursive=recursive,
                threads=threads,
                verbose=verbose,
                quiet=quiet,
                auto_detect=auto_detect,
                config_obj=config_obj,
                output_path=output_path,
            )
        )


_default_batch_service: BatchAnalysisService | None = None


def get_default_batch_service() -> BatchAnalysisService:
    """Return the lazily-created default BatchAnalysisService singleton."""
    global _default_batch_service
    if _default_batch_service is None:
        _default_batch_service = BatchAnalysisService()
    return _default_batch_service


class _BatchServiceProxy:
    """Thin proxy so that ``default_batch_service.xxx`` still works."""

    def __getattr__(self, name: str) -> Any:
        return getattr(get_default_batch_service(), name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(get_default_batch_service(), name, value)


default_batch_service: BatchAnalysisService = _BatchServiceProxy()  # type: ignore[assignment]
