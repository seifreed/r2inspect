"""Use case: Run batch analysis on a directory of binaries."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ...domain.analysis_runtime import BatchRunResult
from ..batch_execution import (
    build_execution_plan,
    configure_batch_runtime,
    execute_batch_plan,
    finalize_batch_result,
)
from ..batch_models import BatchDependencies


@dataclass(frozen=True)
class RunBatchRequest:
    """Input DTO for batch analysis."""

    batch_dir: str
    deps: BatchDependencies
    options: dict[str, Any]
    output_dir: str | None = None
    output_json: bool = False
    output_csv: bool = False
    extensions: str | None = None
    recursive: bool = True
    threads: int = 10
    verbose: bool = False
    quiet: bool = False
    auto_detect: bool = True
    config_obj: Any = None
    output_path: Path | None = None


class RunBatchAnalysisUseCase:
    """Orchestrate batch analysis of multiple binary files."""

    def execute(self, request: RunBatchRequest) -> BatchRunResult | None:
        """Run batch analysis and return a typed domain result."""
        deps = request.deps

        plan = build_execution_plan(
            batch_dir=request.batch_dir,
            deps=deps,
            output_dir=request.output_dir,
            output_json=request.output_json,
            output_csv=request.output_csv,
            output_path=request.output_path,
            auto_detect=request.auto_detect,
            extensions=request.extensions,
            recursive=request.recursive,
            verbose=request.verbose,
            quiet=request.quiet,
        )
        if not plan.files_to_process:
            if deps.display_no_files_message is not None:
                deps.display_no_files_message(request.auto_detect, request.extensions)
            return None

        configure_batch_runtime(
            deps,
            files_to_process=plan.files_to_process,
            threads=request.threads,
            verbose=request.verbose,
            quiet=request.quiet,
        )
        batch_result, rate_limiter = execute_batch_plan(
            plan=plan,
            deps=deps,
            options=request.options,
            output_json=request.output_json,
            config_obj=request.config_obj,
            threads=request.threads,
            verbose=request.verbose,
        )
        finalize_batch_result(
            deps,
            batch_result=batch_result,
            rate_limiter=rate_limiter,
            output_json=request.output_json,
            output_csv=request.output_csv,
            verbose=request.verbose,
        )
        return batch_result

    def run(
        self,
        batch_dir: str,
        options: dict[str, Any],
        deps: BatchDependencies,
        *,
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
        """Convenience wrapper matching the old keyword-arg signature."""
        return self.execute(
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
