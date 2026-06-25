"""Sequential execution helpers for analysis pipelines."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, cast

from .pipeline_runtime_common import build_context, merge_into_plain_context

if TYPE_CHECKING:
    from .analysis_pipeline import AnalysisPipeline

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str, int, int], None]


def _invoke_progress_callback(
    callback: ProgressCallback | None, stage_name: str, idx: int, total: int
) -> None:
    if not callback:
        return
    try:
        callback(stage_name, idx, total)
    except Exception as exc:
        logger.debug("Progress callback failed for %s (%s/%s): %s", stage_name, idx, total, exc)


def execute_sequential_pipeline(
    pipeline: AnalysisPipeline,
    options: dict[str, Any] | None = None,
    progress_callback: ProgressCallback | None = None,
) -> dict[str, Any]:
    pipeline._execution_count += 1
    execution_id = pipeline._execution_count

    logger.info(
        "Starting sequential pipeline execution #%s with %s stages",
        execution_id,
        len(pipeline.stages),
    )
    context = build_context(options, execution_id)
    executed_count = 0
    skipped_count = 0
    failed_count = 0
    completed: set[str] = set()
    failed_stages: set[str] = set()
    total_stages = len(pipeline.stages)
    effective_callback = progress_callback or getattr(pipeline, "_progress_callback", None)

    for idx, stage in enumerate(pipeline.stages, 1):
        _invoke_progress_callback(effective_callback, stage.name, idx, total_stages)
        if not stage.can_execute(completed, failed_stages):
            logger.warning("Skipping stage '%s': unsatisfied dependencies", stage.name)
            error_result = {
                stage.name: {"error": "Skipped: unsatisfied dependencies", "success": False}
            }
            merge_into_plain_context(context, error_result)
            completed.add(stage.name)
            failed_stages.add(stage.name)
            failed_count += 1
            continue

        stage_result = stage.execute(context)
        completed.add(stage.name)
        if stage_result:
            merge_into_plain_context(context, stage_result)
            if (
                isinstance(stage_result.get(stage.name), dict)
                and stage_result[stage.name].get("success") is False
            ):
                failed_count += 1
                failed_stages.add(stage.name)
            else:
                executed_count += 1
        else:
            skipped_count += 1
    logger.info(
        "Sequential pipeline execution #%s complete: %s succeeded, %s failed, %s skipped",
        execution_id,
        executed_count,
        failed_count,
        skipped_count,
    )
    return cast(dict[str, Any], context.get("results", {}))


def execute_with_progress_pipeline(
    pipeline: AnalysisPipeline,
    progress_callback: ProgressCallback,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Backward-compatible wrapper that delegates to execute_sequential_pipeline."""
    return execute_sequential_pipeline(pipeline, options, progress_callback)
