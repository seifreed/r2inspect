"""Parallel execution helpers for analysis pipelines."""

from __future__ import annotations

import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from concurrent.futures import as_completed
from typing import Any, cast

from .pipeline_runtime_common import (
    build_threadsafe_context,
    error_result,
    merge_stage_results,
    stage_success,
)
from .stage_models import AnalysisStage, ThreadSafeContext

logger = logging.getLogger(__name__)


def get_effective_workers(max_workers: int | None) -> int:
    configured = max_workers if max_workers is not None else min(4, os.cpu_count() or 1)
    cap_text = os.getenv("R2INSPECT_MAX_WORKERS", "").strip()
    if not cap_text:
        return configured
    try:
        cap = int(cap_text)
    except ValueError:
        return configured
    if cap <= 0:
        return configured
    return min(configured, cap)


def get_ready_stages(
    remaining: list[AnalysisStage],
    completed: set[str],
    context_snapshot: dict[str, Any],
    failed: set[str] | None = None,
) -> list[AnalysisStage]:
    return [
        stage
        for stage in remaining
        if stage.can_execute(completed, failed) and stage.should_execute(context_snapshot)
    ]


def get_skipped_stages(
    remaining: list[AnalysisStage],
    completed: set[str],
    context_snapshot: dict[str, Any],
    failed: set[str] | None = None,
) -> list[AnalysisStage]:
    return [
        stage
        for stage in remaining
        if stage.can_execute(completed, failed) and not stage.should_execute(context_snapshot)
    ]


def apply_skipped_stages(
    skipped_stages: list[AnalysisStage],
    remaining: list[AnalysisStage],
    completed: set[str],
    completed_lock: threading.Lock,
    remaining_lock: threading.Lock | None = None,
) -> int:
    skipped_count = 0
    for stage in skipped_stages:
        if remaining_lock is not None:
            with remaining_lock:
                if stage in remaining:
                    remaining.remove(stage)
        else:
            if stage in remaining:
                remaining.remove(stage)
        with completed_lock:
            completed.add(stage.name)
        skipped_count += 1
        logger.debug("Skipping stage '%s' (condition not met)", stage.name)
    return skipped_count


def handle_no_ready_stages(
    remaining: list[AnalysisStage],
    completed: set[str],
    ts_context: ThreadSafeContext | None = None,
) -> bool:
    if not completed:
        raise RuntimeError("No stages can execute - check dependencies or conditions")
    if remaining:
        unsatisfied = [s.name for s in remaining if not s.can_execute(completed)]
        if unsatisfied:
            logger.warning(
                "Unsatisfied dependencies detected — skipping stages: %s",
                unsatisfied,
            )
            # Record skipped stages as errors in context so callers know analysis is incomplete
            if ts_context is not None:
                for name in unsatisfied:
                    ts_context.merge_results(
                        {name: {"error": "Skipped: unsatisfied dependencies", "success": False}}
                    )
    return True


def submit_ready_stages(
    executor: ThreadPoolExecutor,
    ready_stages: list[AnalysisStage],
    ts_context: ThreadSafeContext,
    stage_executor,
) -> dict[Any, AnalysisStage]:
    future_to_stage: dict[Any, AnalysisStage] = {}
    for stage in ready_stages:
        future = executor.submit(stage_executor, stage, ts_context)
        future_to_stage[future] = stage
    return future_to_stage


def collect_futures(
    future_to_stage: dict[Any, AnalysisStage],
    ts_context: ThreadSafeContext,
    remaining: list[AnalysisStage],
    completed: set[str],
    failed: set[str],
    completed_lock: threading.Lock,
    remaining_lock: threading.Lock,
) -> dict[str, int]:
    executed_count = 0
    failed_count = 0
    for future in as_completed(future_to_stage):
        stage = future_to_stage[future]
        try:
            stage_result, success = future.result()
            merge_stage_results(ts_context, stage_result)
            with completed_lock:
                completed.add(stage.name)
                if not success:
                    failed.add(stage.name)
            with remaining_lock:
                if stage in remaining:
                    remaining.remove(stage)
            if success:
                executed_count += 1
                logger.debug("Stage '%s' completed successfully", stage.name)
            else:
                failed_count += 1
                logger.warning("Stage '%s' failed", stage.name)
        except Exception as exc:
            logger.error("Unexpected error executing stage '%s': %s", stage.name, exc)
            with completed_lock:
                completed.add(stage.name)
                failed.add(stage.name)
            with remaining_lock:
                if stage in remaining:
                    remaining.remove(stage)
            failed_count += 1
            merge_stage_results(ts_context, error_result(stage.name, str(exc)))
    return {"executed": executed_count, "failed": failed_count}


def execute_stage_with_timeout(
    stage: AnalysisStage, ts_context: ThreadSafeContext
) -> tuple[dict[str, Any], bool]:
    context = ts_context.get_all()
    if stage.timeout:
        with ThreadPoolExecutor(max_workers=1) as timeout_executor:
            future = timeout_executor.submit(stage.execute, context)
            try:
                result = future.result(timeout=stage.timeout)
                return result, stage_success(result, stage.name)
            except FuturesTimeoutError:
                logger.error("Stage '%s' timed out after %ss", stage.name, stage.timeout)
                return error_result(stage.name, f"Timeout after {stage.timeout}s"), False
            except Exception as exc:
                logger.error("Stage '%s' raised exception: %s", stage.name, exc)
                return error_result(stage.name, str(exc)), False
    try:
        result = stage.execute(context)
        return result, stage_success(result, stage.name)
    except Exception as exc:
        logger.error("Stage '%s' raised exception: %s", stage.name, exc)
        return error_result(stage.name, str(exc)), False


def execute_parallel_pipeline(pipeline, options: dict[str, Any] | None = None) -> dict[str, Any]:
    pipeline._execution_count += 1
    execution_id = pipeline._execution_count

    logger.info(
        "Starting parallel pipeline execution #%s with %s stages",
        execution_id,
        len(pipeline.stages),
    )

    ts_context = build_threadsafe_context(options, execution_id)
    completed: set[str] = set()
    failed: set[str] = set()
    completed_lock = threading.Lock()
    remaining_lock = threading.Lock()
    remaining = list(pipeline.stages)

    executed_count = 0
    skipped_count = 0
    failed_count = 0

    with ThreadPoolExecutor(max_workers=get_effective_workers(pipeline.max_workers)) as executor:
        while True:
            with remaining_lock:
                if not remaining:
                    break
                snapshot_remaining = list(remaining)

            context_snapshot = ts_context.get_all()
            with completed_lock:
                snapshot_completed = set(completed)
                snapshot_failed = set(failed)

            ready_stages = get_ready_stages(
                snapshot_remaining, snapshot_completed, context_snapshot, snapshot_failed
            )
            skipped_stages = get_skipped_stages(
                snapshot_remaining, snapshot_completed, context_snapshot, snapshot_failed
            )

            with remaining_lock:
                for stage in skipped_stages:
                    if stage in remaining:
                        remaining.remove(stage)
            with completed_lock:
                for stage in skipped_stages:
                    completed.add(stage.name)
            skipped_count += len(skipped_stages)
            for stage in skipped_stages:
                logger.debug("Skipping stage '%s' (condition not met)", stage.name)

            if not ready_stages:
                with remaining_lock:
                    still_remaining = bool(remaining)
                if still_remaining and handle_no_ready_stages(
                    snapshot_remaining, snapshot_completed, ts_context
                ):
                    break
                if not still_remaining:
                    break

            future_to_stage = submit_ready_stages(
                executor, ready_stages, ts_context, execute_stage_with_timeout
            )
            stats = collect_futures(
                future_to_stage,
                ts_context,
                remaining,
                completed,
                failed,
                completed_lock,
                remaining_lock,
            )
            executed_count += stats["executed"]
            failed_count += stats["failed"]

    logger.info(
        "Parallel pipeline execution #%s complete: %s succeeded, %s failed, %s skipped",
        execution_id,
        executed_count,
        failed_count,
        skipped_count,
    )
    return cast(dict[str, Any], ts_context.get("results", {}))
