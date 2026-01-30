"""
Analysis Pipeline implementation for r2inspect.

This module provides the core pipeline components for orchestrating
analysis stages in a flexible, maintainable way.

Supports both sequential and parallel execution modes with automatic
dependency resolution for optimal performance.

This file defines the unified AnalysisStage base class used by
concrete stages (see stages.py) and the AnalysisPipeline orchestrator.

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0 (GPLv3)
"""

import logging
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from concurrent.futures import as_completed
from typing import Any, cast

logger = logging.getLogger(__name__)


class AnalysisStage:
    """
    Represents a single stage in the analysis pipeline.

    Concrete stages should subclass this class and implement _execute(context),
    storing their output under context['results'][<key>] as needed.

    Attributes:
        name: Unique identifier for the stage
        description: Human-readable description
        optional: Whether this stage is optional
        dependencies: Stage names that must complete before this stage
        condition: Callable that returns True if stage should execute
        timeout: Optional timeout in seconds for this stage (parallel mode only)
    """

    def __init__(
        self,
        name: str,
        analyzer: Callable[[], dict[str, Any]] | None = None,
        description: str = "",
        optional: bool = True,
        *,
        dependencies: list[str] | None = None,
        condition: Callable[[dict[str, Any]], bool] | None = None,
        timeout: float | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.name = name
        self.description = description
        self.optional = optional
        self.dependencies: list[str] = dependencies or []
        self.condition = condition
        self.timeout = timeout
        # Backward-compat convenience mode (callable-based stage)
        self._analyzer = analyzer if callable(analyzer) else None
        self.analyzer = self._analyzer
        self.metadata: dict[str, Any] = metadata or {}

    def can_execute(self, completed_stages: set[str]) -> bool:
        return all(dep in completed_stages for dep in self.dependencies)

    def should_execute(self, context: dict[str, Any]) -> bool:
        if self.condition is None:
            return True
        try:
            return bool(self.condition(context))
        except Exception as e:
            logger.warning(f"Condition check failed for stage '{self.name}': {e}")
            return False

    def _execute(self, _context: dict[str, Any]) -> dict[str, Any]:
        """Default execution for callable-based stages or override in subclass."""
        if self._analyzer is None:
            raise NotImplementedError
        try:
            result = self._analyzer()
        except Exception as e:  # Safety
            return {self.name: {"success": False, "error": str(e)}}
        return {self.name: result}

    def execute(self, context: dict[str, Any]) -> dict[str, Any]:
        if not self.should_execute(context):
            logger.debug(f"Skipping stage '{self.name}' (condition not met)")
            return {}
        try:
            logger.debug(f"Executing stage '{self.name}'")
            return self._execute(context)
        except Exception as e:
            logger.error(f"Stage '{self.name}' failed: {e}")
            # Return error structure under results
            context.setdefault("results", {})
            context["results"][self.name] = {"error": str(e), "success": False}
            return {self.name: {"error": str(e), "success": False}}


class ThreadSafeContext:
    """
    Thread-safe context wrapper for parallel stage execution.

    Provides synchronized access to shared context data when multiple
    stages execute concurrently.
    """

    def __init__(self, initial_data: dict[str, Any] | None = None):
        """
        Initialize thread-safe context.

        Args:
            initial_data: Initial context data
        """
        self._lock = threading.Lock()
        self._data = initial_data or {}

    def update(self, data: dict[str, Any]) -> None:
        """
        Update context data in a thread-safe manner.

        Args:
            data: Dictionary to merge into context
        """
        with self._lock:
            self._data.update(data)

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get value from context in a thread-safe manner.

        Args:
            key: Key to retrieve
            default: Default value if key not found

        Returns:
            Value associated with key or default
        """
        with self._lock:
            return self._data.get(key, default)

    def get_all(self) -> dict[str, Any]:
        """
        Get complete copy of context data.

        Returns:
            Copy of all context data
        """
        with self._lock:
            return self._data.copy()

    def set(self, key: str, value: Any) -> None:
        """
        Set a value in context.

        Args:
            key: Key to set
            value: Value to associate with key
        """
        with self._lock:
            self._data[key] = value


class AnalysisPipeline:
    """
    Configurable pipeline for orchestrating multiple analysis stages.

    The pipeline supports both sequential and parallel execution modes.
    In parallel mode, stages without dependencies execute concurrently
    using ThreadPoolExecutor for improved performance on I/O-bound workloads.

    Parallel Execution:
        The pipeline automatically detects independent stages and executes
        them in parallel while respecting dependency constraints. This can
        significantly reduce analysis time for binaries with multiple
        independent analyzers.

    Example (Sequential):
        >>> pipeline = AnalysisPipeline()
        >>> pipeline.add_stage(AnalysisStage("file_info", get_file_info))
        >>> pipeline.add_stage(AnalysisStage("pe_info", get_pe_info,
        ...                                   condition=lambda ctx: ctx.get("format") == "PE"))
        >>> results = pipeline.execute({"format": "PE"})

    Example (Parallel):
        >>> pipeline = AnalysisPipeline(max_workers=4)
        >>> pipeline.add_stage(AnalysisStage("file_info", get_file_info))
        >>> pipeline.add_stage(AnalysisStage("format", get_format, dependencies=["file_info"]))
        >>> pipeline.add_stage(AnalysisStage("hashes", get_hashes, dependencies=["file_info"]))
        >>> results = pipeline.execute(parallel=True)  # file_info runs first, then format and hashes in parallel

    Attributes:
        stages: List of analysis stages in the pipeline
        max_workers: Maximum number of parallel workers (None = CPU count)
        _execution_count: Number of times pipeline has been executed
    """

    def __init__(self, max_workers: int | None = None):
        """
        Initialize pipeline with optional parallelism support.

        Args:
            max_workers: Max parallel workers (None = CPU count, capped at 4 for I/O workloads)
        """
        self.stages: list[AnalysisStage] = []
        self.max_workers = max_workers
        self._execution_count = 0
        self._progress_callback: Callable[[str, int, int], None] | None = None

    def add_stage(self, stage: AnalysisStage) -> "AnalysisPipeline":
        """
        Add a stage to the pipeline.

        Args:
            stage: AnalysisStage to add

        Returns:
            Self for fluent interface (method chaining)
        """
        self.stages.append(stage)
        logger.debug(f"Added stage '{stage.name}' to pipeline")
        return self

    def remove_stage(self, name: str) -> bool:
        """
        Remove a stage by name.

        Args:
            name: Name of stage to remove

        Returns:
            True if stage was removed, False if not found
        """
        original_length = len(self.stages)
        self.stages = [s for s in self.stages if s.name != name]
        removed = len(self.stages) < original_length

        if removed:
            logger.debug(f"Removed stage '{name}' from pipeline")
        else:
            logger.warning(f"Stage '{name}' not found in pipeline")

        return removed

    def get_stage(self, name: str) -> AnalysisStage | None:
        """
        Get a stage by name.

        Args:
            name: Name of stage to retrieve

        Returns:
            AnalysisStage if found, None otherwise
        """
        for stage in self.stages:
            if stage.name == name:
                return stage
        return None

    def list_stages(self) -> list[str]:
        """
        Get list of all stage names in execution order.

        Returns:
            List of stage names
        """
        return [stage.name for stage in self.stages]

    def set_progress_callback(self, callback: Callable[[str, int, int], None] | None) -> None:
        """Set a progress callback invoked before each stage in sequential mode."""
        self._progress_callback = callback

    def execute_parallel(self, options: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Execute pipeline with parallel stage execution.

        Stages without dependencies run in parallel. Stages with dependencies
        wait for their dependencies to complete. This uses ThreadPoolExecutor
        for concurrency, which is ideal for I/O-bound analyzers.

        Args:
            options: Optional configuration and initial context

        Returns:
            Dictionary containing results from all executed stages

        Raises:
            RuntimeError: If circular dependencies detected
        """
        self._execution_count += 1
        execution_id = self._execution_count

        logger.info(
            f"Starting parallel pipeline execution #{execution_id} with {len(self.stages)} stages"
        )

        # Initialize thread-safe context
        ts_context = ThreadSafeContext(
            {
                "options": options or {},
                "results": {},
                "execution_id": execution_id,
                "metadata": {},
            }
        )

        completed: set[str] = set()
        completed_lock = threading.Lock()
        remaining = list(self.stages)

        executed_count = 0
        skipped_count = 0
        failed_count = 0

        effective_workers = self._get_effective_workers()

        with ThreadPoolExecutor(max_workers=effective_workers) as executor:
            while remaining:
                context_snapshot = ts_context.get_all()
                ready_stages = self._get_ready_stages(remaining, completed, context_snapshot)
                skipped_stages = self._get_skipped_stages(remaining, completed, context_snapshot)

                skipped_count += self._apply_skipped_stages(
                    skipped_stages, remaining, completed, completed_lock
                )

                if not ready_stages:
                    if self._handle_no_ready_stages(remaining, completed):
                        break

                future_to_stage = self._submit_ready_stages(executor, ready_stages, ts_context)
                stats = self._collect_futures(
                    future_to_stage, ts_context, remaining, completed, completed_lock
                )
                executed_count += stats["executed"]
                failed_count += stats["failed"]

        logger.info(
            f"Parallel pipeline execution #{execution_id} complete: "
            f"{executed_count} succeeded, {failed_count} failed, {skipped_count} skipped"
        )

        return cast(dict[str, Any], ts_context.get("results", {}))

    def _get_effective_workers(self) -> int:
        """Determine effective worker count for parallel execution."""
        import os

        return self.max_workers if self.max_workers is not None else min(4, os.cpu_count() or 1)

    def _get_ready_stages(
        self,
        remaining: list[AnalysisStage],
        completed: set[str],
        context_snapshot: dict[str, Any],
    ) -> list[AnalysisStage]:
        """Find stages that can execute now."""
        return [
            stage
            for stage in remaining
            if stage.can_execute(completed) and stage.should_execute(context_snapshot)
        ]

    def _get_skipped_stages(
        self,
        remaining: list[AnalysisStage],
        completed: set[str],
        context_snapshot: dict[str, Any],
    ) -> list[AnalysisStage]:
        """Find stages that should be skipped (conditions false)."""
        return [
            stage
            for stage in remaining
            if stage.can_execute(completed) and not stage.should_execute(context_snapshot)
        ]

    def _apply_skipped_stages(
        self,
        skipped_stages: list[AnalysisStage],
        remaining: list[AnalysisStage],
        completed: set[str],
        completed_lock: threading.Lock,
    ) -> int:
        """Mark skipped stages as completed and remove from remaining."""
        skipped_count = 0
        for stage in skipped_stages:
            remaining.remove(stage)
            with completed_lock:
                completed.add(stage.name)
            skipped_count += 1
            logger.debug(f"Skipping stage '{stage.name}' (condition not met)")
        return skipped_count

    def _handle_no_ready_stages(self, remaining: list[AnalysisStage], completed: set[str]) -> bool:
        """Handle case when no stages are ready; return True to break."""
        if not completed:
            raise RuntimeError("No stages can execute - check dependencies or conditions")
        if remaining:
            unsatisfied = [s.name for s in remaining if not s.can_execute(completed)]
            if unsatisfied:
                logger.warning(
                    "Circular dependency or unsatisfied dependencies detected for "
                    f"stages: {unsatisfied}"
                )
        return True

    def _submit_ready_stages(
        self,
        executor: ThreadPoolExecutor,
        ready_stages: list[AnalysisStage],
        ts_context: ThreadSafeContext,
    ) -> dict[Any, AnalysisStage]:
        """Submit ready stages to executor."""
        future_to_stage: dict[Any, AnalysisStage] = {}
        for stage in ready_stages:
            future = executor.submit(self._execute_stage_with_timeout, stage, ts_context)
            future_to_stage[future] = stage
        return future_to_stage

    def _collect_futures(
        self,
        future_to_stage: dict[Any, AnalysisStage],
        ts_context: ThreadSafeContext,
        remaining: list[AnalysisStage],
        completed: set[str],
        completed_lock: threading.Lock,
    ) -> dict[str, int]:
        """Collect futures and update context/results."""
        executed_count = 0
        failed_count = 0
        for future in as_completed(future_to_stage):
            stage = future_to_stage[future]
            try:
                stage_result, success = future.result()
                if stage_result:
                    ts_context.update(
                        {
                            "results": {
                                **ts_context.get("results", {}),
                                **stage_result,
                            }
                        }
                    )
                with completed_lock:
                    completed.add(stage.name)
                remaining.remove(stage)
                if success:
                    executed_count += 1
                    logger.debug(f"Stage '{stage.name}' completed successfully")
                else:
                    failed_count += 1
                    logger.warning(f"Stage '{stage.name}' failed")
            except Exception as e:
                logger.error(f"Unexpected error executing stage '{stage.name}': {e}")
                with completed_lock:
                    completed.add(stage.name)
                remaining.remove(stage)
                failed_count += 1
                error_result = {stage.name: {"error": str(e), "success": False}}
                ts_context.update(
                    {
                        "results": {
                            **ts_context.get("results", {}),
                            **error_result,
                        }
                    }
                )
        return {"executed": executed_count, "failed": failed_count}

    def _execute_stage_with_timeout(
        self, stage: AnalysisStage, ts_context: ThreadSafeContext
    ) -> tuple[dict[str, Any], bool]:
        """
        Execute a single stage with optional timeout.

        Args:
            stage: Stage to execute
            ts_context: Thread-safe context

        Returns:
            Tuple of (result_dict, success_flag)
        """
        # Get current context snapshot for stage execution
        context = ts_context.get_all()

        if stage.timeout:
            # Execute with timeout using a nested executor
            with ThreadPoolExecutor(max_workers=1) as timeout_executor:
                future = timeout_executor.submit(stage.execute, context)
                try:
                    result = future.result(timeout=stage.timeout)
                    success = not (
                        isinstance(result.get(stage.name), dict)
                        and result[stage.name].get("success") is False
                    )
                    return result, success
                except FuturesTimeoutError:
                    logger.error(f"Stage '{stage.name}' timed out after {stage.timeout}s")
                    return {
                        stage.name: {
                            "error": f"Timeout after {stage.timeout}s",
                            "success": False,
                        }
                    }, False
                except Exception as e:
                    logger.error(f"Stage '{stage.name}' raised exception: {e}")
                    return {stage.name: {"error": str(e), "success": False}}, False
        else:
            # Execute without timeout
            try:
                result = stage.execute(context)
                success = not (
                    isinstance(result.get(stage.name), dict)
                    and result[stage.name].get("success") is False
                )
                return result, success
            except Exception as e:
                logger.error(f"Stage '{stage.name}' raised exception: {e}")
                return {stage.name: {"error": str(e), "success": False}}, False

    def execute(
        self, options: dict[str, Any] | None = None, parallel: bool = False
    ) -> dict[str, Any]:
        """
        Execute all stages in the pipeline.

        Supports both sequential and parallel execution modes. Parallel mode
        executes independent stages concurrently for improved performance.

        Args:
            options: Optional configuration and initial context
            parallel: If True, use parallel execution with dependency resolution

        Returns:
            Dictionary containing results from all executed stages

        Example:
            >>> # Sequential execution (default)
            >>> results = pipeline.execute()
            >>>
            >>> # Parallel execution
            >>> results = pipeline.execute(parallel=True)
        """
        if parallel:
            return self.execute_parallel(options)
        else:
            return self._execute_sequential(options)

    def _execute_sequential(self, options: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Execute all stages sequentially (original implementation).

        Args:
            options: Optional configuration and initial context

        Returns:
            Dictionary containing results from all executed stages
        """
        self._execution_count += 1
        execution_id = self._execution_count

        logger.info(
            f"Starting sequential pipeline execution #{execution_id} with {len(self.stages)} stages"
        )

        # Initialize context
        context: dict[str, Any] = {
            "options": options or {},
            "results": {},
            "execution_id": execution_id,
        }

        # Execute each stage
        executed_count = 0
        skipped_count = 0
        failed_count = 0

        total_stages = len(self.stages)
        for idx, stage in enumerate(self.stages, 1):
            if self._progress_callback:
                try:
                    self._progress_callback(stage.name, idx, total_stages)
                except Exception as exc:
                    logger.debug(
                        "Progress callback failed for %s (%s/%s): %s",
                        stage.name,
                        idx,
                        total_stages,
                        exc,
                    )
            stage_result = stage.execute(context)

            if stage_result:
                context_results = cast(dict[str, Any], context.get("results", {}))
                context_results.update(stage_result)
                context["results"] = context_results

                # Check if stage failed
                if (
                    isinstance(stage_result.get(stage.name), dict)
                    and stage_result[stage.name].get("success") is False
                ):
                    failed_count += 1
                else:
                    executed_count += 1
            else:
                skipped_count += 1

        logger.info(
            f"Sequential pipeline execution #{execution_id} complete: "
            f"{executed_count} succeeded, {failed_count} failed, {skipped_count} skipped"
        )

        return cast(dict[str, Any], context.get("results", {}))

    def execute_with_progress(
        self,
        progress_callback: Callable[[str, int, int], None],
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Execute pipeline with progress reporting.

        Args:
            progress_callback: Function called for each stage with (name, current, total)
            options: Optional configuration and initial context

        Returns:
            Dictionary containing results from all executed stages
        """
        self._execution_count += 1
        execution_id = self._execution_count

        logger.info(f"Starting pipeline execution #{execution_id} with progress tracking")

        # Initialize context
        context: dict[str, Any] = {
            "options": options or {},
            "results": {},
            "execution_id": execution_id,
        }

        total_stages = len(self.stages)

        # Execute each stage with progress reporting
        for idx, stage in enumerate(self.stages, 1):
            progress_callback(stage.name, idx, total_stages)

            stage_result = stage.execute(context)

            if stage_result:
                context_results = cast(dict[str, Any], context.get("results", {}))
                context_results.update(stage_result)
                context["results"] = context_results

        logger.info(f"Pipeline execution #{execution_id} with progress tracking complete")

        return cast(dict[str, Any], context.get("results", {}))

    def clear(self) -> None:
        """Remove all stages from the pipeline."""
        self.stages.clear()
        logger.debug("Pipeline cleared")

    def __len__(self) -> int:
        """Return the number of stages in the pipeline."""
        return len(self.stages)

    def __repr__(self) -> str:
        """String representation of the pipeline."""
        return f"AnalysisPipeline(stages={len(self.stages)}, executed={self._execution_count})"
