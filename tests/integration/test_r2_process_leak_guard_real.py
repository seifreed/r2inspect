#!/usr/bin/env python3
"""Empirical regression guard: repeated analysis must not leak r2 or FDs.

This is the measurement counterpart to the unit-level reaping tests. It runs
many real create_inspector -> analyze -> close cycles against a real binary
through real radare2, and asserts that neither orphaned radare2 child
processes nor open file descriptors accumulate. It would have failed before
the r2-lifecycle reaping fixes (magic cache, force_close_process, timed-out
open orphan, forced-exit child reaping).
"""

from __future__ import annotations

import gc
import sys
from pathlib import Path

import psutil
import pytest

from r2inspect.application.use_cases import AnalyzeBinaryUseCase
from r2inspect.config import Config
from r2inspect.factory import create_inspector
from r2inspect.cli.batch_workers import process_files_parallel
from r2inspect.infrastructure.rate_limiter import BatchRateLimiter
from tests.helpers import env_vars

pytestmark = pytest.mark.requires_r2

_FIXTURE = Path("samples/fixtures/hello_pe.exe")
_FIXTURE_DIR = Path("samples/fixtures")
_CYCLES = 8


def _radare2_child_count(proc: psutil.Process) -> int:
    count = 0
    for child in proc.children(recursive=True):
        try:
            if "radare2" in (child.name() or "").lower():
                count += 1
        except psutil.Error:
            continue
    return count


def _run_one_cycle() -> None:
    with create_inspector(filename=str(_FIXTURE)) as inspector:
        AnalyzeBinaryUseCase().run(inspector, {"batch_mode": True})


def test_repeated_analysis_leaks_no_processes_or_fds() -> None:
    if not _FIXTURE.exists():
        pytest.skip("hello_pe.exe fixture missing")

    proc = psutil.Process()
    with env_vars(R2INSPECT_TEST_MODE="1", R2INSPECT_ANALYSIS_DEPTH="0"):
        # Warmup absorbs one-time allocations (logging file handler, imports)
        # so the baseline reflects steady state, not first-run setup.
        _run_one_cycle()
        base_fds = proc.num_fds()
        base_children = _radare2_child_count(proc)

        for _ in range(_CYCLES):
            _run_one_cycle()

        leaked_children = _radare2_child_count(proc) - base_children
        leaked_fds = proc.num_fds() - base_fds

    assert (
        leaked_children <= 0
    ), f"orphaned radare2 processes after {_CYCLES} cycles: +{leaked_children}"
    # Small tolerance: an incidentally re-opened fd is not a per-cycle leak.
    assert leaked_fds <= 2, f"file descriptors leaked across {_CYCLES} cycles: +{leaked_fds}"


def test_repeated_analysis_on_one_inspector_does_not_grow_objects() -> None:
    """Long-lived inspector (interactive session) must not accumulate objects.

    Re-analyzing through a single inspector exercises the adapter command cache
    and result aggregation repeatedly. A per-run container that never clears
    would show up as monotonic live-object growth here.
    """
    if not _FIXTURE.exists():
        pytest.skip("hello_pe.exe fixture missing")
    if sys.platform != "linux":
        pytest.skip("gc.get_objects() leak guard is stable only on Linux CI")

    with (
        env_vars(R2INSPECT_TEST_MODE="1", R2INSPECT_ANALYSIS_DEPTH="0"),
        create_inspector(filename=str(_FIXTURE)) as inspector,
    ):
        for _ in range(3):  # warmup: fill caches to steady state
            inspector.analyze(batch_mode=True)
        half_cycles = _CYCLES // 2
        gc.collect()
        base_objects = len(gc.get_objects())

        for _ in range(half_cycles):
            inspector.analyze(batch_mode=True)
        gc.collect()
        mid_objects = len(gc.get_objects())

        for _ in range(half_cycles):
            inspector.analyze(batch_mode=True)
        gc.collect()
        final_objects = len(gc.get_objects())

    first_window_growth = mid_objects - base_objects
    second_window_growth = final_objects - mid_objects
    # Runtime/library caches can appear after warmup on some Python builds. A
    # sustained per-run leak should still grow in the second measurement window.
    assert (
        second_window_growth <= 750
    ), f"live objects kept growing by {second_window_growth} over {half_cycles} analyze() calls"
    assert second_window_growth <= max(
        250, first_window_growth
    ), f"second growth window ({second_window_growth}) exceeded first ({first_window_growth})"


def test_parallel_batch_leaks_no_processes_or_fds(tmp_path: Path) -> None:
    """Concurrent batch (ThreadPoolExecutor, many r2 spawns) must reap cleanly.

    The batch worker spawns one radare2 per file across worker threads. After
    the batch completes, no radare2 child process or file descriptor should
    remain — this is the real-world 'spawn r2 then close it' path at scale.
    """
    files = [path for path in _FIXTURE_DIR.glob("*") if path.is_file()]
    if len(files) < 2:
        pytest.skip("need at least 2 binary fixtures for a batch")

    proc = psutil.Process()
    all_results: dict[str, dict] = {}
    failed: list[tuple[str, str]] = []
    with env_vars(R2INSPECT_TEST_MODE="1", R2INSPECT_ANALYSIS_DEPTH="0"):
        base_fds = proc.num_fds()
        base_children = _radare2_child_count(proc)
        rate_limiter = BatchRateLimiter(max_concurrent=4, rate_per_second=50, burst_size=20)
        process_files_parallel(
            files,
            all_results,
            failed,
            tmp_path,
            _FIXTURE_DIR,
            Config(),
            {"batch_mode": True},
            False,
            4,
            rate_limiter,
        )
        leaked_children = _radare2_child_count(proc) - base_children
        leaked_fds = proc.num_fds() - base_fds

    assert all_results, "batch processed no files"
    assert leaked_children <= 0, f"orphaned radare2 after parallel batch: +{leaked_children}"
    assert leaked_fds <= 2, f"file descriptors leaked after parallel batch: +{leaked_fds}"
