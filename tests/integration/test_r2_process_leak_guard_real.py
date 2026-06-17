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

from pathlib import Path

import psutil
import pytest

from r2inspect.application.use_cases import AnalyzeBinaryUseCase
from r2inspect.factory import create_inspector
from tests.helpers import env_vars

pytestmark = pytest.mark.requires_r2

_FIXTURE = Path("samples/fixtures/hello_pe.exe")
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
