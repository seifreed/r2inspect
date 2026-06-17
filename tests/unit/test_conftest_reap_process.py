"""Regression: the test-suite process reaper must escalate SIGTERM to SIGKILL.

A radare2 wedged in a CPU-bound, uninterruptible loop ignores SIGTERM; if the
reaper only calls ``terminate()`` it survives the sweep and keeps burning a core
orphaned for the rest of the session. ``reap_process`` must fall back to
``kill()``. Verified against real subprocesses — no mocks.
"""

from __future__ import annotations

import sys
import time

import psutil
import pytest

from tests.helpers.process_reaper import reap_process

# Ignores SIGTERM, then spins so it stays alive until SIGKILL arrives.
_SIGTERM_IGNORING = (
    "import signal, time\n"
    "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
    "print('ready', flush=True)\n"
    "while True: time.sleep(0.05)\n"
)

# Honors the default SIGTERM disposition and exits promptly.
_SIGTERM_HONORING = "import time\nprint('ready', flush=True)\ntime.sleep(30)\n"


def _spawn(script: str) -> psutil.Process:
    proc = psutil.Popen(
        [sys.executable, "-c", script],
        stdout=psutil.subprocess.PIPE,
        text=True,
    )
    proc.stdout.readline()  # block until the child installed its handler
    return proc


@pytest.mark.unit
def test_reap_process_kills_sigterm_ignoring_child() -> None:
    proc = _spawn(_SIGTERM_IGNORING)
    try:
        assert proc.is_running()
        reap_process(proc, timeout=0.3)
        assert not proc.is_running() or proc.status() == psutil.STATUS_ZOMBIE
    finally:
        if proc.is_running():
            proc.kill()


@pytest.mark.unit
def test_reap_process_terminates_well_behaved_child() -> None:
    proc = _spawn(_SIGTERM_HONORING)
    try:
        start = time.monotonic()
        reap_process(proc, timeout=2.0)
        # SIGTERM is honored, so it dies without needing the kill escalation.
        assert not proc.is_running() or proc.status() == psutil.STATUS_ZOMBIE
        assert time.monotonic() - start < 2.0
    finally:
        if proc.is_running():
            proc.kill()


@pytest.mark.unit
def test_reap_process_tolerates_already_dead_child() -> None:
    proc = _spawn(_SIGTERM_HONORING)
    proc.kill()
    proc.wait(timeout=2)
    # No NoSuchProcess should escape — reaping a corpse is a no-op.
    reap_process(proc, timeout=0.3)
