"""Regression: terminate_radare2_processes must escalate SIGTERM to SIGKILL.

A radare2 wedged in a CPU-bound, uninterruptible loop ignores SIGTERM; if
safe-mode reopen only calls terminate() it survives and keeps burning a core.
The reaper must fall back to kill(). Verified with hand-rolled fakes injected
via the process_iter seam — no mocks, no monkeypatch.
"""

from __future__ import annotations

import psutil
import pytest

from r2inspect.infrastructure.r2_session_cleanup import terminate_radare2_processes

_FILENAME = "/tmp/sample.bin"


class _FakeProc:
    def __init__(
        self, name: str, *, wait_times_out: bool = False, wait_error: bool = False
    ) -> None:
        self.info = {"name": name, "cmdline": [_FILENAME]}
        self._wait_times_out = wait_times_out
        self._wait_error = wait_error
        self.terminated = False
        self.killed = False

    def terminate(self) -> None:
        self.terminated = True

    def wait(self, timeout: float | None = None) -> int:
        if self._wait_error:
            raise RuntimeError("wait blew up")
        if self._wait_times_out:
            raise psutil.TimeoutExpired(timeout or 0.0)
        return 0

    def kill(self) -> None:
        self.killed = True


def _iter_of(*procs: _FakeProc):
    def _iterator(_fields):
        return list(procs)

    return _iterator


@pytest.mark.unit
def test_wedged_radare2_is_killed_after_sigterm_timeout() -> None:
    wedged = _FakeProc("radare2", wait_times_out=True)
    terminate_radare2_processes(_FILENAME, process_iter=_iter_of(wedged), kill_timeout=0.01)
    assert wedged.terminated is True
    assert wedged.killed is True


@pytest.mark.unit
def test_well_behaved_radare2_is_not_killed() -> None:
    polite = _FakeProc("radare2")
    terminate_radare2_processes(_FILENAME, process_iter=_iter_of(polite), kill_timeout=0.01)
    assert polite.terminated is True
    assert polite.killed is False


@pytest.mark.unit
def test_non_radare2_process_is_left_alone() -> None:
    other = _FakeProc("python")
    terminate_radare2_processes(_FILENAME, process_iter=_iter_of(other), kill_timeout=0.01)
    assert other.terminated is False
    assert other.killed is False


@pytest.mark.unit
def test_kill_failure_is_swallowed() -> None:
    class _KillFails(_FakeProc):
        def kill(self) -> None:
            raise psutil.NoSuchProcess(pid=1, name="radare2")

    proc = _KillFails("radare2", wait_times_out=True)
    # Must not raise even though kill() fails.
    terminate_radare2_processes(_FILENAME, process_iter=_iter_of(proc), kill_timeout=0.01)
    assert proc.terminated is True


@pytest.mark.unit
def test_wait_error_other_than_timeout_is_swallowed() -> None:
    proc = _FakeProc("radare2", wait_error=True)
    # A non-timeout wait() error is logged, not raised, and no kill happens.
    terminate_radare2_processes(_FILENAME, process_iter=_iter_of(proc), kill_timeout=0.01)
    assert proc.terminated is True
    assert proc.killed is False
