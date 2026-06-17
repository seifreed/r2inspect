#!/usr/bin/env python3
"""force_close_process must close pipes and reap the process.

Regression guard: the production cleanup path (R2Session.close ->
force_close_process) previously only called process.terminate(), leaking
stdio file descriptors and leaving unreaped (zombie) radare2 processes
across a batch run.
"""

from __future__ import annotations

from r2inspect.infrastructure.r2_session_cleanup import force_close_process


class _Stream:
    def __init__(self, *, close_raises: bool = False) -> None:
        self.closed = False
        self._close_raises = close_raises

    def close(self) -> None:
        if self._close_raises:
            raise OSError("close failed")
        self.closed = True


class _Process:
    def __init__(
        self,
        *,
        running: bool,
        terminate_raises: bool = False,
        kill_raises: bool = False,
    ) -> None:
        self.stdin = _Stream()
        self.stdout = _Stream()
        self.stderr = _Stream()
        self._poll = None if running else 0
        self._terminate_raises = terminate_raises
        self._kill_raises = kill_raises
        self.terminated = False
        self.waited = False
        self.killed = False

    def poll(self):
        return self._poll

    def terminate(self) -> None:
        if self._terminate_raises:
            raise OSError("terminate failed")
        self.terminated = True
        self._poll = 0

    def wait(self, timeout=None) -> None:
        self.waited = True

    def kill(self) -> None:
        if self._kill_raises:
            raise OSError("kill failed")
        self.killed = True


class _R2:
    def __init__(self, process) -> None:
        self.process = process


def test_running_process_streams_closed_and_reaped():
    proc = _Process(running=True)
    force_close_process(_R2(proc))

    assert proc.stdin.closed and proc.stdout.closed and proc.stderr.closed
    assert proc.terminated
    assert proc.waited  # reaped, not left as a zombie


def test_already_exited_process_streams_closed_but_not_terminated():
    proc = _Process(running=False)
    force_close_process(_R2(proc))

    assert proc.stdin.closed and proc.stdout.closed and proc.stderr.closed
    assert not proc.terminated


def test_no_process_attribute_returns_early():
    force_close_process(_R2(None))  # must not raise


def test_missing_stream_is_skipped():
    proc = _Process(running=False)
    proc.stdout = None
    force_close_process(_R2(proc))

    assert proc.stdin.closed and proc.stderr.closed


def test_stream_close_failure_is_swallowed():
    proc = _Process(running=False)
    proc.stdin = _Stream(close_raises=True)
    force_close_process(_R2(proc))  # must not raise

    assert proc.stdout.closed and proc.stderr.closed


def test_terminate_failure_falls_back_to_kill():
    proc = _Process(running=True, terminate_raises=True)
    force_close_process(_R2(proc))

    assert proc.killed


def test_kill_failure_is_swallowed():
    proc = _Process(running=True, terminate_raises=True, kill_raises=True)
    force_close_process(_R2(proc))  # must not raise

    assert not proc.killed
