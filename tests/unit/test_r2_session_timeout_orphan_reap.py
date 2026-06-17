#!/usr/bin/env python3
"""An r2 instance that finishes opening after a timeout must be fully reaped.

Regression guard: open_with_timeout previously only called ``quit()`` on an
orphaned r2 (one that finished spawning after we already raised TimeoutError),
leaking its stdio pipes and leaving the radare2 process unreaped — a FD + zombie
leak per timed-out open. Reaping is deterministically verified via threading
events (no sleeps).
"""

from __future__ import annotations

import logging
import threading

import pytest

from r2inspect.infrastructure.r2_session import R2Session
from r2inspect.infrastructure.r2_session_timeouts import _close_orphan_r2, open_with_timeout


class _Stream:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _Process:
    def __init__(self, reaped: threading.Event) -> None:
        self.stdin = _Stream()
        self.stdout = _Stream()
        self.stderr = _Stream()
        self._poll: int | None = None
        self.terminated = False
        self._reaped = reaped

    def poll(self) -> int | None:
        return self._poll

    def terminate(self) -> None:
        self.terminated = True
        self._poll = 0

    def wait(self, timeout: float | None = None) -> None:
        self._reaped.set()


class _R2:
    def __init__(self, reaped: threading.Event) -> None:
        self.process = _Process(reaped)
        self.quit_called = False

    def quit(self) -> None:
        self.quit_called = True


def test_orphan_completing_after_timeout_is_quit_and_reaped():
    release = threading.Event()
    reaped = threading.Event()
    r2 = _R2(reaped)

    def _blocking_opener(_filename: str, flags=None):
        release.wait(2.0)  # stay "opening" until the test has timed out
        return r2

    session = R2Session("sample", opener=_blocking_opener)

    with pytest.raises(TimeoutError):
        open_with_timeout(session, ["-2"], 0.01, logger=logging.getLogger("test"))

    release.set()  # now let the orphan open() return inside the worker thread
    assert reaped.wait(2.0), "worker never reaped the orphaned r2 process"
    assert r2.quit_called
    assert r2.process.terminated
    assert r2.process.stdin.closed
    assert r2.process.stdout.closed
    assert r2.process.stderr.closed


def test_close_orphan_swallows_quit_failure():
    reaped = threading.Event()

    class _QuitRaises(_R2):
        def quit(self) -> None:
            raise OSError("quit failed")

    r2 = _QuitRaises(reaped)
    _close_orphan_r2(r2, logging.getLogger("test"))  # must not raise

    assert reaped.is_set()
    assert r2.process.terminated
