#!/usr/bin/env python3
"""Forced batch exit must reap child radare2 processes.

Regression guard: schedule_forced_exit / ensure_batch_shutdown call os._exit,
which skips all cleanup. Any radare2 still held by a lingering daemon worker
(a timed-out r2 command/open) would be orphaned. _terminate_child_processes
must terminate, then kill survivors. Hand-rolled doubles only (no mocks).
"""

from __future__ import annotations

from typing import Any

from r2inspect.cli.batch_runtime import _terminate_child_processes


class _Child:
    def __init__(self, *, terminate_raises: bool = False, kill_raises: bool = False) -> None:
        self.terminated = False
        self.killed = False
        self._terminate_raises = terminate_raises
        self._kill_raises = kill_raises

    def terminate(self) -> None:
        if self._terminate_raises:
            raise OSError("terminate failed")
        self.terminated = True

    def kill(self) -> None:
        if self._kill_raises:
            raise OSError("kill failed")
        self.killed = True


class _Proc:
    def __init__(self, children: list[_Child]) -> None:
        self._children = children

    def children(self, recursive: bool = False) -> list[_Child]:
        return self._children


def test_terminates_then_kills_survivors():
    survivor = _Child()
    gone = _Child()
    proc = _Proc([survivor, gone])

    _terminate_child_processes(
        current_process=proc,
        wait_procs=lambda children, timeout: ([gone], [survivor]),
    )

    assert survivor.terminated and gone.terminated
    assert survivor.killed  # survived terminate, so killed
    assert not gone.killed  # already gone


def test_no_children_is_noop():
    proc = _Proc([])
    _terminate_child_processes(
        current_process=proc, wait_procs=lambda children, timeout: ([], [])
    )  # must not raise


def test_enumerate_failure_is_swallowed():
    class _Boom:
        def children(self, recursive: bool = False) -> list[_Child]:
            raise OSError("enumerate failed")

    _terminate_child_processes(current_process=_Boom())  # must not raise


def test_terminate_failure_is_swallowed():
    bad = _Child(terminate_raises=True)
    proc = _Proc([bad])
    _terminate_child_processes(
        current_process=proc, wait_procs=lambda children, timeout: ([], [bad])
    )
    assert bad.killed  # still killed despite terminate failure


def test_wait_failure_is_swallowed():
    child = _Child()
    proc = _Proc([child])

    def _boom_wait(children: Any, timeout: float) -> Any:
        raise RuntimeError("wait failed")

    _terminate_child_processes(current_process=proc, wait_procs=_boom_wait)
    assert child.terminated and not child.killed  # returned before kill phase


def test_kill_failure_is_swallowed():
    survivor = _Child(kill_raises=True)
    proc = _Proc([survivor])
    _terminate_child_processes(
        current_process=proc, wait_procs=lambda children, timeout: ([], [survivor])
    )  # must not raise
    assert survivor.terminated
