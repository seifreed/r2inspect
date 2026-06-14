"""Unit coverage for the extracted parallel-runtime round helpers."""

from __future__ import annotations

import threading
from typing import Any

from r2inspect.pipeline.pipeline_parallel_runtime import (
    _retire_skipped_stages,
    _stalled_round_should_break,
)


class _Stage:
    def __init__(self, name: str) -> None:
        self.name = name


def test_stalled_round_does_not_break_when_ready_stages_exist() -> None:
    assert (
        _stalled_round_should_break(
            [_Stage("a")], [_Stage("a")], threading.Lock(), [], set(), None
        )
        is False
    )


def test_stalled_round_breaks_when_nothing_remaining() -> None:
    assert (
        _stalled_round_should_break([], [], threading.Lock(), [], set(), None)
        is True
    )


def test_retire_skipped_stages_removes_and_marks_completed() -> None:
    stage_a = _Stage("a")
    stage_b = _Stage("b")
    remaining: list[Any] = [stage_a, stage_b]
    completed: set[str] = set()

    count = _retire_skipped_stages(
        [stage_a], remaining, completed, threading.Lock(), threading.Lock()
    )

    assert count == 1
    assert remaining == [stage_b]
    assert completed == {"a"}
