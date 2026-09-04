"""Unit coverage for the extracted parallel-runtime round helpers."""

from __future__ import annotations

import threading
from concurrent.futures import Future
from typing import Any

from r2inspect.pipeline.pipeline_parallel_runtime import (
    _retire_skipped_stages,
    _stalled_round_should_break,
    apply_skipped_stages,
    collect_futures,
    execute_stage_with_timeout,
    get_effective_workers,
)
from r2inspect.pipeline.stage_models import ThreadSafeContext
from tests.helpers import env_vars


class _Stage:
    def __init__(self, name: str) -> None:
        self.name = name


def test_stalled_round_does_not_break_when_ready_stages_exist() -> None:
    assert (
        _stalled_round_should_break([_Stage("a")], [_Stage("a")], threading.Lock(), [], set(), None)
        is False
    )


def test_stalled_round_breaks_when_nothing_remaining() -> None:
    assert _stalled_round_should_break([], [], threading.Lock(), [], set(), None) is True


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


def test_parallel_helpers_cover_skips_and_execution_failures() -> None:
    with env_vars(R2INSPECT_MAX_WORKERS=None):
        assert get_effective_workers(3) == 3

    stage_a = _Stage("a")
    stage_b = _Stage("b")
    remaining: list[Any] = [stage_a, stage_b]
    completed: set[str] = set()
    assert apply_skipped_stages([stage_a], remaining, completed, threading.Lock()) == 1
    assert (
        apply_skipped_stages([stage_b], remaining, completed, threading.Lock(), threading.Lock())
        == 1
    )
    assert completed == {"a", "b"}

    failed_future: Future[tuple[dict[str, Any], bool]] = Future()
    failed_future.set_exception(RuntimeError("future failed"))
    remaining = [stage_a]
    failed: set[str] = set()
    context = ThreadSafeContext({"results": {}})
    assert collect_futures(
        {failed_future: stage_a},
        context,
        remaining,
        completed,
        failed,
        threading.Lock(),
        threading.Lock(),
    ) == {"executed": 0, "failed": 1}
    assert failed == {"a"}
    assert context.get_all()["results"]["a"]["error"] == "future failed"

    class RaisingStage(_Stage):
        timeout = None

        def execute(self, _context):
            raise RuntimeError("stage failed")

    result, success = execute_stage_with_timeout(RaisingStage("raising"), context)
    assert not success
    assert result["raising"]["error"] == "stage failed"
