"""Run a callable in a daemon thread with a hard wall-clock timeout."""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any


def run_with_timeout(
    fn: Callable[[], Any], timeout: float
) -> tuple[bool, Any, BaseException | None]:
    """Execute ``fn`` in a daemon thread, joining for at most ``timeout`` seconds.

    Returns ``(completed, value, error)``: ``completed`` is False when the worker
    is still running after the join (the caller decides how to signal the
    timeout); otherwise ``value`` holds ``fn``'s return and ``error`` holds any
    exception it raised. The worker is a daemon thread so an abandoned call
    cannot keep the process alive.
    """
    result_holder: dict[str, Any] = {"value": None, "error": None}

    def _runner() -> None:
        try:
            result_holder["value"] = fn()
        except Exception as exc:
            result_holder["error"] = exc

    worker = threading.Thread(target=_runner, daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        return False, None, None
    return True, result_holder["value"], result_holder["error"]
