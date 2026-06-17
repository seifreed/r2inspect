"""Process reaping helper shared by the conftest r2 sweep and its tests."""

from __future__ import annotations

from typing import Any


def reap_process(proc: Any, *, timeout: float = 2.0) -> None:
    """Terminate ``proc`` and escalate to SIGKILL if SIGTERM does not land.

    A radare2 wedged in a CPU-bound, uninterruptible loop (e.g. the telfhash
    hang) ignores SIGTERM and would keep burning a core orphaned for the rest
    of the session. ``terminate()`` then ``wait`` then ``kill()`` matches the
    production escalation in ``force_close_process`` / batch shutdown.
    """
    import psutil

    try:
        proc.terminate()
        try:
            proc.wait(timeout=timeout)
        except psutil.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=timeout)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
        pass
