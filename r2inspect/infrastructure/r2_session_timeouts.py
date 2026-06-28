#!/usr/bin/env python3
"""Timeout and command helpers for r2 sessions."""

from __future__ import annotations

import os
import threading
import time
from typing import Any

from .r2_session_cleanup import force_close_process
from .timeout_runner import run_with_timeout


def _close_orphan_r2(r2: Any, logger: Any) -> None:
    """Fully tear down an r2 spawned after we already gave up on the open.

    ``quit()`` alone leaves the stdio pipes open and the process unreaped — a
    leaked FD plus a zombie radare2 per timed-out open. Mirror the normal
    close path: quit, then close the pipes and reap the process.
    """
    try:
        r2.quit()
    except Exception as exc:
        logger.debug("Failed to quit orphaned r2 instance: %s", exc)
    force_close_process(r2)


def open_with_timeout(session: Any, flags: list[str], timeout: float, *, logger: Any) -> Any:
    result_holder: dict[str, Any] = {"r2": None, "error": None}
    timed_out = threading.Event()

    def _runner() -> None:
        try:
            r2 = session._opener(session.filename, flags=flags)
            # If we timed out while opening, close the orphan immediately
            if timed_out.is_set():
                _close_orphan_r2(r2, logger)
            else:
                result_holder["r2"] = r2
        except Exception as exc:
            result_holder["error"] = exc

    worker = threading.Thread(target=_runner, daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        timed_out.set()
        # Attempt to clean up any orphaned r2 process spawned by the thread
        try:
            from .r2_session_cleanup import terminate_radare2_processes

            terminate_radare2_processes(session.filename)
        except Exception as exc:
            logger.debug("Failed to terminate orphaned radare2 processes: %s", exc)
        raise TimeoutError(f"r2pipe.open() timed out after {timeout:.3f}s")
    if result_holder["error"] is not None:
        raise result_holder["error"]
    session.r2 = result_holder["r2"]
    return session.r2


def _is_forced_timeout(command: str) -> bool:
    forced = os.environ.get("R2INSPECT_FORCE_CMD_TIMEOUT")
    if forced is None:
        return False
    forced_commands = {item.strip() for item in forced.split(",")}
    return (not any(forced_commands)) or command in forced_commands


def run_cmd_with_timeout(session: Any, command: str, timeout: float, *, logger: Any) -> bool:
    if session.r2 is None:
        return False
    if _is_forced_timeout(command):
        logger.warning("Forcing r2 command timeout: %s", command)
        return False

    try:
        completed, result, error = run_with_timeout(lambda: session.r2.cmd(command), timeout)
        if not completed:
            logger.warning("r2 command timed out after %.1fs: %s", timeout, command)
            return False
        if error is not None:
            raise error
        return bool(result or result == "")
    except Exception as exc:
        logger.warning("r2 command failed (%s): %s", command, exc)
        return False


def run_basic_info_check(session: Any, *, logger: Any, min_info_response_length: int) -> bool:
    if session.r2 is None:
        raise RuntimeError("r2pipe session not initialized")
    if not session._run_cmd_with_timeout("i", session._get_cmd_timeout()):
        return False
    result = session.r2.cmd("i")
    if len(result or "") < min_info_response_length:
        logger.warning("r2 basic info command returned minimal data for %s", session.filename)
    return True


def perform_initial_analysis(session: Any, file_size_mb: float, *, logger: Any) -> bool:
    try:
        if session.r2 is None:
            return True
        analysis_depth = os.environ.get("R2INSPECT_ANALYSIS_DEPTH", "").strip()
        if analysis_depth == "0":
            return True

        if file_size_mb > session._get_huge_file_threshold():
            # Always-complete policy: run basic analysis even on huge binaries so
            # function discovery works, with a generous timeout. aa is linear and
            # fast (~0.08s/MB); only aaa is the multi-minute command, so aa is used
            # here to keep huge binaries tractable while still finding functions.
            return bool(session._run_cmd_with_timeout("aa", session._get_huge_analysis_timeout()))

        if session._is_test_mode or file_size_mb > session._get_large_file_threshold():
            return bool(session._run_cmd_with_timeout("aa", session._get_analysis_timeout()))

        return bool(
            session._run_cmd_with_timeout("aaa", session._get_analysis_timeout(full_analysis=True))
        )
    except Exception as exc:
        logger.warning("Analysis command failed, continuing with basic r2 setup: %s", exc)
        return True


__all__ = [
    "time",
]
