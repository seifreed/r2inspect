#!/usr/bin/env python3
"""Timeout and command helpers for r2 sessions."""

from __future__ import annotations

import os
import threading
import time
from typing import Any

import r2pipe


def open_with_timeout(session: Any, flags: list[str], timeout: float, *, logger: Any) -> Any:
    result_holder: dict[str, Any] = {"r2": None, "error": None}
    timed_out = threading.Event()

    def _runner() -> None:
        try:
            r2 = r2pipe.open(session.filename, flags=flags)
            # If we timed out while opening, close the orphan immediately
            if timed_out.is_set():
                try:
                    r2.quit()
                except Exception as exc:
                    logger.debug("Failed to quit orphaned r2 instance: %s", exc)
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


def run_cmd_with_timeout(session: Any, command: str, timeout: float, *, logger: Any) -> bool:
    if session.r2 is None:
        return False
    forced = os.environ.get("R2INSPECT_FORCE_CMD_TIMEOUT")
    forced_commands = {item.strip() for item in forced.split(",")} if forced is not None else set()
    if forced is not None and ((not any(forced_commands)) or command in forced_commands):
        logger.warning("Forcing r2 command timeout: %s", command)
        return False

    result_holder: dict[str, Any] = {"ok": False, "error": None}

    def _runner() -> None:
        try:
            result = session.r2.cmd(command)
            result_holder["ok"] = bool(result or result == "")
        except Exception as exc:
            result_holder["error"] = exc

    try:
        worker = threading.Thread(target=_runner, daemon=True)
        worker.start()
        worker.join(timeout)
        if worker.is_alive():
            logger.warning("r2 command timed out after %.1fs: %s", timeout, command)
            return False
        if result_holder["error"] is not None:
            raise result_holder["error"]
        return bool(result_holder["ok"])
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

        if file_size_mb >= session._get_huge_file_threshold():
            return True

        if session._is_test_mode or file_size_mb >= session._get_large_file_threshold():
            return bool(session._run_cmd_with_timeout("aa", session._get_analysis_timeout()))

        return bool(
            session._run_cmd_with_timeout("aaa", session._get_analysis_timeout(full_analysis=True))
        )
    except Exception as exc:
        logger.warning("Analysis command failed, continuing with basic r2 setup: %s", exc)
        return True
