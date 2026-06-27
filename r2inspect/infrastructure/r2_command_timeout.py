"""Timeout-guarded r2 command execution with wedged-pipe tracking."""

from __future__ import annotations

import contextlib
import os
import threading
import weakref
from typing import Any

from ..domain.constants import SUBPROCESS_TIMEOUT_SECONDS
from ..interfaces import R2CommandInterface
from .logging import get_logger

logger = get_logger(__name__)

# A synchronous r2pipe that does not answer within the timeout is desynchronized:
# the abandoned worker thread stays blocked in cmd() forever, and every later
# command on the same pipe hangs the same way. Track wedged instances so we
# fast-fail their subsequent commands instead of leaking one daemon thread per
# call -- unbounded leakage exhausted the process thread limit on large batches
# and in CI ("RuntimeError: can't start new thread").
_wedged_lock = threading.Lock()
_wedged_instances: weakref.WeakSet[Any] = weakref.WeakSet()


def is_wedged(r2_instance: Any) -> bool:
    with _wedged_lock:
        try:
            return r2_instance in _wedged_instances
        except TypeError:
            return False


def mark_wedged(r2_instance: Any) -> None:
    with _wedged_lock, contextlib.suppress(TypeError):
        _wedged_instances.add(r2_instance)


def _run_cmd_with_timeout(
    r2_instance: R2CommandInterface, command: str, default: Any | None
) -> Any | None:
    if is_wedged(r2_instance):
        return default

    result: dict[str, Any] = {"value": default, "done": False}

    def _run() -> None:
        try:
            result["value"] = r2_instance.cmd(command)
        except Exception as exc:
            logger.debug("r2 cmd failed for %s: %s", command, exc)
            result["value"] = default
        finally:
            result["done"] = True

    timeout_seconds: float = float(SUBPROCESS_TIMEOUT_SECONDS)
    env_timeout = os.environ.get("R2INSPECT_CMD_TIMEOUT_SECONDS")
    if env_timeout:
        try:
            timeout_seconds = float(env_timeout)
        except ValueError:
            timeout_seconds = SUBPROCESS_TIMEOUT_SECONDS

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    thread.join(timeout=timeout_seconds)

    if not result["done"]:
        logger.warning("r2 command timed out: %s", command)
        mark_wedged(r2_instance)
        return default

    return result["value"]
