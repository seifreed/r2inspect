#!/usr/bin/env python3
"""Default recovery strategies for the error classifier."""

from __future__ import annotations

from typing import Any


def memory_recovery(logger: Any) -> Any | None:
    import gc

    collected = 0
    for _ in range(3):
        collected += gc.collect()
    logger.info("Performed aggressive garbage collection, freed %d objects", collected)
    # Raise to signal that the original operation was NOT recovered —
    # callers must retry explicitly rather than accepting None as success.
    raise MemoryError("Memory recovery attempted; caller should retry the operation")


def r2pipe_recovery(error_info: Any) -> Any | None:
    return None if error_info.context.get("command", "").endswith("j") else ""


def file_access_recovery(error_info: Any, logger: Any) -> Any | None:
    logger.warning("File access error: %s", error_info.suggested_action)
    return None
