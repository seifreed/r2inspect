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
    # gc done: signal successful recovery. Raising here would only be
    # swallowed by ErrorRecoveryManager.handle_error's except clause,
    # silently turning every memory recovery into a failure.
    return None


def r2pipe_recovery(error_info: Any) -> Any | None:
    return None if error_info.context.get("command", "").endswith("j") else ""


def file_access_recovery(error_info: Any, logger: Any) -> Any | None:
    logger.warning("File access error: %s", error_info.suggested_action)
    return None
