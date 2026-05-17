"""Runtime helpers for SSDeep hashing and comparison."""

from __future__ import annotations

from typing import Any, cast


def compare_with_library(hash1: str, hash2: str, get_ssdeep_fn: Any, logger: Any) -> int | None:
    ssdeep_module = get_ssdeep_fn()
    if ssdeep_module is None:
        return None
    try:
        return cast(int, ssdeep_module.compare(hash1, hash2))
    except Exception as exc:
        logger.warning("SSDeep comparison failed with library: %s", exc)
        return None


def is_available(get_ssdeep_fn: Any) -> bool:
    return get_ssdeep_fn() is not None
