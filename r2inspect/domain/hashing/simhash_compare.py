"""Pure domain logic for SimHash comparison.

This module contains pure functions for SimHash distance calculation
with no infrastructure dependencies (stdlib only).
"""

from __future__ import annotations

from typing import Any, cast


def compare_hashes(
    *,
    simhash_available: bool,
    simhash_class: Any,
    hash1: str | int | None,
    hash2: str | int | None,
    logger: Any,
) -> int | None:
    """Compare two SimHash values and return the distance.

    Args:
        simhash_available: Whether SimHash library is available
        simhash_class: The SimHash class to use for comparison
        hash1: First hash value (hex string or int)
        hash2: Second hash value (hex string or int)
        logger: Logger for error reporting

    Returns:
        Distance between hashes, or None if comparison not possible
    """
    if not simhash_available:
        return None

    if hash1 is None or hash2 is None:
        return None

    try:
        hash1_int = int(hash1, 16) if isinstance(hash1, str) else hash1
        hash2_int = int(hash2, 16) if isinstance(hash2, str) else hash2

        simhash1 = simhash_class(hash1_int)
        simhash2 = simhash_class(hash2_int)
        return cast(int, simhash1.distance(simhash2))
    except Exception as exc:
        logger.warning("SimHash comparison failed: %s", exc)
        return None


__all__ = ["compare_hashes"]
