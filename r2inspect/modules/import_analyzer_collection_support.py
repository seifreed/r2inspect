"""Collection and normalization helpers for import analysis.

Pure functions are re-exported from domain.analysis.import_collection.
Infrastructure-dependent functions remain here.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..domain.analysis.import_collection import (
    normalize_import_entries,
    safe_len,
)


__all__ = [
    "safe_len",
    "normalize_import_entries",
    "collect_imports",
]


def collect_imports(
    *,
    cmdj: Callable[[str, Any], Any],
    analyze_import_fn: Callable[[dict[str, Any]], dict[str, Any]],
    logger: Any,
) -> list[dict[str, Any]]:
    imports_info: list[dict[str, Any]] = []

    try:
        imports = normalize_import_entries(cmdj("iij", []))

        if imports:
            for imp in imports:
                imports_info.append(analyze_import_fn(imp))
        else:
            logger.debug("No valid import entries returned by iij")

    except Exception as exc:
        logger.error("Error getting imports via iij: %s", exc)

    return imports_info
