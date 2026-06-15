"""Shared helper for extracting valid functions from an r2-backed analyzer."""

from __future__ import annotations

import logging
from typing import Any, Protocol


class FunctionExtractionHost(Protocol):
    """Capabilities a host must expose to collect functions via radare2."""

    adapter: Any

    def _cmd_list(self, command: str) -> list[Any]: ...


def collect_valid_functions(
    host: FunctionExtractionHost,
    logger: logging.Logger,
    *,
    run_analyze_all: bool = False,
    clean_names: bool = False,
) -> list[dict[str, Any]]:
    """Return functions from ``aflj`` that have a real address and non-zero size.

    ``run_analyze_all`` triggers a full analysis pass first when the adapter
    supports it; ``clean_names`` HTML-unescapes each function name in place.
    """
    if run_analyze_all and host.adapter is not None and hasattr(host.adapter, "analyze_all"):
        host.adapter.analyze_all()
    functions = host._cmd_list("aflj")
    if not functions:
        logger.debug("No functions found with 'aflj' command")
        return []
    valid_functions = []
    for func in functions:
        if func.get("addr") is not None and func.get("size", 0) > 0:
            if clean_names and func.get("name"):
                func["name"] = func["name"].replace("&nbsp;", " ").replace("&amp;", "&")
            valid_functions.append(func)
    logger.debug("Extracted %s valid functions", len(valid_functions))
    return valid_functions
