"""Adapter bridge for function-local import behavior findings."""

from __future__ import annotations

from typing import Any, cast

from ..domain.services.behavior_analysis import behavior_findings


def collect_behavior_findings(analyzer: Any, imports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    functions = analyzer._safe_call(
        lambda: analyzer._coerce_dict_list(analyzer._get_via_adapter("get_functions", "aflj")),
        [],
        "Error collecting functions for behavior correlation",
    )
    return cast(
        list[dict[str, Any]],
        analyzer._safe_call(
            lambda: behavior_findings(
                imports,
                functions,
                lambda address: analyzer._coerce_dict_list(analyzer._cmdj(f"axtj @ {address}", [])),
            ),
            [],
            "Error correlating imported API behavior",
        ),
    )


__all__ = ["collect_behavior_findings"]
