"""Function-local correlation of imported API behavior."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..findings import native_finding, parse_address

_CLUSTERS = (
    (
        "process_network",
        {"createprocessa", "createprocessw", "openprocess", "createprocessexa"},
        {"socket", "connect", "wsastartup", "internetopena", "internetconnecta"},
        "Correlated process creation and network communication",
    ),
    (
        "mapping_file",
        {"mapviewoffile", "mapviewoffileex", "openfilemappinga", "createfilemappinga"},
        {"createfilea", "createfilew", "movefilea", "deletefilea"},
        "Correlated file mapping and file-system access",
    ),
)
_CLUSTER_APIS = set().union(*(left | right for _, left, right, _ in _CLUSTERS))


def _function_for(address: int, functions: list[dict[str, Any]]) -> tuple[int, str] | None:
    for function in functions:
        start = parse_address(function.get("offset", function.get("addr")))
        size = function.get("size", 0)
        if start is not None and isinstance(size, int) and start <= address < start + max(size, 1):
            return start, str(function.get("name") or hex(start))
    return None


def _collect_calls(
    imports: list[dict[str, Any]],
    functions: list[dict[str, Any]],
    xrefs_for: Callable[[int], list[dict[str, Any]]],
) -> dict[tuple[int, str], list[tuple[str, int]]]:
    calls: dict[tuple[int, str], list[tuple[str, int]]] = {}
    for item in imports:
        name = str(item.get("name") or "").casefold()
        target = parse_address(item.get("address", item.get("plt")))
        if target is None or not any(name.endswith(api) for api in _CLUSTER_APIS):
            continue
        for xref in xrefs_for(target):
            call_site = parse_address(xref.get("from", xref.get("addr")))
            if (
                call_site is not None
                and (function := _function_for(call_site, functions)) is not None
            ):
                calls.setdefault(function, []).append((name, call_site))
    return calls


def _matching_calls(api_calls: list[tuple[str, int]], group: set[str]) -> list[tuple[str, int]]:
    return [(api, address) for name, address in api_calls for api in group if name.endswith(api)]


def behavior_findings(
    imports: list[dict[str, Any]],
    functions: list[dict[str, Any]],
    xrefs_for: Callable[[int], list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    calls = _collect_calls(imports, functions, xrefs_for)
    findings: list[dict[str, Any]] = []
    for cluster_id, left, right, title in _CLUSTERS:
        for (function_address, function_name), api_calls in calls.items():
            left_calls = _matching_calls(api_calls, left)
            right_calls = _matching_calls(api_calls, right)
            if not left_calls or not right_calls:
                continue
            call_sites = sorted({address for _, address in left_calls + right_calls})
            evidence = [
                {
                    "kind": "function_local_api_calls",
                    "value": {
                        "function": function_name,
                        "left_apis": sorted({name for name, _ in left_calls}),
                        "right_apis": sorted({name for name, _ in right_calls}),
                        "call_sites": [hex(address) for address in call_sites],
                    },
                    "description": "Both API groups are referenced by the same function",
                }
            ]
            findings.append(
                native_finding(
                    rule_id=f"r2inspect.behavior.{cluster_id}.v1",
                    title=title,
                    category="behavior",
                    severity="medium",
                    confidence=0.85,
                    source_analyzer="import_analyzer",
                    method="function_local_xrefs",
                    evidence=evidence,
                    locations=[
                        {"virtual_address": address, "function": function_name}
                        for address in call_sites
                    ]
                    or [{"virtual_address": function_address, "function": function_name}],
                )
            )
    return findings


__all__ = ["behavior_findings"]
