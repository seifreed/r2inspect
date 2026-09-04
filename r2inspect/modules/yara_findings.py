"""Native finding projection for parsed YARA matches."""

from __future__ import annotations

import math
from typing import Any

from ..domain.findings import finding_slug, native_finding


def _terms(value: Any) -> list[str]:
    if isinstance(value, str):
        return [item for item in value.replace(",", " ").split() if item]
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item]
    return []


def _confidence(value: Any) -> float:
    try:
        confidence = float(value) if not isinstance(value, bool) else 0.8
    except (TypeError, ValueError):
        return 0.8
    if not math.isfinite(confidence):
        return 0.8
    return min(max(confidence / 100 if confidence > 1 else confidence, 0.0), 1.0)


def match_finding(match: dict[str, Any]) -> dict[str, Any]:
    raw_meta = match.get("meta")
    meta: dict[str, Any] = raw_meta if isinstance(raw_meta, dict) else {}
    raw_severity = {"info": "informational", "warning": "medium"}.get(
        str(meta.get("severity", "medium")).casefold(),
        str(meta.get("severity", "medium")).casefold(),
    )
    severity = (
        raw_severity
        if raw_severity in {"informational", "low", "medium", "high", "critical"}
        else "medium"
    )
    confidence = _confidence(meta.get("confidence", 0.8))
    rule = str(match.get("rule") or "unknown")
    namespace = str(match.get("namespace") or "default")
    raw_strings = match.get("strings")
    strings: list[Any] = raw_strings if isinstance(raw_strings, list) else []
    offsets = {
        instance["offset"]
        for string_match in strings
        if isinstance(string_match, dict) and isinstance(string_match.get("instances"), list)
        for instance in string_match["instances"]
        if isinstance(instance, dict)
        and isinstance(instance.get("offset"), int)
        and not isinstance(instance["offset"], bool)
        and instance["offset"] >= 0
    }
    return native_finding(
        rule_id=f"r2inspect.yara.{finding_slug(namespace)}.{finding_slug(rule)}.v1",
        title=str(meta.get("description") or f"YARA rule matched: {rule}"),
        category=str(meta.get("category") or "yara"),
        severity=severity,
        confidence=confidence,
        source_analyzer="yara_analyzer",
        method="yara_pattern",
        evidence=[
            {
                "kind": "yara_match",
                "value": {
                    "rule": rule,
                    "namespace": namespace,
                    "tags": match.get("tags", []),
                    "strings": strings,
                },
                "description": "Matched YARA strings and metadata",
            }
        ],
        locations=[{"offset": offset} for offset in sorted(offsets)],
        attack=_terms(meta.get("attack", meta.get("mitre_attack"))),
        mbc=_terms(meta.get("mbc")),
    )


__all__ = ["match_finding"]
