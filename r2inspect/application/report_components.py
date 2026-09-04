"""Findings, outcomes, and optional engine data for report/v1."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Literal, cast

from ..schemas.report_v1 import EvidenceV1, FindingV1
from ..schemas.results_models import AnalysisResult
from .report_analyzers import analyzer_outcomes
from .technique_mappings import map_techniques


def findings(result: AnalysisResult) -> list[FindingV1]:
    output: list[FindingV1] = []
    aliases = {"info": "informational", "warning": "medium"}
    valid = {"informational", "low", "medium", "high", "critical"}
    for indicator in result.indicators:
        severity = aliases.get(indicator.severity.lower(), indicator.severity.lower())
        severity = severity if severity in valid else "informational"
        slug = re.sub(r"[^a-z0-9]+", ".", indicator.type.lower()).strip(".") or "unknown"
        rule_id = f"legacy.indicator.{slug}"
        digest = hashlib.sha256(f"{rule_id}\0{indicator.description}".encode()).hexdigest()[:16]
        attack, mbc = map_techniques(indicator.type, rule_id)
        output.append(
            FindingV1(
                finding_id=f"finding-{digest}",
                rule_id=rule_id,
                title=indicator.description or indicator.type or "Security indicator",
                category=indicator.type or "security",
                severity=cast(
                    Literal["informational", "low", "medium", "high", "critical"], severity
                ),
                confidence=0.5,
                source_analyzer="result_aggregator",
                method="legacy_indicator",
                evidence=[EvidenceV1(kind="description", value=indicator.description)],
                attack=attack,
                mbc=mbc,
            )
        )
    return output


def capa_capabilities(raw: dict[str, Any]) -> list[dict[str, Any]]:
    capa = raw.get("capa")
    payload = capa.get("result") if isinstance(capa, dict) else None
    rules = payload.get("rules") if isinstance(payload, dict) else None
    if not isinstance(rules, dict):
        return []
    return [
        {"source": "capa", "name": name, "details": details}
        for name, details in sorted(rules.items())
    ]


def floss_artifacts(raw: dict[str, Any]) -> list[dict[str, Any]]:
    floss = raw.get("floss")
    payload = floss.get("result") if isinstance(floss, dict) else None
    strings = payload.get("strings") if isinstance(payload, dict) else None
    if not isinstance(strings, dict):
        return []
    artifacts: list[dict[str, Any]] = []
    for kind, values in strings.items():
        if not isinstance(values, list):
            continue
        for value in values:
            if isinstance(value, dict):
                value = value.get("string")
            if isinstance(value, str):
                artifacts.append({"source": "floss", "type": str(kind), "value": value})
    return artifacts


__all__ = ["analyzer_outcomes", "capa_capabilities", "findings", "floss_artifacts"]
