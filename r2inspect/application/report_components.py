"""Findings, outcomes, and optional engine data for report/v1."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Literal, cast

from ..schemas.report_v1 import AnalyzerOutcomeV1, AnalyzerStatus, EvidenceV1, FindingV1
from ..schemas.results_models import AnalysisResult
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


def _status(value: dict[str, Any]) -> AnalyzerStatus:
    error = value.get("error")
    text = str(error).lower() if error else ""
    if error:
        if "timed out" in text or "timeout" in text:
            return AnalyzerStatus.TIMED_OUT
        if "unsupported" in text:
            return AnalyzerStatus.UNSUPPORTED
        if value.get("library_available") is False or "dependency" in text:
            return AnalyzerStatus.DEPENDENCY_UNAVAILABLE
        return AnalyzerStatus.FAILED
    if value.get("available") is False:
        return AnalyzerStatus.DEPENDENCY_UNAVAILABLE
    return (
        AnalyzerStatus.NOT_DETECTED if value.get("detected") is False else AnalyzerStatus.COMPLETED
    )


def analyzer_outcomes(raw: dict[str, Any]) -> list[AnalyzerOutcomeV1]:
    outcomes = []
    for analyzer_id, value in sorted(raw.items()):
        if not isinstance(value, dict) or not {"available", "error", "execution_time"}.intersection(
            value
        ):
            continue
        duration = value.get("execution_time", 0.0)
        error = value.get("error")
        outcomes.append(
            AnalyzerOutcomeV1(
                analyzer_id=analyzer_id,
                status=_status(value),
                duration=float(duration) if isinstance(duration, (int, float)) else 0.0,
                error=str(error) if error else None,
            )
        )
    return outcomes


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
    return [
        {"source": "floss", "type": str(kind), "value": value}
        for kind, values in strings.items()
        if isinstance(values, list)
        for value in values
    ]
