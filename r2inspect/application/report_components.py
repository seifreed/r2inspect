"""Findings, outcomes, and optional engine data for report/v1."""

from __future__ import annotations

from typing import Any

from ..schemas.report_v1 import FindingV1
from ..schemas.results_models import AnalysisResult
from .report_analyzers import analyzer_outcomes


def findings(result: AnalysisResult) -> list[FindingV1]:
    raw = result.to_dict()
    native_payloads: list[dict[str, Any]] = []
    for key in ("packer", "anti_analysis", "import_analysis"):
        payload = raw.get(key)
        values = payload.get("findings") if isinstance(payload, dict) else None
        if isinstance(values, list):
            native_payloads.extend(item for item in values if isinstance(item, dict))
    yara_matches = raw.get("yara_matches", raw.get("yara", []))
    if isinstance(yara_matches, list):
        native_payloads.extend(
            finding
            for match in yara_matches
            if isinstance(match, dict) and isinstance((finding := match.get("finding")), dict)
        )
    output = [FindingV1.model_validate(payload) for payload in native_payloads]
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
