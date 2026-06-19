#!/usr/bin/env python3
"""Security scoring helpers."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ..domain.services.binary_helpers import clamp_score

MITIGATION_SCORES = {
    "ASLR": {"enabled": 15, "high_entropy": 5},
    "DEP": {"enabled": 15},
    "CFG": {"enabled": 15},
    "RFG": {"enabled": 10},
    "SafeSEH": {"enabled": 10},
    "Stack_Cookies": {"enabled": 15},
    "Authenticode": {"enabled": 10},
    "Force_Integrity": {"enabled": 5},
    "AppContainer": {"enabled": 5},
}


def build_security_score(result: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(result, dict):
        return {"score": 0, "max_score": 0, "percentage": 0.0, "grade": "Unknown"}
    score = 0
    max_score = 0
    mitigations = result.get("mitigations")
    if not isinstance(mitigations, dict):
        mitigations = {}
    vulnerabilities = result.get("vulnerabilities")
    if isinstance(vulnerabilities, list):
        pass
    elif isinstance(vulnerabilities, (dict, str, bytes)) or not isinstance(vulnerabilities, Iterable):
        vulnerabilities = []
    else:
        vulnerabilities = list(vulnerabilities)

    for mitigation_name, scoring in MITIGATION_SCORES.items():
        mitigation = mitigations.get(mitigation_name, {})
        if not isinstance(mitigation, dict):
            mitigation = {}
        for check, points in scoring.items():
            max_score += points
            if mitigation.get(check):
                score += points

    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        if vuln.get("severity") == "high":
            score -= 10
        elif vuln.get("severity") == "medium":
            score -= 5

    score = clamp_score(score, minimum=0, maximum=max_score if max_score > 0 else 0)
    percentage = round((score / max_score * 100) if max_score > 0 else 0, 1)

    return {
        "score": score,
        "max_score": max_score,
        "percentage": percentage,
        "grade": _grade_from_percentage(percentage, max_score),
    }


def _grade_from_percentage(percentage: float, max_score: int) -> str:
    try:
        percentage = float(percentage)
        max_score = int(max_score)
    except (TypeError, ValueError):
        return "Unknown"
    if max_score == 0:
        return "Unknown"
    if percentage >= 90:
        return "A"
    if percentage >= 80:
        return "B"
    if percentage >= 70:
        return "C"
    if percentage >= 60:
        return "D"
    return "F"
