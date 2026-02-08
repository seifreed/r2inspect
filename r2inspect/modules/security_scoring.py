#!/usr/bin/env python3
"""Security scoring helpers."""

from __future__ import annotations

from typing import Any

from .domain_helpers import clamp_score

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
    score = 0
    max_score = 0

    for mitigation_name, scoring in MITIGATION_SCORES.items():
        mitigation = result["mitigations"].get(mitigation_name, {})
        for check, points in scoring.items():
            max_score += points
            if mitigation.get(check):
                score += points

    for vuln in result.get("vulnerabilities", []):
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
