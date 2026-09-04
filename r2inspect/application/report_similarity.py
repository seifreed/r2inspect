"""Similarity hash extraction for report/v1."""

from __future__ import annotations

import importlib
from typing import Any

from ..schemas.report_v1 import ReportV1

HASH_FIELDS = {"tlsh", "ssdeep", "imphash", "impfuzzy", "telfhash", "ccbhash", "simhash"}

_FIELDS = {
    "ccbhash": ("ccbhash", "binary_ccbhash"),
    "impfuzzy": ("impfuzzy", "hash_value"),
    "ssdeep": ("ssdeep", "hash_value"),
    "telfhash": ("telfhash", "telfhash"),
    "tlsh": ("tlsh", "binary_tlsh"),
}


def similarity_hashes(raw: dict[str, Any]) -> dict[str, str]:
    hashes = {}
    for name, (section, field) in _FIELDS.items():
        payload = raw.get(section)
        value = payload.get(field) if isinstance(payload, dict) else None
        if isinstance(value, str) and value:
            hashes[name] = value
    simhash = raw.get("simhash")
    combined = simhash.get("combined_simhash") if isinstance(simhash, dict) else None
    if isinstance(combined, dict) and isinstance(combined.get("hex"), str):
        hashes["simhash"] = combined["hex"]
    return hashes


def _hash_similarity(kind: str, left: str, right: str) -> float:
    if not left or not right:
        return 0.0
    if left == right:
        return 1.0
    if kind == "simhash":
        try:
            left, right = left.removeprefix("0x"), right.removeprefix("0x")
            return 1.0 - (int(left, 16) ^ int(right, 16)).bit_count() / (
                max(len(left), len(right)) * 4
            )
        except ValueError:
            return 0.0
    try:
        module = importlib.import_module("ssdeep" if kind in {"ssdeep", "impfuzzy"} else "tlsh")
        if kind in {"ssdeep", "impfuzzy"}:
            return float(module.compare(left, right)) / 100.0
        if kind == "tlsh":
            return max(0.0, 1.0 - float(module.diff(left, right)) / 300.0)
    except (ImportError, ValueError, AttributeError):
        pass
    return 0.0


def report_features(report: ReportV1) -> dict[str, Any]:
    hashes = {
        str(item["type"]): str(item["value"])
        for item in report.similarity
        if isinstance(item, dict) and item.get("type") in HASH_FIELDS and item.get("value")
    }
    hashes.update(
        {key: str(value) for key, value in report.sample.hashes.items() if key in HASH_FIELDS}
    )
    hashes.update(similarity_hashes(report.extras))
    return {"rule_ids": {finding.rule_id for finding in report.findings}, "hashes": hashes}


def feature_similarity(left: dict[str, Any], right: dict[str, Any]) -> float:
    left_rules, right_rules = left["rule_ids"], right["rule_ids"]
    union = left_rules | right_rules
    rule_score = len(left_rules & right_rules) / len(union) if union else 0.0
    scores = [
        _hash_similarity(kind, left["hashes"].get(kind, ""), right["hashes"].get(kind, ""))
        for kind in HASH_FIELDS
        if left["hashes"].get(kind) and right["hashes"].get(kind)
    ]
    return rule_score if not scores else 0.4 * rule_score + 0.6 * max(scores)


__all__ = ["feature_similarity", "report_features", "similarity_hashes"]
