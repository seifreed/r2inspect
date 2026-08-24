#!/usr/bin/env python3
"""Evaluate report/v1 files against independently labeled findings."""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any

from r2inspect.schemas.report_v1 import ReportV1


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]


def evaluate(manifest_path: Path) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("manifest must contain a non-empty cases list")

    tp = fp = fn = 0
    durations: list[float] = []
    statuses: Counter[str] = Counter()
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("report"), str):
            raise ValueError("each case requires a report path")
        report_path = manifest_path.parent / case["report"]
        report = ReportV1.model_validate_json(report_path.read_text(encoding="utf-8"))
        expected = set(case.get("expected_rule_ids", []))
        actual = {finding.rule_id for finding in report.findings}
        tp += len(expected & actual)
        fp += len(actual - expected)
        fn += len(expected - actual)
        durations.append(report.analysis.duration)
        statuses.update(outcome.status.value for outcome in report.analyzers)

    total_outcomes = sum(statuses.values())
    failed = sum(statuses[name] for name in ("failed", "timed_out"))
    unknown = sum(
        statuses[name] for name in ("unsupported", "dependency_unavailable", "not_applicable")
    )
    return {
        "schema_version": "r2inspect.benchmark/v1",
        "cases": len(cases),
        "findings": {
            "true_positive": tp,
            "false_positive": fp,
            "false_negative": fn,
            "precision": _ratio(tp, tp + fp),
            "recall": _ratio(tp, tp + fn),
        },
        "analyzers": {
            "statuses": dict(sorted(statuses.items())),
            "error_rate": _ratio(failed, total_outcomes),
            "unknown_rate": _ratio(unknown, total_outcomes),
        },
        "latency_seconds": {
            "median": _percentile(durations, 0.5),
            "p95": _percentile(durations, 0.95),
            "p99": _percentile(durations, 0.99),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--min-precision", type=float)
    parser.add_argument("--min-recall", type=float)
    parser.add_argument("--max-error-rate", type=float)
    args = parser.parse_args()
    metrics = evaluate(args.manifest)
    result = json.dumps(metrics, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(result, encoding="utf-8")
    else:
        print(result, end="")
    precision = metrics["findings"]["precision"]
    recall = metrics["findings"]["recall"]
    error_rate = metrics["analyzers"]["error_rate"]
    if args.min_precision is not None and (precision is None or precision < args.min_precision):
        raise SystemExit("benchmark precision is below the configured threshold")
    if args.min_recall is not None and (recall is None or recall < args.min_recall):
        raise SystemExit("benchmark recall is below the configured threshold")
    if args.max_error_rate is not None and (error_rate is None or error_rate > args.max_error_rate):
        raise SystemExit("benchmark error rate is above the configured threshold")


if __name__ == "__main__":
    main()
