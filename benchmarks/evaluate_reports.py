#!/usr/bin/env python3
"""Evaluate report/v1 files against independently labeled findings."""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter, defaultdict
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


def _distribution(values: list[float]) -> dict[str, float | None]:
    return {
        "median": _percentile(values, 0.5),
        "p95": _percentile(values, 0.95),
        "p99": _percentile(values, 0.99),
    }


def _differential(manifest_path: Path, baseline_path: Path) -> dict[str, Any]:
    def load(path: Path) -> dict[str, tuple[str, ...]]:
        manifest = json.loads(path.read_text(encoding="utf-8"))
        output = {}
        for case in manifest.get("cases", []):
            report = ReportV1.model_validate_json(
                (path.parent / case["report"]).read_text(encoding="utf-8")
            )
            sample_id = str(case.get("id") or report.sample.hashes.get("sha256") or case["report"])
            output[sample_id] = tuple(sorted(f.rule_id for f in report.findings))
        return output

    current, baseline = load(manifest_path), load(baseline_path)
    changed = [
        sample
        for sample in sorted(current.keys() & baseline.keys())
        if current[sample] != baseline[sample]
    ]
    return {
        "baseline_cases": len(baseline),
        "matched_cases": len(current.keys() & baseline.keys()),
        "changed_cases": changed,
        "new_cases": sorted(current.keys() - baseline.keys()),
        "removed_cases": sorted(baseline.keys() - current.keys()),
    }


def evaluate(manifest_path: Path, *, baseline_manifest: Path | None = None) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("manifest must contain a non-empty cases list")

    tp = fp = fn = 0
    durations: list[float] = []
    statuses: Counter[str] = Counter()
    analyzer_stats: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"statuses": Counter(), "durations": []}
    )
    memory_values: list[float] = []
    platforms: Counter[str] = Counter()
    radare2_versions: Counter[str] = Counter()
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
        platforms[str(case.get("platform") or report.extras.get("platform") or "unknown")] += 1
        radare2_versions[report.tool.radare2_version or "unknown"] += 1
        memory = report.extras.get("memory_stats")
        if isinstance(memory, dict) and isinstance(memory.get("peak_memory_mb"), (int, float)):
            memory_values.append(float(memory["peak_memory_mb"]))
        for outcome in report.analyzers:
            stats = analyzer_stats[outcome.analyzer_id]
            stats["statuses"][outcome.status.value] += 1
            stats["durations"].append(outcome.duration)

    total_outcomes = sum(statuses.values())
    failed = sum(statuses[name] for name in ("failed", "timed_out"))
    unknown = sum(
        statuses[name] for name in ("unsupported", "dependency_unavailable", "not_applicable")
    )
    result = {
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
        "latency_seconds": _distribution(durations),
        "analyzer_metrics": {
            analyzer_id: {
                "cases": sum(stats["statuses"].values()),
                "statuses": dict(sorted(stats["statuses"].items())),
                "error_rate": _ratio(
                    sum(stats["statuses"][name] for name in ("failed", "timed_out")),
                    sum(stats["statuses"].values()),
                ),
                "latency_seconds": _distribution(stats["durations"]),
            }
            for analyzer_id, stats in sorted(analyzer_stats.items())
        },
        "memory_mb": {**_distribution(memory_values), "samples": len(memory_values)},
        "environment": {
            "platforms": dict(sorted(platforms.items())),
            "radare2_versions": dict(sorted(radare2_versions.items())),
        },
    }
    if baseline_manifest is not None:
        result["differential"] = _differential(manifest_path, baseline_manifest)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--min-precision", type=float)
    parser.add_argument("--min-recall", type=float)
    parser.add_argument("--max-error-rate", type=float)
    parser.add_argument("--baseline-manifest", type=Path)
    args = parser.parse_args()
    metrics = evaluate(args.manifest, baseline_manifest=args.baseline_manifest)
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
