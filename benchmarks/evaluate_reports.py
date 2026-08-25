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


def _predicted_malware(report: ReportV1, classification: dict[str, Any]) -> bool:
    """Apply the manifest-declared, reproducible classification strategy."""
    strategy = classification.get("strategy")
    if strategy == "any_finding":
        return bool(report.findings)
    if strategy == "high_or_critical":
        return any(finding.severity in {"high", "critical"} for finding in report.findings)
    if strategy == "rule_ids":
        rule_ids = classification.get("positive_rule_ids")
        if not isinstance(rule_ids, list) or not all(isinstance(item, str) for item in rule_ids):
            raise ValueError("rule_ids classification requires positive_rule_ids")
        return bool({finding.rule_id for finding in report.findings} & set(rule_ids))
    raise ValueError(
        "classification.strategy must be any_finding, high_or_critical, or rule_ids"
    )


def _classification_metrics(
    rows: list[tuple[str, bool]], classification: dict[str, Any]
) -> dict[str, Any]:
    """Score binary labels while leaving unknown cases out of the denominator."""
    tp = fp = tn = fn = 0
    for expected, predicted in rows:
        if expected == "unknown":
            continue
        if expected == "malware" and predicted:
            tp += 1
        elif expected == "benign" and predicted:
            fp += 1
        elif expected == "benign":
            tn += 1
        elif expected == "malware":
            fn += 1
        else:
            raise ValueError(f"unsupported classification label: {expected}")
    return {
        "strategy": classification.get("strategy"),
        "evaluated_cases": tp + fp + tn + fn,
        "unknown_cases": sum(expected == "unknown" for expected, _ in rows),
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "precision": _ratio(tp, tp + fp),
        "recall": _ratio(tp, tp + fn),
        "false_positive_rate": _ratio(fp, fp + tn),
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
    classification_rows: list[tuple[str, bool]] = []
    classification = manifest.get("classification")
    if classification is not None and not isinstance(classification, dict):
        raise ValueError("classification must be an object")
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
        if isinstance(classification, dict):
            label = case.get("class")
            if label not in {"benign", "malware", "unknown"}:
                raise ValueError("classification requires benign, malware, or unknown case labels")
            classification_rows.append((str(label), _predicted_malware(report, classification)))
        memory = report.extras.get("memory_stats")
        peak_memory = memory.get("peak_memory_mb") if isinstance(memory, dict) else None
        if isinstance(peak_memory, (int, float)):
            memory_values.append(float(peak_memory))
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
        "corpus_kind": manifest.get("corpus_kind", "synthetic"),
        "corpus_id": manifest.get("corpus_id"),
        "provenance": manifest.get("provenance"),
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
    if isinstance(classification, dict):
        result["classification"] = _classification_metrics(classification_rows, classification)
    differential = manifest.get("differential")
    if isinstance(differential, list):
        by_tool: dict[str, dict[str, int]] = defaultdict(
            lambda: {"cases": 0, "completed": 0, "agreements": 0, "timed_out": 0, "failed": 0}
        )
        for item in differential:
            if not isinstance(item, dict) or not isinstance(item.get("tool"), str):
                continue
            stats = by_tool[item["tool"]]
            stats["cases"] += 1
            status = item.get("status", "completed")
            if status == "completed":
                stats["completed"] += 1
            elif status == "timed_out":
                stats["timed_out"] += 1
            else:
                stats["failed"] += 1
            if status == "completed" and item.get("r2inspect_only") == [] and item.get("specialist_only") == []:
                stats["agreements"] += 1
        result["differential_tools"] = {
            tool: {
                **stats,
                "agreement_rate": _ratio(stats["agreements"], stats["completed"]),
            }
            for tool, stats in sorted(by_tool.items())
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
