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

_FAILURE_STATUSES = ("failed", "timed_out")
_LEGACY_FINDING_PREFIXES = {
    "legacy.indicator.packer": "r2inspect.packer.",
    "legacy.indicator.yara.match": "r2inspect.yara.",
}


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


def _status_rates(statuses: Counter[str]) -> dict[str, float | None]:
    total = sum(statuses.values())
    return {
        "execution_failure_rate": _ratio(sum(statuses[name] for name in _FAILURE_STATUSES), total),
        "dependency_unavailable_rate": _ratio(statuses["dependency_unavailable"], total),
        "not_applicable_rate": _ratio(statuses["not_applicable"], total),
    }


def _dimension_stats() -> dict[str, Any]:
    return {
        "durations": [],
        "memory": [],
        "statuses": Counter(),
        "classification": [],
    }


def _dimension_summary(stats: dict[str, Any], cases: int) -> dict[str, Any]:
    statuses = stats["statuses"]
    total = sum(statuses.values())
    summary: dict[str, Any] = {
        "cases": cases,
        "latency_seconds": _distribution(stats["durations"]),
        "memory_mb": {**_distribution(stats["memory"]), "samples": len(stats["memory"])},
        "analyzer_statuses": dict(sorted(statuses.items())),
        **_status_rates(statuses),
        "timeouts": statuses["timed_out"],
        "timeout_rate": _ratio(statuses["timed_out"], total),
    }
    if stats["classification"]:
        summary["classification"] = _binary_metrics(stats["classification"])
    return summary


def _finding_labels(case: dict[str, Any]) -> dict[str, str | None] | None:
    if "expected_findings" in case:
        labels = case["expected_findings"]
        if not isinstance(labels, list) or not all(
            isinstance(item, dict)
            and isinstance(item.get("rule_id"), str)
            and isinstance(item.get("category"), str)
            for item in labels
        ):
            raise ValueError("expected_findings requires rule_id and category strings")
        return {str(item["rule_id"]): str(item["category"]) for item in labels}
    if "expected_rule_ids" in case:
        rule_ids = case["expected_rule_ids"]
        if not isinstance(rule_ids, list) or not all(isinstance(item, str) for item in rule_ids):
            raise ValueError("expected_rule_ids must be a list of strings")
        return dict.fromkeys(rule_ids)
    return None


def _update_scores(scores: dict[str, Counter[str]], expected: set[str], actual: set[str]) -> None:
    for key in expected | actual:
        if key in expected and key in actual:
            scores[key]["true_positive"] += 1
        elif key in actual:
            scores[key]["false_positive"] += 1
        else:
            scores[key]["false_negative"] += 1


def _migrate_legacy_labels(
    expected: dict[str, str | None], actual: set[str]
) -> dict[str, str | None]:
    migrated = dict(expected)
    for legacy_id, prefix in _LEGACY_FINDING_PREFIXES.items():
        matches = [rule_id for rule_id in actual if rule_id.startswith(prefix)]
        if legacy_id in migrated and len(matches) == 1:
            migrated[matches[0]] = migrated.pop(legacy_id)
    return migrated


def _score_summary(counts: Counter[str]) -> dict[str, int | float | None]:
    tp = counts["true_positive"]
    fp = counts["false_positive"]
    fn = counts["false_negative"]
    return {
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "precision": _ratio(tp, tp + fp),
        "recall": _ratio(tp, tp + fn),
    }


def _predicted_malware(report: ReportV1, classification: dict[str, Any]) -> bool:
    """Apply the manifest-declared, reproducible classification strategy."""
    strategy = classification.get("strategy")
    if strategy == "any_finding":
        return bool(report.findings)
    if strategy == "high_or_critical":
        return any(finding.severity in {"high", "critical"} for finding in report.findings)
    if strategy == "calibrated_behavior":
        extras = report.extras
        functions = extras.get("functions")
        raw_function_count = functions.get("total_functions") if isinstance(functions, dict) else 0
        function_count = (
            int(raw_function_count) if isinstance(raw_function_count, int | float) else 0
        )
        imports = extras.get("imports")
        import_count = len(imports) if isinstance(imports, list) else 0
        exports = extras.get("exports")
        export_count = len(exports) if isinstance(exports, list) else 0
        max_functions = int(classification.get("max_functions", 1000))
        max_imports = int(classification.get("max_imports", 500))
        max_exports = int(classification.get("max_exports", 500))
        if (
            function_count > max_functions
            or import_count > max_imports
            or export_count > max_exports
        ):
            return False
        severe = [
            finding for finding in report.findings if finding.severity in {"high", "critical"}
        ]
        categories = {finding.category for finding in severe}
        if len(categories) >= 2:
            return True
        return any(
            finding.category in {"Suspicious API", "Behavior Cluster", "behavior"}
            and finding.severity == "medium"
            for finding in report.findings
        )
    if strategy == "rule_ids":
        rule_ids = classification.get("positive_rule_ids")
        if not isinstance(rule_ids, list) or not all(isinstance(item, str) for item in rule_ids):
            raise ValueError("rule_ids classification requires positive_rule_ids")
        return bool({finding.rule_id for finding in report.findings} & set(rule_ids))
    raise ValueError(
        "classification.strategy must be any_finding, high_or_critical, calibrated_behavior, or rule_ids"
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


def _binary_metrics(rows: list[tuple[str, bool]]) -> dict[str, Any]:
    """Score analyzer-level binary detections against corpus labels."""
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
    return {
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

    finding_counts: Counter[str] = Counter()
    finding_rule_scores: dict[str, Counter[str]] = defaultdict(Counter)
    finding_category_scores: dict[str, Counter[str]] = defaultdict(Counter)
    finding_cases = category_cases = 0
    observed_findings = findings_with_evidence = 0
    high_findings = high_findings_with_locations = 0
    high_finding_tp = high_finding_fp = 0
    durations: list[float] = []
    statuses: Counter[str] = Counter()
    analyzer_stats: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"statuses": Counter(), "durations": [], "memory": [], "classification": []}
    )
    platform_stats: dict[str, dict[str, Any]] = defaultdict(_dimension_stats)
    radare2_stats: dict[str, dict[str, Any]] = defaultdict(_dimension_stats)
    memory_values: list[float] = []
    platforms: Counter[str] = Counter()
    radare2_versions: Counter[str] = Counter()
    sample_types: Counter[str] = Counter()
    classification_rows: list[tuple[str, bool]] = []
    classification = manifest.get("classification")
    if classification is not None and not isinstance(classification, dict):
        raise ValueError("classification must be an object")
    detection_analyzers: set[str] = set()
    if isinstance(classification, dict):
        declared = classification.get("detection_analyzers", [])
        if not isinstance(declared, list) or not all(isinstance(item, str) for item in declared):
            raise ValueError("classification.detection_analyzers must be a list of strings")
        detection_analyzers = set(declared)
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("report"), str):
            raise ValueError("each case requires a report path")
        report_path = manifest_path.parent / case["report"]
        report = ReportV1.model_validate_json(report_path.read_text(encoding="utf-8"))
        sample_types[str(case.get("sample_type") or "unspecified")] += 1
        observed_findings += len(report.findings)
        findings_with_evidence += sum(bool(finding.evidence) for finding in report.findings)
        severe_findings = [
            finding for finding in report.findings if finding.severity in {"high", "critical"}
        ]
        high_findings += len(severe_findings)
        high_findings_with_locations += sum(bool(finding.locations) for finding in severe_findings)
        expected_findings = _finding_labels(case)
        if expected_findings is not None:
            finding_cases += 1
            actual = {finding.rule_id for finding in report.findings}
            expected_findings = _migrate_legacy_labels(expected_findings, actual)
            expected = set(expected_findings)
            finding_counts["true_positive"] += len(expected & actual)
            finding_counts["false_positive"] += len(actual - expected)
            finding_counts["false_negative"] += len(expected - actual)
            _update_scores(finding_rule_scores, expected, actual)
            severe_rules = {finding.rule_id for finding in severe_findings}
            high_finding_tp += len(expected & severe_rules)
            high_finding_fp += len(severe_rules - expected)
            if all(category is not None for category in expected_findings.values()):
                category_cases += 1
                expected_categories = {str(category) for category in expected_findings.values()}
                actual_categories = {finding.category for finding in report.findings}
                _update_scores(finding_category_scores, expected_categories, actual_categories)
        durations.append(report.analysis.duration)
        statuses.update(outcome.status.value for outcome in report.analyzers)
        platform = str(
            case.get("platform")
            or case.get("runner_platform")
            or report.extras.get("platform")
            or "unknown"
        )
        platforms[platform] += 1
        radare2_version = report.tool.radare2_version or "unknown"
        radare2_versions[radare2_version] += 1
        dimensions = (platform_stats[platform], radare2_stats[radare2_version])
        for stats in dimensions:
            stats["durations"].append(report.analysis.duration)
        if isinstance(classification, dict):
            label = case.get("class")
            if label not in {"benign", "malware", "unknown"}:
                raise ValueError("classification requires benign, malware, or unknown case labels")
            classification_rows.append((str(label), _predicted_malware(report, classification)))
        memory = report.extras.get("memory_stats")
        peak_memory = memory.get("peak_memory_mb") if isinstance(memory, dict) else None
        if isinstance(peak_memory, int | float):
            memory_values.append(float(peak_memory))
            for stats in dimensions:
                stats["memory"].append(float(peak_memory))
        label = case.get("class")
        if isinstance(classification, dict) and label in {"benign", "malware", "unknown"}:
            prediction = (str(label), _predicted_malware(report, classification))
            for stats in dimensions:
                stats["classification"].append(prediction)
        for outcome in report.analyzers:
            stats = analyzer_stats[outcome.analyzer_id]
            stats["statuses"][outcome.status.value] += 1
            stats["durations"].append(outcome.duration)
            memory = next(
                (
                    outcome.metrics.get(key)
                    for key in (
                        "peak_memory_mb",
                        "memory_mb",
                        "rss_mb",
                        "process_memory_after_mb",
                    )
                    if outcome.metrics.get(key) is not None
                ),
                None,
            )
            if isinstance(memory, int | float) and not isinstance(memory, bool):
                stats["memory"].append(float(memory))
            detected = outcome.metrics.get("detected")
            if (
                outcome.analyzer_id in detection_analyzers
                and isinstance(detected, bool)
                and label in {"benign", "malware", "unknown"}
            ):
                stats["classification"].append((str(label), detected))
            for dimension in dimensions:
                dimension["statuses"][outcome.status.value] += 1

    total_outcomes = sum(statuses.values())
    findings_summary = _score_summary(finding_counts)
    result = {
        "schema_version": "r2inspect.benchmark/v1",
        "corpus_kind": manifest.get("corpus_kind", "synthetic"),
        "corpus_id": manifest.get("corpus_id"),
        "provenance": manifest.get("provenance"),
        "cases": len(cases),
        "evaluation_role": manifest.get("evaluation_role"),
        "findings": {
            "evaluated_cases": finding_cases,
            "unlabeled_cases": len(cases) - finding_cases,
            **findings_summary,
            "by_rule": {
                key: _score_summary(counts) for key, counts in sorted(finding_rule_scores.items())
            },
            "by_category": {
                "evaluated_cases": category_cases,
                "metrics": {
                    key: _score_summary(counts)
                    for key, counts in sorted(finding_category_scores.items())
                },
            },
            "quality": {
                "observed": observed_findings,
                "evidence_coverage": _ratio(findings_with_evidence, observed_findings),
                "high_severity_observed": high_findings,
                "high_severity_location_rate": _ratio(high_findings_with_locations, high_findings),
                "high_severity_false_positive_rate": _ratio(
                    high_finding_fp, high_finding_tp + high_finding_fp
                ),
            },
        },
        "analyzers": {
            "statuses": dict(sorted(statuses.items())),
            **_status_rates(statuses),
            "timeouts": statuses["timed_out"],
            "timeout_rate": _ratio(statuses["timed_out"], total_outcomes),
        },
        "latency_seconds": _distribution(durations),
        "analyzer_metrics": {
            analyzer_id: {
                "cases": sum(stats["statuses"].values()),
                "statuses": dict(sorted(stats["statuses"].items())),
                **_status_rates(stats["statuses"]),
                "timeouts": stats["statuses"]["timed_out"],
                "timeout_rate": _ratio(
                    stats["statuses"]["timed_out"], sum(stats["statuses"].values())
                ),
                "latency_seconds": _distribution(stats["durations"]),
                "memory_mb": {
                    **_distribution(stats["memory"]),
                    "samples": len(stats["memory"]),
                },
            }
            for analyzer_id, stats in sorted(analyzer_stats.items())
        },
        "memory_mb": {**_distribution(memory_values), "samples": len(memory_values)},
        "environment": {
            "platforms": dict(sorted(platforms.items())),
            "radare2_versions": dict(sorted(radare2_versions.items())),
        },
        "sample_types": dict(sorted(sample_types.items())),
        "platform_metrics": {
            platform: _dimension_summary(stats, platforms[platform])
            for platform, stats in sorted(platform_stats.items())
        },
        "radare2_metrics": {
            version: _dimension_summary(stats, radare2_versions[version])
            for version, stats in sorted(radare2_stats.items())
        },
    }
    for analyzer_id, stats in analyzer_stats.items():
        if stats["classification"]:
            result["analyzer_metrics"][analyzer_id]["classification"] = _binary_metrics(
                stats["classification"]
            )
    if isinstance(classification, dict):
        result["classification"] = _classification_metrics(classification_rows, classification)
    differential = manifest.get("differential")
    if isinstance(differential, list):
        by_tool: dict[str, dict[str, int]] = defaultdict(
            lambda: {
                "cases": 0,
                "completed": 0,
                "agreements": 0,
                "timed_out": 0,
                "skipped": 0,
                "failed": 0,
            }
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
            elif status == "skipped_by_profile":
                stats["skipped"] += 1
            else:
                stats["failed"] += 1
            if status == "completed" and item.get("agreement"):
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
    parser.add_argument("--min-classification-precision", type=float)
    parser.add_argument("--min-classification-recall", type=float)
    parser.add_argument(
        "--max-execution-failure-rate", "--max-error-rate", type=float, dest="max_failure_rate"
    )
    parser.add_argument("--max-dependency-unavailable-rate", type=float)
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
    failure_rate = metrics["analyzers"]["execution_failure_rate"]
    dependency_rate = metrics["analyzers"]["dependency_unavailable_rate"]
    if args.min_precision is not None and (precision is None or precision < args.min_precision):
        raise SystemExit("benchmark precision is below the configured threshold")
    if args.min_recall is not None and (recall is None or recall < args.min_recall):
        raise SystemExit("benchmark recall is below the configured threshold")
    if args.max_failure_rate is not None and (
        failure_rate is None or failure_rate > args.max_failure_rate
    ):
        raise SystemExit("benchmark execution failure rate is above the configured threshold")
    if args.max_dependency_unavailable_rate is not None and (
        dependency_rate is None or dependency_rate > args.max_dependency_unavailable_rate
    ):
        raise SystemExit("benchmark dependency unavailable rate is above the configured threshold")
    classification = metrics.get("classification", {})
    classification_precision = classification.get("precision")
    classification_recall = classification.get("recall")
    if args.min_classification_precision is not None and (
        classification_precision is None
        or classification_precision < args.min_classification_precision
    ):
        raise SystemExit("benchmark classification precision is below the configured threshold")
    if args.min_classification_recall is not None and (
        classification_recall is None or classification_recall < args.min_classification_recall
    ):
        raise SystemExit("benchmark classification recall is below the configured threshold")


if __name__ == "__main__":
    main()
