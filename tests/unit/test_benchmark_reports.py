from __future__ import annotations

import json
from pathlib import Path

from benchmarks.evaluate_reports import evaluate
from r2inspect.application.report_builder import build_report_v1
from r2inspect.application.result_mapper import build_analysis_result
from r2inspect.schemas.report_v1 import (
    AnalyzerOutcomeV1,
    AnalyzerStatus,
    EvidenceV1,
    FindingV1,
)


def test_evaluate_reports_scores_findings_statuses_and_latency(tmp_path: Path) -> None:
    report = build_report_v1(
        build_analysis_result(
            {
                "file_info": {"file_type": "PE"},
                "detector": {"available": True, "detected": False},
                "execution_time": 2.0,
            }
        ),
        analysis_id="benchmark-case",
        commit="abc",
        radare2_version="6.1.8",
    )
    report.findings.append(
        FindingV1(
            finding_id="finding-1",
            rule_id="rule.actual",
            title="Actual",
            category="test",
            severity="low",
            confidence=1.0,
            source_analyzer="detector",
            method="fixture",
            evidence=[EvidenceV1(kind="fixture", value=True)],
        )
    )
    (tmp_path / "report.json").write_text(report.model_dump_json(), encoding="utf-8")
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "report": "report.json",
                        "expected_rule_ids": ["rule.actual", "rule.missed"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    result = evaluate(tmp_path / "manifest.json")

    assert result["findings"]["evaluated_cases"] == 1
    assert result["findings"]["unlabeled_cases"] == 0
    assert result["findings"]["true_positive"] == 1
    assert result["findings"]["false_positive"] == 0
    assert result["findings"]["false_negative"] == 1
    assert result["findings"]["precision"] == 1.0
    assert result["findings"]["recall"] == 0.5
    assert result["findings"]["by_rule"]["rule.missed"]["false_negative"] == 1
    assert result["findings"]["quality"]["evidence_coverage"] == 1.0
    assert result["analyzers"]["statuses"] == {"not_detected": 1}
    assert result["latency_seconds"]["p99"] == 2.0


def test_evaluate_reports_exposes_dimensions_and_differential(tmp_path: Path) -> None:
    report = build_report_v1(
        build_analysis_result(
            {
                "file_info": {"file_type": "ELF"},
                "detector": {"available": True, "detected": True, "execution_time": 0.25},
                "execution_time": 1.0,
                "memory_stats": {"peak_memory_mb": 12.5},
            }
        ),
        analysis_id="case-1",
        radare2_version="6.1.8",
    )
    (tmp_path / "report.json").write_text(report.model_dump_json(), encoding="utf-8")
    manifest = {
        "corpus_kind": "real_labeled",
        "corpus_id": "dataset-v1",
        "provenance": {
            "source": "licensed-source",
            "dataset_version": "v1",
            "labeling_method": "independent-review",
        },
        "cases": [{"id": "sample-1", "report": "report.json", "platform": "linux"}],
    }
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (tmp_path / "baseline.json").write_text(json.dumps(manifest), encoding="utf-8")

    result = evaluate(tmp_path / "manifest.json", baseline_manifest=tmp_path / "baseline.json")

    assert result["analyzer_metrics"]["detector"]["latency_seconds"]["median"] == 0.25
    assert result["analyzer_metrics"]["detector"]["memory_mb"]["samples"] == 0
    assert result["analyzer_metrics"]["detector"]["timeouts"] == 0
    assert result["analyzers"]["timeouts"] == 0
    assert result["memory_mb"]["median"] == 12.5
    assert result["environment"] == {"platforms": {"linux": 1}, "radare2_versions": {"6.1.8": 1}}
    assert result["platform_metrics"]["linux"]["memory_mb"]["median"] == 12.5
    assert result["platform_metrics"]["linux"]["timeouts"] == 0
    assert result["radare2_metrics"]["6.1.8"]["latency_seconds"]["median"] == 1.0
    assert result["radare2_metrics"]["6.1.8"]["execution_failure_rate"] == 0.0
    assert result["differential"]["changed_cases"] == []
    assert result["corpus_kind"] == "real_labeled"
    assert result["provenance"]["dataset_version"] == "v1"
    assert result["sample_types"] == {"unspecified": 1}


def test_evaluate_reports_keeps_platform_comparison_dimensions(tmp_path: Path) -> None:
    report = build_report_v1(
        build_analysis_result(
            {
                "file_info": {"file_type": "ELF"},
                "detector": {"available": True, "detected": False, "execution_time": 0.25},
                "execution_time": 1.0,
                "memory_stats": {"peak_memory_mb": 12.5},
            }
        ),
        analysis_id="cross-platform",
        radare2_version="6.1.8",
    )
    (tmp_path / "report.json").write_text(report.model_dump_json(), encoding="utf-8")
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "cases": [
                    {"id": "linux", "report": "report.json", "platform": "linux"},
                    {"id": "windows", "report": "report.json", "platform": "windows"},
                ]
            }
        ),
        encoding="utf-8",
    )

    result = evaluate(tmp_path / "manifest.json")

    assert set(result["platform_metrics"]) == {"linux", "windows"}
    assert result["platform_metrics"]["linux"]["memory_mb"]["median"] == 12.5
    assert result["platform_metrics"]["windows"]["timeouts"] == 0


def test_evaluate_reports_scores_declared_real_classification(tmp_path: Path) -> None:
    report = build_report_v1(
        build_analysis_result(
            {
                "file_info": {"file_type": "PE"},
                "detector": {"available": True, "detected": True},
            }
        ),
        analysis_id="malware-case",
        commit="abc",
        radare2_version="6.1.8",
    )
    report.findings.append(
        FindingV1(
            finding_id="finding-1",
            rule_id="rule.malware",
            title="Detection",
            category="detection",
            severity="high",
            confidence=1.0,
            source_analyzer="detector",
            method="fixture",
        )
    )
    (tmp_path / "report.json").write_text(report.model_dump_json(), encoding="utf-8")
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "corpus_kind": "real_labeled",
                "classification": {"strategy": "high_or_critical"},
                "cases": [
                    {"report": "report.json", "class": "malware"},
                    {"report": "report.json", "class": "benign"},
                    {"report": "report.json", "class": "unknown"},
                ],
            }
        ),
        encoding="utf-8",
    )

    result = evaluate(tmp_path / "manifest.json")

    assert result["classification"] == {
        "strategy": "high_or_critical",
        "evaluated_cases": 2,
        "unknown_cases": 1,
        "true_positive": 1,
        "false_positive": 1,
        "true_negative": 0,
        "false_negative": 0,
        "precision": 0.5,
        "recall": 1.0,
        "false_positive_rate": 1.0,
    }


def test_evaluate_reports_scores_analyzer_detection_by_label(tmp_path: Path) -> None:
    reports = []
    for name, detected, label in (
        ("malware", True, "malware"),
        ("benign", False, "benign"),
    ):
        report = build_report_v1(
            build_analysis_result(
                {
                    "file_info": {"file_type": "PE"},
                    "detector": {"available": True, "detected": detected},
                    "compiler_detector": {"available": True, "detected": True},
                }
            ),
            analysis_id=name,
        )
        path = tmp_path / f"{name}.json"
        path.write_text(report.model_dump_json(), encoding="utf-8")
        reports.append({"id": name, "report": path.name, "class": label})
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "corpus_kind": "real_labeled",
                "classification": {
                    "strategy": "any_finding",
                    "detection_analyzers": ["detector"],
                },
                "cases": reports,
            }
        ),
        encoding="utf-8",
    )

    result = evaluate(tmp_path / "manifest.json")

    assert result["analyzer_metrics"]["detector"]["classification"] == {
        "evaluated_cases": 2,
        "unknown_cases": 0,
        "true_positive": 1,
        "false_positive": 0,
        "true_negative": 1,
        "false_negative": 0,
        "precision": 1.0,
        "recall": 1.0,
        "false_positive_rate": 0.0,
    }
    assert "classification" not in result["analyzer_metrics"]["compiler_detector"]


def test_calibrated_behavior_ignores_generic_signatures_in_large_binaries(tmp_path: Path) -> None:
    report = build_report_v1(
        build_analysis_result(
            {
                "file_info": {"file_type": "PE"},
                "detector": {"available": True, "detected": True},
                "imports": [{"name": str(index)} for index in range(600)],
                "exports": [{"name": str(index)} for index in range(600)],
                "functions": {"total_functions": 1200},
            }
        ),
        analysis_id="system-dll",
    )
    report.findings.append(
        FindingV1(
            finding_id="finding-1",
            rule_id="rule.anti-debug",
            title="Anti-debugging",
            category="Anti-Debug",
            severity="high",
            confidence=1.0,
            source_analyzer="yara",
            method="fixture",
        )
    )
    report.extras.update(
        {
            "imports": [{"name": str(index)} for index in range(600)],
            "exports": [{"name": str(index)} for index in range(600)],
            "functions": {"total_functions": 1200},
        }
    )
    (tmp_path / "report.json").write_text(report.model_dump_json(), encoding="utf-8")
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "corpus_kind": "real_labeled",
                "classification": {"strategy": "calibrated_behavior"},
                "cases": [
                    {"report": "report.json", "class": "benign"},
                    {"report": "report.json", "class": "unknown"},
                ],
            }
        ),
        encoding="utf-8",
    )
    result = evaluate(tmp_path / "manifest.json")
    assert result["classification"]["false_positive"] == 0


def test_calibrated_behavior_applies_each_complexity_limit(tmp_path: Path) -> None:
    report = build_report_v1(
        build_analysis_result({"file_info": {"file_type": "PE"}}), analysis_id="large-imports"
    )
    report.findings.append(
        FindingV1(
            finding_id="finding-1",
            rule_id="rule.cluster",
            title="Cluster",
            category="Behavior Cluster",
            severity="medium",
            confidence=1.0,
            source_analyzer="behavior",
            method="fixture",
        )
    )
    report.extras["imports"] = [{"name": str(index)} for index in range(501)]
    (tmp_path / "report.json").write_text(report.model_dump_json(), encoding="utf-8")
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "classification": {
                    "strategy": "calibrated_behavior",
                    "max_functions": 1000,
                    "max_imports": 500,
                    "max_exports": 500,
                },
                "cases": [{"report": "report.json", "class": "benign"}],
            }
        ),
        encoding="utf-8",
    )

    assert evaluate(tmp_path / "manifest.json")["classification"]["false_positive"] == 0


def test_evaluate_reports_separates_analyzer_status_rates(tmp_path: Path) -> None:
    report = build_report_v1(
        build_analysis_result({"file_info": {"file_type": "ELF"}}), analysis_id="statuses"
    )
    report.analyzers = [
        AnalyzerOutcomeV1(analyzer_id="ok", status=AnalyzerStatus.COMPLETED),
        AnalyzerOutcomeV1(analyzer_id="failed", status=AnalyzerStatus.FAILED),
        AnalyzerOutcomeV1(analyzer_id="missing", status=AnalyzerStatus.DEPENDENCY_UNAVAILABLE),
        AnalyzerOutcomeV1(analyzer_id="irrelevant", status=AnalyzerStatus.NOT_APPLICABLE),
    ]
    (tmp_path / "report.json").write_text(report.model_dump_json(), encoding="utf-8")
    (tmp_path / "manifest.json").write_text(
        json.dumps({"cases": [{"report": "report.json"}]}), encoding="utf-8"
    )

    result = evaluate(tmp_path / "manifest.json")

    assert result["analyzers"]["execution_failure_rate"] == 0.25
    assert result["analyzers"]["dependency_unavailable_rate"] == 0.25
    assert result["analyzers"]["not_applicable_rate"] == 0.25
    assert result["analyzer_metrics"]["missing"]["dependency_unavailable_rate"] == 1.0


def test_evaluate_reports_does_not_score_unlabeled_findings(tmp_path: Path) -> None:
    report = build_report_v1(
        build_analysis_result({"file_info": {"file_type": "PE"}}), analysis_id="unlabeled"
    )
    report.findings.append(
        FindingV1(
            finding_id="finding-1",
            rule_id="rule.observed",
            title="Observed",
            category="behavior",
            severity="medium",
            confidence=1.0,
            source_analyzer="detector",
            method="fixture",
        )
    )
    (tmp_path / "report.json").write_text(report.model_dump_json(), encoding="utf-8")
    (tmp_path / "manifest.json").write_text(
        json.dumps({"cases": [{"report": "report.json"}]}), encoding="utf-8"
    )

    findings = evaluate(tmp_path / "manifest.json")["findings"]

    assert findings["evaluated_cases"] == 0
    assert findings["unlabeled_cases"] == 1
    assert findings["false_positive"] == 0


def test_evaluate_reports_scores_structured_finding_categories(tmp_path: Path) -> None:
    report = build_report_v1(
        build_analysis_result({"file_info": {"file_type": "PE"}}), analysis_id="labeled"
    )
    report.findings.append(
        FindingV1(
            finding_id="finding-1",
            rule_id="rule.expected",
            title="Expected",
            category="anti-analysis",
            severity="high",
            confidence=1.0,
            source_analyzer="anti_analysis",
            method="fixture",
        )
    )
    (tmp_path / "report.json").write_text(report.model_dump_json(), encoding="utf-8")
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "report": "report.json",
                        "expected_findings": [
                            {"rule_id": "rule.expected", "category": "anti-analysis"}
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = evaluate(tmp_path / "manifest.json")["findings"]

    assert findings["by_category"]["evaluated_cases"] == 1
    assert findings["by_category"]["metrics"]["anti-analysis"]["precision"] == 1.0
    assert findings["quality"]["high_severity_location_rate"] == 0.0
    assert findings["quality"]["high_severity_false_positive_rate"] == 0.0


def test_evaluate_reports_migrates_unique_legacy_finding_labels(tmp_path: Path) -> None:
    report = build_report_v1(
        build_analysis_result({"file_info": {"file_type": "PE"}}), analysis_id="legacy-labels"
    )
    for rule_id, category in (
        ("r2inspect.packer.detected.v1", "packer"),
        ("r2inspect.yara.example.v1", "yara"),
    ):
        report.findings.append(
            FindingV1(
                finding_id=rule_id,
                rule_id=rule_id,
                title=rule_id,
                category=category,
                severity="medium",
                confidence=1.0,
                source_analyzer=category,
                method="fixture",
            )
        )
    (tmp_path / "report.json").write_text(report.model_dump_json(), encoding="utf-8")
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "report": "report.json",
                        "expected_findings": [
                            {"rule_id": "legacy.indicator.packer", "category": "packer"},
                            {"rule_id": "legacy.indicator.yara.match", "category": "yara"},
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = evaluate(tmp_path / "manifest.json")["findings"]

    assert findings["true_positive"] == 2
    assert findings["false_positive"] == 0
    assert findings["false_negative"] == 0
