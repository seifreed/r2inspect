from __future__ import annotations

import json
from pathlib import Path

from benchmarks.evaluate_reports import evaluate
from r2inspect.application.report_builder import build_report_v1
from r2inspect.application.result_mapper import build_analysis_result
from r2inspect.schemas.report_v1 import EvidenceV1, FindingV1


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

    assert result["findings"] == {
        "true_positive": 1,
        "false_positive": 0,
        "false_negative": 1,
        "precision": 1.0,
        "recall": 0.5,
    }
    assert result["analyzers"]["statuses"] == {"not_detected": 1}
    assert result["latency_seconds"]["p99"] == 2.0
