from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from r2inspect.schemas.report_v1 import (
    AnalysisMetadataV1,
    AnalyzerOutcomeV1,
    AnalyzerStatus,
    EvidenceV1,
    FindingV1,
    ReportV1,
    SampleInfoV1,
    ToolInfoV1,
)


def _report() -> ReportV1:
    return ReportV1(
        tool=ToolInfoV1(version="3.1.0"),
        analysis=AnalysisMetadataV1(
            id="analysis-1",
            started_at=datetime(2026, 1, 1, tzinfo=UTC),
            duration=0.25,
        ),
        sample=SampleInfoV1(size=4, hashes={"sha256": "ab" * 32}),
        findings=[
            FindingV1(
                finding_id="finding-1",
                rule_id="test.rule",
                title="Test finding",
                category="test",
                severity="low",
                confidence=0.5,
                source_analyzer="test",
                method="fixture",
                evidence=[EvidenceV1(kind="string", value="fixture evidence")],
            )
        ],
        analyzers=[AnalyzerOutcomeV1(analyzer_id="test", status=AnalyzerStatus.COMPLETED)],
    )


def test_report_v1_round_trips_and_rejects_unknown_fields() -> None:
    report = _report()
    payload = json.loads(report.model_dump_json())

    assert payload["schema_version"] == "r2inspect.report/v1"
    assert payload["tool"]["backend"] == "r2"
    assert ReportV1.model_validate(payload) == report
    with pytest.raises(ValidationError):
        ReportV1.model_validate({**payload, "unknown": True})


def test_committed_report_schema_matches_model() -> None:
    schema_path = (
        Path(__file__).resolve().parents[2]
        / "r2inspect"
        / "schemas"
        / "r2inspect.report.v1.schema.json"
    )
    assert json.loads(schema_path.read_text(encoding="utf-8")) == ReportV1.model_json_schema()


def test_report_v1_consumer_example_validates_and_reads_typed_fields(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(_report().model_dump_json(), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "examples/consume_report.py", str(report_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    summary = json.loads(result.stdout)

    assert summary["schema_version"] == "r2inspect.report/v1"
    assert summary["analyzers"] == [{"analyzer_id": "test", "status": "completed"}]
    assert summary["findings"] == [
        {
            "rule_id": "test.rule",
            "source_analyzer": "test",
            "evidence": [{"description": None, "kind": "string", "value": "fixture evidence"}],
        }
    ]
