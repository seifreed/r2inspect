from __future__ import annotations

import json
from datetime import UTC, datetime

from r2inspect.application.report_compare import compare_reports
from r2inspect.application.report_exports import to_html, to_misp, to_sarif, to_stix
from r2inspect.schemas.report_v1 import (
    AnalysisMetadataV1,
    FindingV1,
    ReportV1,
    SampleInfoV1,
    ToolInfoV1,
)


def _report(title: str = "Finding") -> ReportV1:
    return ReportV1(
        tool=ToolInfoV1(version="test"),
        analysis=AnalysisMetadataV1(id="analysis", started_at=datetime.now(UTC), duration=1.0),
        sample=SampleInfoV1(path="sample.bin", hashes={"sha256": "a" * 64}),
        findings=[
            FindingV1(
                finding_id="finding-1",
                rule_id="rule.test",
                title=title,
                category="test",
                severity="high",
                confidence=0.9,
                source_analyzer="test",
                method="fixture",
            )
        ],
    )


def test_exports_have_expected_wire_shapes() -> None:
    report = _report()
    assert "rule.test" in to_html(report)
    assert to_sarif(report)["version"] == "2.1.0"
    assert to_misp(report)["Event"]["Attribute"]
    assert to_stix(report)["type"] == "bundle"


def test_compare_and_json_round_trip() -> None:
    result = compare_reports(_report(), _report("Changed"))
    assert result["status"] == "changed"
    assert result["findings"]["added"]
    json.dumps(result)
