from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
from pymisp import MISPEvent
from stix2 import parse

from r2inspect.application.report_compare import compare_reports
from r2inspect.application.report_exports import to_html, to_misp, to_sarif, to_stix
from r2inspect.schemas.report_v1 import (
    AnalysisMetadataV1,
    FindingV1,
    LocationV1,
    ReportV1,
    SampleInfoV1,
    ToolInfoV1,
)


def _report(title: str = "Finding") -> ReportV1:
    return ReportV1(
        tool=ToolInfoV1(version="test"),
        analysis=AnalysisMetadataV1(
            id="analysis", started_at=datetime(2026, 9, 4, tzinfo=UTC), duration=1.0
        ),
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
                locations=[LocationV1(offset=42, virtual_address=0x401000, function="main")],
            )
        ],
    )


def test_exports_have_expected_wire_shapes() -> None:
    report = _report()
    assert "rule.test" in to_html(report)
    assert to_sarif(report)["version"] == "2.1.0"
    assert to_misp(report)["Event"]["Attribute"]
    assert to_stix(report)["type"] == "bundle"


def test_structured_exports_match_golden_files_and_official_consumers() -> None:
    root = Path(__file__).parents[1] / "fixtures"
    exports = {
        "sarif": to_sarif(_report()),
        "misp": to_misp(_report()),
        "stix": to_stix(_report()),
    }
    for name, payload in exports.items():
        golden = json.loads((root / "golden" / f"export.{name}.json").read_text())
        assert payload == golden

    schema = json.loads((root / "schemas" / "sarif-schema-2.1.0.json").read_text())
    jsonschema.validate(exports["sarif"], schema)
    assert exports["sarif"]["runs"][0]["results"][0]["locations"] == [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": "sample.bin"},
                "region": {"byteOffset": 42},
            },
            "properties": {"virtualAddress": 0x401000},
            "logicalLocations": [{"fullyQualifiedName": "main", "kind": "function"}],
        }
    ]
    assert parse(exports["stix"], allow_custom=False).type == "bundle"
    event = MISPEvent()
    event.load(exports["misp"])
    assert len(event.attributes) == 2


def test_compare_and_json_round_trip() -> None:
    result = compare_reports(_report(), _report("Changed"))
    assert result["status"] == "changed"
    assert result["findings"]["added"]
    json.dumps(result)
