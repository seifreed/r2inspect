from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic_core import PydanticSerializationError

from r2inspect.application.report_builder import build_report_v1
from r2inspect.application.result_mapper import build_analysis_result
from r2inspect.schemas.report_v1 import AnalyzerStatus, ReportV1


def test_build_report_v1_maps_core_data_findings_and_outcomes() -> None:
    result = build_analysis_result(
        {
            "file_info": {
                "path": "/samples/a.exe",
                "size": 4096,
                "sha256": "ab" * 32,
                "file_type": "PE32+",
                "arch": "x86_64",
                "bits": 64,
                "endian": "le",
            },
            "hashing": {"ssdeep": "3:abc"},
            "security": {"aslr": True, "dep": True, "guard_cf": False},
            "indicators": [
                {
                    "type": "suspicious_import",
                    "description": "Creates a process",
                    "severity": "High",
                }
            ],
            "yara": {
                "available": False,
                "error": "dependency unavailable",
                "execution_time": 0.1,
            },
            "pe_info": {"entry_point": 4096},
            "timestamp": datetime(2026, 1, 1, tzinfo=UTC),
            "execution_time": 1.25,
        }
    )

    report = build_report_v1(
        result,
        profile="deep",
        analysis_id="analysis-1",
        configuration={"threads": 2},
        commit="abc123",
        radare2_version="6.1.8",
    )

    assert ReportV1.model_validate_json(report.model_dump_json()) == report
    assert report.sample.hashes["sha256"] == "ab" * 32
    assert report.format.pe == {"entry_point": 4096}
    assert report.security.normalized_mitigations["randomization"].enabled is True
    assert report.findings[0].severity == "high"
    assert report.analyzers[0].status is AnalyzerStatus.DEPENDENCY_UNAVAILABLE
    assert report.analysis.configuration_digest is not None
    assert report.extras["pe_info"] == {"entry_point": 4096}


def test_build_report_v1_distinguishes_not_detected_from_unavailable() -> None:
    result = build_analysis_result(
        {
            "file_info": {"file_type": "ELF64"},
            "one": {"available": True, "detected": False},
            "two": {"available": False},
        }
    )

    report = build_report_v1(result, analysis_id="analysis-2")

    assert [outcome.status for outcome in report.analyzers] == [
        AnalyzerStatus.NOT_DETECTED,
        AnalyzerStatus.DEPENDENCY_UNAVAILABLE,
    ]


def test_build_report_v1_rejects_unknown_legacy_objects() -> None:
    result = build_analysis_result({"custom": object()})

    with pytest.raises(PydanticSerializationError):
        build_report_v1(result, analysis_id="analysis-3")
