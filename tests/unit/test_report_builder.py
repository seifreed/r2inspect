from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path

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
    assert report.sample.detected_format == "PE"
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


@pytest.mark.parametrize(
    ("file_type", "detail_key", "features", "expected"),
    [
        (
            "PE32+",
            "pe_info",
            {"aslr": True, "dep": True, "guard_cf": True, "authenticode": True},
            {
                "randomization": True,
                "no_execution": True,
                "control_flow_integrity": True,
                "signature": True,
            },
        ),
        (
            "ELF64",
            "elf_info",
            {"pie": True, "nx": True, "stack_canary": True, "relro": "full"},
            {
                "randomization": True,
                "no_execution": True,
                "stack_protection": True,
                "relocations": True,
            },
        ),
        (
            "Mach-O 64",
            "macho_info",
            {"pie": True, "nx": True, "signed": True, "arc": True},
            {
                "randomization": True,
                "no_execution": True,
                "signature": True,
                "additional_hardening": True,
            },
        ),
    ],
)
def test_build_report_v1_normalizes_format_security(
    file_type: str,
    detail_key: str,
    features: dict[str, object],
    expected: dict[str, bool],
) -> None:
    result = build_analysis_result(
        {
            "file_info": {"file_type": file_type},
            detail_key: {"security_features": features},
        }
    )

    report = build_report_v1(
        result,
        analysis_id="analysis-security",
        commit="abc123",
        radare2_version="6.1.8",
    )

    assert report.security.format_specific == features
    assert {
        name: report.security.normalized_mitigations[name].enabled for name in expected
    } == expected
    if file_type == "PE32+":
        assert report.security.normalized_mitigations["stack_protection"].enabled is None


def test_report_v1_format_projection_matches_golden() -> None:
    golden_path = Path(__file__).parents[1] / "golden" / "report_v1_formats.json"
    expected = json.loads(golden_path.read_text(encoding="utf-8"))
    inputs = {
        "PE32+": ("pe_info", {"aslr": True, "dep": True, "guard_cf": True, "authenticode": True}),
        "ELF64": ("elf_info", {"pie": True, "nx": True, "stack_canary": True, "relro": "full"}),
        "Mach-O 64": ("macho_info", {"pie": True, "nx": True, "signed": True, "arc": True}),
    }

    actual = {}
    for file_type, (detail_key, features) in inputs.items():
        report = build_report_v1(
            build_analysis_result(
                {"file_info": {"file_type": file_type}, detail_key: {"security_features": features}}
            ),
            analysis_id="golden",
            commit="abc",
            radare2_version="6.1.8",
        )
        normalized = {
            name: mitigation.enabled
            for name, mitigation in report.security.normalized_mitigations.items()
            if mitigation.enabled is not None
        }
        if file_type == "PE32+":
            normalized["stack_protection"] = None
        actual[file_type] = {
            "detected_format": report.sample.detected_format,
            "format_specific": report.security.format_specific,
            "normalized": normalized,
        }

    assert actual == expected
