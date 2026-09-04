from __future__ import annotations

from r2inspect.application.report_components import findings
from r2inspect.application.result_mapper import build_analysis_result
from r2inspect.domain.services.behavior_analysis import behavior_findings
from r2inspect.modules.anti_analysis_support import build_anti_analysis_report
from r2inspect.modules.packer_detector import PackerEvidenceScorer, _packer_findings
from r2inspect.modules.yara_findings import match_finding
from r2inspect.pipeline.stages_metadata import MetadataStage
from r2inspect.registry.analyzer_registry import AnalyzerCategory, AnalyzerRegistry
from r2inspect.schemas.report_v1 import FindingV1
from tests.helpers import FakeAdapter, FakeConfig


def test_four_native_finding_sources_are_schema_valid() -> None:
    scorer = PackerEvidenceScorer()
    scorer.add_signature({"type": "UPX", "signature": "UPX!", "address": "0x401000"})
    scorer.add_entropy_results(
        {".text": {"entropy": 7.9, "high_entropy": True}, "summary": {"high_entropy_sections": 1}}
    )
    packer = _packer_findings(scorer.verdict())[0]

    class AntiDetector:
        def _detect_anti_debug_detailed(self):
            return {
                "detected": True,
                "evidence": [{"type": "PEB", "detail": "PEB access", "address": "0x402000"}],
            }

        def _detect_anti_vm_detailed(self):
            return {"detected": False, "evidence": []}

        def _detect_anti_sandbox_detailed(self):
            return {"detected": False, "evidence": []}

        def _detect_evasion_techniques(self):
            return []

        def _find_suspicious_apis(self):
            return []

        def _detect_timing_checks_detailed(self):
            return {"detected": False, "evidence": []}

        def _detect_environment_checks(self):
            return []

    anti = build_anti_analysis_report(AntiDetector())["findings"][0]
    yara = match_finding(
        {
            "rule": "known_malware",
            "namespace": "community",
            "tags": ["malware"],
            "meta": {"severity": "critical", "confidence": 95, "attack": "T1027"},
            "strings": [
                {"identifier": "$a", "instances": [{"offset": 32, "matched_data": "UPX!"}]}
            ],
        }
    )
    behavior = behavior_findings(
        [
            {"name": "CreateProcessA", "address": "0x5000"},
            {"name": "connect", "address": "0x6000"},
        ],
        [{"offset": 0x1000, "size": 0x100, "name": "main"}],
        lambda target: [{"from": 0x1010 if target == 0x5000 else 0x1020}],
    )[0]

    parsed = [FindingV1.model_validate(item) for item in (packer, anti, yara, behavior)]
    assert {item.source_analyzer for item in parsed} == {
        "packer_detector",
        "anti_analysis",
        "yara_analyzer",
        "import_analyzer",
    }
    assert all(item.evidence for item in parsed)
    assert all(item.locations for item in parsed)


def test_report_uses_native_findings_and_drops_presence_only_api_noise() -> None:
    native = match_finding(
        {"rule": "rule1", "namespace": "default", "meta": {}, "tags": [], "strings": []}
    )
    result = build_analysis_result(
        {
            "yara_matches": [{"rule": "rule1", "finding": native}],
            "indicators": [
                {"type": "YARA Match", "description": "legacy duplicate", "severity": "High"},
                {"type": "Suspicious API", "description": "VirtualAlloc", "severity": "Medium"},
            ],
        }
    )

    report_findings = findings(result)

    assert [item.rule_id for item in report_findings] == [native["rule_id"]]
    assert report_findings[0].source_analyzer == "yara_analyzer"


def test_yara_finding_normalizes_untrusted_metadata() -> None:
    finding = FindingV1.model_validate(
        match_finding(
            {
                "rule": "rule1",
                "meta": {"severity": "warning", "confidence": "95"},
                "strings": [{"instances": [{"offset": True}]}],
            }
        )
    )

    assert finding.severity == "medium"
    assert finding.confidence == 0.95
    assert finding.locations == []

    assert match_finding({"rule": "bad", "meta": {"confidence": float("nan")}})["confidence"] == 0.8


def test_metadata_stage_preserves_import_analyzer_findings() -> None:
    native = behavior_findings(
        [
            {"name": "CreateProcessA", "address": "0x5000"},
            {"name": "connect", "address": "0x6000"},
        ],
        [{"offset": 0x1000, "size": 0x100, "name": "main"}],
        lambda target: [{"from": 0x1010 if target == 0x5000 else 0x1020}],
    )

    class ImportAnalyzer:
        def __init__(self, **_):
            pass

        def analyze(self):
            return {"imports": [{"name": "connect"}], "findings": native}

    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register("import_analyzer", ImportAnalyzer, AnalyzerCategory.METADATA)
    stage = MetadataStage(registry, FakeAdapter(), FakeConfig(), "sample.exe", {})

    output = stage._extract_imports({"results": {}})

    assert output == {
        "imports": [{"name": "connect"}],
        "import_analysis": {"imports": [{"name": "connect"}], "findings": native},
    }
