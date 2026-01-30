from __future__ import annotations

from pathlib import Path

import pytest
import r2pipe

from r2inspect.config import Config
from r2inspect.modules.anti_analysis import AntiAnalysisDetector
from r2inspect.modules.authenticode_analyzer import AuthenticodeAnalyzer
from r2inspect.modules.crypto_analyzer import CryptoAnalyzer
from r2inspect.modules.exploit_mitigation_analyzer import ExploitMitigationAnalyzer
from r2inspect.modules.packer_detector import PackerDetector

pytestmark = pytest.mark.requires_r2

PE_FIXTURE = "samples/fixtures/hello_pe.exe"


def _config(tmp_path: Path) -> Config:
    return Config(str(tmp_path / "r2inspect_phase5.json"))


def test_anti_analysis_detector_structure(tmp_path: Path) -> None:
    r2 = r2pipe.open(PE_FIXTURE)
    try:
        detector = AntiAnalysisDetector(r2, _config(tmp_path))
        result = detector.detect()
    finally:
        r2.quit()

    assert isinstance(result["anti_debug"], bool)
    assert isinstance(result["anti_vm"], bool)
    assert isinstance(result["anti_sandbox"], bool)
    assert isinstance(result["evasion_techniques"], list)
    assert isinstance(result["suspicious_apis"], list)
    assert isinstance(result["timing_checks"], bool)
    assert isinstance(result["environment_checks"], list)
    details = result["detection_details"]
    assert isinstance(details["anti_debug_evidence"], list)
    assert isinstance(details["anti_vm_evidence"], list)
    assert isinstance(details["anti_sandbox_evidence"], list)
    assert isinstance(details["timing_evidence"], list)


def test_crypto_analyzer_structure(tmp_path: Path) -> None:
    r2 = r2pipe.open(PE_FIXTURE)
    try:
        analyzer = CryptoAnalyzer(r2, _config(tmp_path))
        result = analyzer.detect()
    finally:
        r2.quit()

    assert isinstance(result["algorithms"], list)
    assert isinstance(result["constants"], list)
    assert isinstance(result["entropy_analysis"], dict)
    assert isinstance(result["suspicious_patterns"], list)


def test_packer_detector_structure(tmp_path: Path) -> None:
    r2 = r2pipe.open(PE_FIXTURE)
    try:
        detector = PackerDetector(r2, _config(tmp_path))
        result = detector.detect()
    finally:
        r2.quit()

    assert isinstance(result["is_packed"], bool)
    assert result["packer_type"] is None or isinstance(result["packer_type"], str)
    assert isinstance(result["confidence"], float)
    assert isinstance(result["indicators"], list)
    assert isinstance(result["entropy_analysis"], dict)
    assert isinstance(result["section_analysis"], dict)


def test_exploit_mitigation_analyzer_structure(tmp_path: Path) -> None:
    r2 = r2pipe.open(PE_FIXTURE)
    try:
        analyzer = ExploitMitigationAnalyzer(r2)
        result = analyzer.analyze()
    finally:
        r2.quit()

    assert isinstance(result.get("mitigations", {}), dict)
    assert isinstance(result.get("dll_characteristics", {}), dict)
    assert isinstance(result.get("load_config", {}), dict)
    assert isinstance(result.get("recommendations", []), list)
    assert isinstance(result.get("vulnerabilities", []), list)
    assert "security_score" in result


def test_authenticode_analyzer_structure(tmp_path: Path) -> None:
    r2 = r2pipe.open(PE_FIXTURE)
    try:
        analyzer = AuthenticodeAnalyzer(r2)
        result = analyzer.analyze()
    finally:
        r2.quit()

    assert isinstance(result["has_signature"], bool)
    assert isinstance(result["signature_valid"], bool)
    assert isinstance(result["certificates"], list)
    assert isinstance(result["errors"], list)
    assert "security_directory" in result
