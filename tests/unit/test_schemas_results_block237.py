from datetime import datetime

from r2inspect.schemas import results as results_mod
from r2inspect.schemas.results import (
    AnalysisResult,
    AntiAnalysisResult,
    CryptoResult,
    HashingResult,
    Indicator,
    SectionInfo,
    SecurityFeatures,
)


def test_results_helper_methods():
    hashing = HashingResult(ssdeep="3:abc:def")
    assert hashing.has_hash("ssdeep") is True
    assert hashing.has_hash("tlsh") is False

    security = SecurityFeatures(nx=True, pie=True, relro="partial", guard_cf=True)
    enabled = security.get_enabled_features()
    assert "nx" in enabled
    assert "relro_partial" in enabled
    assert security.security_score() > 0

    section = SectionInfo(name=".text", suspicious_indicators=["packed"])
    assert section.is_suspicious() is True

    anti = AntiAnalysisResult(anti_debug=True)
    assert anti.has_evasion() is True

    crypto = CryptoResult(algorithms=[{"name": "AES"}])
    assert crypto.has_crypto() is True


def test_analysis_result_summary_and_flags():
    result = AnalysisResult()
    result.file_info.name = "sample.exe"
    result.file_info.file_type = "PE"
    result.file_info.size = 123
    result.file_info.md5 = "abc"
    result.file_info.sha256 = "def"
    result.packer.is_packed = True
    result.packer.packer_type = "UPX"
    result.crypto.algorithms.append({"name": "AES"})
    result.anti_analysis.anti_vm = True
    result.indicators.append(Indicator(type="Packer", description="packed", severity="High"))

    summary = result.summary()
    assert summary["file_name"] == "sample.exe"
    assert summary["is_packed"] is True
    assert summary["has_crypto"] is True
    assert summary["has_evasion"] is True
    assert summary["high_severity_count"] == 1

    assert result.is_suspicious() is True
    assert result.get_high_severity_indicators()[0].severity == "High"

    result.error = "boom"
    assert result.has_error() is True

    payload = result.to_dict()
    assert payload["file_info"]["name"] == "sample.exe"
    assert "timestamp" in payload


def test_from_dict_and_load_helpers():
    data = {
        "file_info": {
            "name": "test.bin",
            "path": "/tmp/test.bin",
            "size": 10,
            "md5": "m",
            "sha1": "s1",
            "sha256": "s256",
            "file_type": "ELF",
            "architecture": "x64",
            "bits": 64,
            "endian": "little",
            "mime_type": "application/octet-stream",
        },
        "hashing": {"ssdeep": "hash"},
        "security": {"nx": True, "relro": "full"},
        "imports": [{"name": "printf", "library": "libc"}],
        "exports": [{"name": "main", "address": "0x1000"}],
        "sections": [{"name": ".text", "is_executable": True}],
        "strings": ["hello"],
        "yara_matches": [{"rule": "TestRule", "tags": ["tag"]}],
        "functions": [{"name": "fcn", "address": 1, "size": 2}],
        "anti_analysis": {"anti_vm": True, "techniques": [{"name": "vm"}]},
        "packer": {"is_packed": True, "packer_type": "UPX", "confidence": 80},
        "crypto": {"algorithms": [{"name": "AES"}], "constants": [{"v": 1}]},
        "indicators": [{"type": "Anti-VM", "description": "vm", "severity": "High"}],
        "error": None,
        "timestamp": datetime.utcnow().isoformat(),
        "execution_time": 1.23,
    }

    result = results_mod.from_dict(data)
    assert result.file_info.name == "test.bin"
    assert result.hashing.ssdeep == "hash"
    assert result.security.nx is True
    assert result.imports[0].name == "printf"
    assert result.exports[0].name == "main"
    assert result.sections[0].name == ".text"
    assert result.strings == ["hello"]
    assert result.yara_matches[0].rule == "TestRule"
    assert result.functions[0].name == "fcn"
    assert result.anti_analysis.anti_vm is True
    assert result.packer.is_packed is True
    assert result.crypto.has_crypto() is True
    assert result.indicators[0].severity == "High"
    assert result.execution_time == 1.23

    bad_result = AnalysisResult()
    results_mod._load_timestamp(bad_result, {"timestamp": "bad"})
    assert isinstance(bad_result.timestamp, datetime)

    results_mod._load_execution_time(bad_result, {"execution_time": 0.5})
    assert bad_result.execution_time == 0.5
