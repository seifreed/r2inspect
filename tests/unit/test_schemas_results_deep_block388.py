from __future__ import annotations

from datetime import datetime

from r2inspect.schemas.results import (
    AnalysisResult,
    AntiAnalysisResult,
    CryptoResult,
    ExportInfo,
    FileInfo,
    FunctionInfo,
    HashingResult,
    ImportInfo,
    Indicator,
    PackerResult,
    SectionInfo,
    SecurityFeatures,
    StringInfo,
    YaraMatch,
    from_dict,
)


def _full_payload() -> dict:
    return {
        "file_info": {
            "name": "sample.exe",
            "path": "/tmp/sample.exe",
            "size": 1234,
            "md5": "m",
            "sha1": "s1",
            "sha256": "s256",
            "file_type": "PE32+",
            "architecture": "x86-64",
            "bits": 64,
            "endian": "little",
            "mime_type": "application/octet-stream",
        },
        "hashing": {
            "ssdeep": "ss",
            "tlsh": "tl",
            "imphash": "ih",
            "impfuzzy": "if",
            "ccbhash": "cc",
            "simhash": "sh",
            "telfhash": "te",
            "rich_hash": "rh",
            "machoc_hash": "mh",
        },
        "security": {
            "nx": True,
            "pie": True,
            "canary": True,
            "relro": "full",
            "aslr": True,
            "seh": True,
            "guard_cf": True,
            "authenticode": True,
            "fortify": True,
            "rpath": False,
            "runpath": False,
            "high_entropy_va": True,
        },
        "imports": [
            {
                "name": "CreateFileA",
                "library": "KERNEL32.dll",
                "address": "0x401000",
                "ordinal": 1,
                "category": "file",
                "risk_score": 70,
                "risk_level": "High",
                "risk_tags": ["fs"],
            }
        ],
        "exports": [{"name": "exp", "address": "0x402000", "ordinal": 2, "size": 10}],
        "sections": [
            {
                "name": ".text",
                "virtual_address": 4096,
                "virtual_size": 2048,
                "raw_size": 1024,
                "entropy": 6.0,
                "permissions": "r-x",
                "is_executable": True,
                "is_writable": False,
                "is_readable": True,
                "suspicious_indicators": ["high_entropy"],
            }
        ],
        "strings": ["api", "url"],
        "yara_matches": [
            {
                "rule": "R1",
                "namespace": "default",
                "tags": ["mal"],
                "meta": {"author": "a"},
                "strings": [{"offset": 1, "value": "x"}],
            }
        ],
        "functions": [
            {
                "name": "fcn.main",
                "address": 4096,
                "size": 20,
                "complexity": 2,
                "basic_blocks": 3,
                "call_refs": 1,
                "data_refs": 1,
            }
        ],
        "anti_analysis": {
            "anti_debug": True,
            "anti_vm": True,
            "anti_sandbox": False,
            "timing_checks": True,
            "techniques": [{"name": "rdtsc"}],
        },
        "packer": {
            "is_packed": True,
            "packer_type": "UPX",
            "confidence": 90,
            "indicators": ["sec"],
        },
        "crypto": {
            "algorithms": [{"name": "AES"}],
            "constants": [{"name": "SBOX"}],
            "functions": ["CryptEncrypt"],
        },
        "indicators": [
            {"type": "Anti-Debug", "description": "debug checks", "severity": "High"},
            {"type": "Packer", "description": "packed", "severity": "Low"},
        ],
        "error": None,
        "timestamp": datetime.utcnow().isoformat(),
        "execution_time": 1.5,
    }


def test_results_models_and_helpers() -> None:
    file_info = FileInfo(name="a", path="/tmp/a")
    hashing = HashingResult(ssdeep="x")
    security = SecurityFeatures(nx=True, relro="partial")
    section = SectionInfo(name=".text", suspicious_indicators=["x"])
    imp = ImportInfo(name="f")
    exp = ExportInfo(name="e")
    yara = YaraMatch(rule="R")
    string = StringInfo(value="v")
    func = FunctionInfo(name="main")
    anti = AntiAnalysisResult(anti_debug=True)
    packer = PackerResult(is_packed=True)
    crypto = CryptoResult(algorithms=[{"name": "AES"}])
    indicator = Indicator(type="T", severity="Critical")

    assert file_info.to_dict()["name"] == "a"
    assert hashing.has_hash("ssdeep") is True
    assert hashing.has_hash("tlsh") is False
    assert "nx" in security.get_enabled_features()
    assert any(x.startswith("relro_") for x in security.get_enabled_features())
    assert security.security_score() > 0
    assert section.is_suspicious() is True
    assert imp.to_dict()["name"] == "f"
    assert exp.to_dict()["name"] == "e"
    assert yara.to_dict()["rule"] == "R"
    assert string.to_dict()["value"] == "v"
    assert func.to_dict()["name"] == "main"
    assert anti.has_evasion() is True
    assert packer.to_dict()["is_packed"] is True
    assert crypto.has_crypto() is True
    assert indicator.to_dict()["severity"] == "Critical"


def test_analysis_result_to_dict_summary_and_from_dict_roundtrip() -> None:
    payload = _full_payload()
    result = from_dict(payload)

    assert isinstance(result, AnalysisResult)
    assert result.file_info.name == "sample.exe"
    assert result.security.security_score() >= 50
    assert result.is_suspicious() is True
    assert result.has_error() is False
    assert len(result.get_high_severity_indicators()) == 1

    data = result.to_dict()
    assert data["file_info"]["name"] == "sample.exe"
    assert data["hashing"]["ssdeep"] == "ss"
    assert data["anti_analysis"]["anti_debug"] is True
    assert data["packer"]["packer_type"] == "UPX"
    assert isinstance(data["timestamp"], str)

    summary = result.summary()
    assert summary["file_name"] == "sample.exe"
    assert summary["is_packed"] is True
    assert summary["has_crypto"] is True
    assert summary["has_evasion"] is True
    assert summary["high_severity_count"] == 1


def test_from_dict_partial_and_invalid_timestamp() -> None:
    partial = from_dict({"timestamp": "not-a-date", "execution_time": 0.2})
    assert isinstance(partial, AnalysisResult)
    assert partial.execution_time == 0.2

    dt = datetime.utcnow()
    partial2 = from_dict({"timestamp": dt, "error": "boom"})
    assert partial2.timestamp == dt
    assert partial2.has_error() is True

    empty = from_dict({})
    assert empty.file_info.name == ""
    assert empty.security.security_score() == 0
    assert empty.summary()["total_imports"] == 0
