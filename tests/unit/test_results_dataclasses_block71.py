from __future__ import annotations

from datetime import datetime

from r2inspect.schemas import results


def test_hashing_result_has_hash():
    hashes = results.HashingResult(ssdeep="  ", tlsh="abc")
    assert hashes.has_hash("ssdeep") is False
    assert hashes.has_hash("tlsh") is True


def test_security_features_scores():
    features = results.SecurityFeatures(nx=True, pie=True, relro="partial")
    enabled = features.get_enabled_features()
    assert "nx" in enabled
    assert "pie" in enabled
    assert "relro_partial" in enabled
    assert 0 < features.security_score() <= 100


def test_analysis_result_to_dict_and_summary():
    res = results.AnalysisResult(
        file_info=results.FileInfo(name="sample.bin", size=123, md5="m", sha256="s"),
        hashing=results.HashingResult(tlsh="t"),
        security=results.SecurityFeatures(nx=True),
        imports=[results.ImportInfo(name="CreateFile")],
        exports=[results.ExportInfo(name="exp")],
        sections=[results.SectionInfo(name=".text", suspicious_indicators=["packed"])],
        strings=["hello"],
        yara_matches=[results.YaraMatch(rule="rule1")],
        functions=[results.FunctionInfo(name="main")],
        anti_analysis=results.AntiAnalysisResult(anti_debug=True),
        packer=results.PackerResult(is_packed=True, packer_type="upx"),
        crypto=results.CryptoResult(algorithms=[{"name": "AES"}]),
        indicators=[results.Indicator(severity="High")],
        execution_time=1.2,
    )

    data = res.to_dict()
    assert data["file_info"]["name"] == "sample.bin"
    assert data["hashing"]["tlsh"] == "t"
    assert data["security"]["nx"] is True
    assert data["timestamp"]
    assert isinstance(data["timestamp"], str)

    assert res.has_error() is False
    assert res.is_suspicious() is True
    summary = res.summary()
    assert summary["file_name"] == "sample.bin"
    assert summary["is_packed"] is True
    assert summary["high_severity_count"] == 1


def test_from_dict_loads_fields():
    ts = datetime.utcnow().isoformat()
    payload = {
        "file_info": {"name": "a", "size": 1, "md5": "m"},
        "hashing": {"ssdeep": "h"},
        "security": {"nx": True, "relro": "full"},
        "imports": [{"name": "f", "ordinal": 2}],
        "exports": [{"name": "e", "ordinal": 3}],
        "sections": [{"name": ".data", "is_writable": True}],
        "strings": ["s1"],
        "yara_matches": [{"rule": "r"}],
        "functions": [{"name": "fn", "address": 1}],
        "anti_analysis": {"anti_vm": True},
        "packer": {"is_packed": False},
        "crypto": {"algorithms": [{"name": "AES"}]},
        "indicators": [{"severity": "Critical"}],
        "error": "boom",
        "timestamp": ts,
        "execution_time": 2.5,
    }

    res = results.from_dict(payload)
    assert res.file_info.name == "a"
    assert res.hashing.ssdeep == "h"
    assert res.security.relro == "full"
    assert len(res.imports) == 1
    assert len(res.exports) == 1
    assert len(res.sections) == 1
    assert res.strings == ["s1"]
    assert len(res.yara_matches) == 1
    assert len(res.functions) == 1
    assert res.anti_analysis.anti_vm is True
    assert res.crypto.has_crypto() is True
    assert res.indicators[0].severity == "Critical"
    assert res.error == "boom"
    assert res.execution_time == 2.5
    assert res.timestamp.isoformat().startswith(ts[:19])
