from __future__ import annotations

from datetime import datetime

from r2inspect.schemas import results as results_schema


def test_results_dataclasses_and_helpers() -> None:
    file_info = results_schema.FileInfo(
        name="sample.bin",
        path="/tmp/sample.bin",
        size=10,
        md5="md5",
        sha1="sha1",
        sha256="sha256",
        file_type="PE",
        architecture="x86",
        bits=32,
        endian="little",
        mime_type="application/octet-stream",
    )

    hashing = results_schema.HashingResult(
        ssdeep="ssdeep",
        tlsh="tlsh",
        imphash="imphash",
        impfuzzy="impfuzzy",
        ccbhash="ccbhash",
        simhash="simhash",
        telfhash="telfhash",
        rich_hash="rich_hash",
        machoc_hash="machoc_hash",
    )
    assert hashing.has_hash("ssdeep") is True
    assert hashing.has_hash("missing") is False

    security = results_schema.SecurityFeatures(
        nx=True,
        pie=True,
        canary=True,
        relro="full",
        aslr=True,
        guard_cf=True,
        seh=True,
        authenticode=True,
        fortify=True,
        high_entropy_va=True,
    )
    enabled = security.get_enabled_features()
    assert "nx" in enabled
    assert "relro_full" in enabled
    assert security.security_score() == 100

    partial_security = results_schema.SecurityFeatures(relro="partial")
    assert partial_security.security_score() == 2

    section = results_schema.SectionInfo(
        name=".text",
        entropy=7.1,
        suspicious_indicators=["packed"],
    )
    assert section.is_suspicious() is True

    assert results_schema.StringInfo(value="s").to_dict()["value"] == "s"

    anti_analysis = results_schema.AntiAnalysisResult(
        anti_debug=True,
        techniques=[{"name": "debug"}],
    )
    assert anti_analysis.has_evasion() is True

    packer = results_schema.PackerResult(is_packed=True, packer_type="UPX", confidence=90)

    crypto = results_schema.CryptoResult(
        algorithms=[{"name": "AES"}],
        constants=[{"name": "SBOX"}],
        functions=["encrypt"],
    )
    assert crypto.has_crypto() is True

    indicator = results_schema.Indicator(type="Packer", description="UPX", severity="High")

    analysis = results_schema.AnalysisResult(
        file_info=file_info,
        hashing=hashing,
        security=security,
        imports=[results_schema.ImportInfo(name="CreateFileA", library="KERNEL32.dll")],
        exports=[results_schema.ExportInfo(name="Export", address="0x1", ordinal=1, size=10)],
        sections=[section],
        strings=["abc"],
        yara_matches=[
            results_schema.YaraMatch(rule="test", namespace="default", tags=["a"], meta={})
        ],
        functions=[results_schema.FunctionInfo(name="main", address=0x1000, size=10)],
        anti_analysis=anti_analysis,
        packer=packer,
        crypto=crypto,
        indicators=[indicator],
        error="boom",
        timestamp=datetime(2020, 1, 1),
        execution_time=1.5,
    )

    analysis_dict = analysis.to_dict()
    assert analysis_dict["file_info"]["name"] == "sample.bin"
    assert analysis.has_error() is True
    assert analysis.is_suspicious() is True
    assert analysis.get_high_severity_indicators()[0].severity == "High"
    summary = analysis.summary()
    assert summary["is_packed"] is True


def test_results_from_dict_full_load() -> None:
    raw = {
        "file_info": {
            "name": "sample.bin",
            "path": "/tmp/sample.bin",
            "size": 10,
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256",
            "file_type": "PE",
            "architecture": "x86",
            "bits": 32,
            "endian": "little",
            "mime_type": "application/octet-stream",
        },
        "hashing": {"ssdeep": "ssdeep"},
        "security": {"nx": True, "relro": "partial"},
        "imports": [{"name": "CreateFileA", "library": "KERNEL32.dll"}],
        "exports": [{"name": "Export", "address": "0x1", "ordinal": 1, "size": 10}],
        "sections": [{"name": ".text", "entropy": 7.1, "permissions": "r-x"}],
        "strings": ["abc"],
        "yara_matches": [{"rule": "test", "namespace": "default", "tags": ["a"], "meta": {}}],
        "functions": [{"name": "main", "address": 4096, "size": 10, "complexity": 1}],
        "anti_analysis": {"anti_debug": True, "techniques": [{"name": "debug"}]},
        "packer": {"is_packed": True, "packer_type": "UPX", "confidence": 90},
        "crypto": {"algorithms": [{"name": "AES"}], "constants": [{"name": "SBOX"}]},
        "indicators": [{"type": "Packer", "description": "UPX", "severity": "High"}],
        "error": "boom",
        "timestamp": datetime(2020, 1, 1).isoformat(),
        "execution_time": 1.5,
    }

    result = results_schema.from_dict(raw)
    assert result.file_info.name == "sample.bin"
    assert result.hashing.ssdeep == "ssdeep"
    assert result.security.relro == "partial"
    assert result.imports[0].name == "CreateFileA"
    assert result.sections[0].permissions == "r-x"
    assert result.indicators[0].severity == "High"


def test_results_from_dict_empty_and_timestamp_edges() -> None:
    result = results_schema.from_dict({})
    assert result.file_info.name == ""

    invalid_ts = results_schema.from_dict({"timestamp": "not-a-timestamp"})
    assert invalid_ts.timestamp is not None

    dt = datetime(2020, 1, 2)
    direct_dt = results_schema.from_dict({"timestamp": dt})
    assert direct_dt.timestamp == dt
