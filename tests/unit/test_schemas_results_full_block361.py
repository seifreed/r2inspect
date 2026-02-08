from __future__ import annotations

from datetime import datetime

from r2inspect.schemas import results as results_module
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


def test_results_dataclasses_methods_and_summary() -> None:
    file_info = FileInfo(
        name="sample.bin",
        path="/tmp/sample.bin",
        size=123,
        md5="md5",
        sha256="sha256",
        file_type="PE",
        architecture="x86",
        bits=64,
        endian="little",
        mime_type="application/octet-stream",
    )
    hashing = HashingResult(ssdeep="hash", tlsh="", imphash="imphash")
    security = SecurityFeatures(nx=True, pie=True, relro="full", aslr=True, guard_cf=True)
    imports = [
        ImportInfo(
            name="CreateFileA",
            library="KERNEL32.dll",
            address="0x1000",
            ordinal=1,
            category="file",
            risk_score=90,
            risk_level="High",
            risk_tags=["file"],
        )
    ]
    exports = [ExportInfo(name="ExportedFunc", address="0x2000", ordinal=5, size=12)]
    sections = [
        SectionInfo(
            name=".text",
            virtual_address=0x1000,
            raw_size=1024,
            entropy=6.5,
            permissions="r-x",
            is_executable=True,
            suspicious_indicators=["packed"],
        )
    ]
    strings = ["hello", "world"]
    yara_matches = [YaraMatch(rule="TestRule", namespace="default")]
    functions = [FunctionInfo(name="func", address=0x3000, size=10, complexity=2)]
    anti_analysis = AntiAnalysisResult(anti_debug=True)
    packer = PackerResult(is_packed=True, packer_type="UPX", confidence=90)
    crypto = CryptoResult(algorithms=[{"name": "AES"}], constants=[{"name": "CONST"}])
    indicators = [
        Indicator(type="Anti-Debug", description="Detected", severity="High"),
        Indicator(type="Packer", description="Detected", severity="Low"),
    ]

    result = AnalysisResult(
        file_info=file_info,
        hashing=hashing,
        security=security,
        imports=imports,
        exports=exports,
        sections=sections,
        strings=strings,
        yara_matches=yara_matches,
        functions=functions,
        anti_analysis=anti_analysis,
        packer=packer,
        crypto=crypto,
        indicators=indicators,
        error="boom",
        execution_time=1.23,
    )

    data = result.to_dict()
    assert data["file_info"]["name"] == "sample.bin"
    assert result.has_error()
    assert result.is_suspicious()
    assert result.get_high_severity_indicators()[0].severity == "High"
    summary = result.summary()
    assert summary["file_name"] == "sample.bin"
    assert summary["is_packed"] is True
    assert summary["has_crypto"] is True
    assert summary["has_evasion"] is True
    assert summary["security_score"] >= 0

    assert hashing.has_hash("ssdeep") is True
    assert hashing.has_hash("tlsh") is False
    assert security.get_enabled_features()
    assert security.security_score() > 0
    assert sections[0].is_suspicious() is True
    assert crypto.has_crypto() is True
    assert anti_analysis.has_evasion() is True


def test_results_from_dict_and_loaders() -> None:
    ts = datetime.utcnow()
    payload = {
        "file_info": {
            "name": "f.bin",
            "path": "/tmp/f.bin",
            "size": 1,
            "md5": "m",
            "sha1": "s1",
            "sha256": "s2",
            "file_type": "ELF",
            "architecture": "x86",
            "bits": 64,
            "endian": "little",
            "mime_type": "application/octet-stream",
        },
        "hashing": {
            "ssdeep": "ss",
            "tlsh": "tl",
            "imphash": "imph",
            "impfuzzy": "impf",
            "ccbhash": "ccb",
            "simhash": "sim",
            "telfhash": "telf",
            "rich_hash": "rich",
            "machoc_hash": "machoc",
        },
        "security": {
            "nx": True,
            "pie": True,
            "canary": True,
            "relro": "partial",
            "aslr": True,
            "seh": True,
            "guard_cf": False,
            "authenticode": False,
            "fortify": True,
            "rpath": True,
            "runpath": True,
            "high_entropy_va": True,
        },
        "imports": [
            {
                "name": "open",
                "library": "libc",
                "address": "0x1",
                "ordinal": 2,
                "category": "file",
                "risk_score": 10,
                "risk_level": "Low",
                "risk_tags": ["file"],
            }
        ],
        "exports": [{"name": "exp", "address": "0x2", "ordinal": 1, "size": 4}],
        "sections": [
            {
                "name": ".text",
                "virtual_address": 1,
                "virtual_size": 2,
                "raw_size": 3,
                "entropy": 4.2,
                "permissions": "r-x",
                "is_executable": True,
                "is_writable": False,
                "is_readable": True,
                "suspicious_indicators": [],
            }
        ],
        "strings": ["a", "b"],
        "yara_matches": [
            {
                "rule": "rule",
                "namespace": "default",
                "tags": ["t"],
                "meta": {"k": "v"},
                "strings": [{"offset": 0, "data": "abc"}],
            }
        ],
        "functions": [
            {
                "name": "f",
                "address": 3,
                "size": 4,
                "complexity": 5,
                "basic_blocks": 1,
                "call_refs": 2,
                "data_refs": 3,
            }
        ],
        "anti_analysis": {
            "anti_debug": True,
            "anti_vm": False,
            "anti_sandbox": True,
            "timing_checks": True,
            "techniques": [{"name": "t"}],
        },
        "packer": {"is_packed": True, "packer_type": "UPX", "confidence": 90},
        "crypto": {
            "algorithms": [{"name": "AES"}],
            "constants": [{"name": "CONST"}],
            "functions": ["f"],
        },
        "indicators": [{"type": "Anti-Debug", "description": "desc", "severity": "Critical"}],
        "error": "err",
        "timestamp": ts.isoformat(),
        "execution_time": 2.5,
    }

    result = from_dict(payload)

    assert result.file_info.name == "f.bin"
    assert result.hashing.ssdeep == "ss"
    assert result.security.relro == "partial"
    assert result.imports[0].name == "open"
    assert result.exports[0].name == "exp"
    assert result.sections[0].name == ".text"
    assert result.strings == ["a", "b"]
    assert result.yara_matches[0].rule == "rule"
    assert result.functions[0].name == "f"
    assert result.anti_analysis.anti_sandbox is True
    assert result.packer.is_packed is True
    assert result.crypto.has_crypto() is True
    assert result.indicators[0].severity == "Critical"
    assert result.error == "err"
    assert result.execution_time == 2.5
    assert isinstance(result.timestamp, datetime)

    # Loaders with missing keys should be no-ops
    empty = from_dict({})
    assert empty.file_info.name == ""
    assert empty.hashing.ssdeep == ""

    # Timestamp loader accepts datetime
    direct = AnalysisResult()
    results_module._load_timestamp(direct, {"timestamp": ts})
    assert direct.timestamp == ts

    # Invalid timestamp leaves default
    default_ts = direct.timestamp
    results_module._load_timestamp(direct, {"timestamp": "bad"})
    assert direct.timestamp == default_ts


def test_string_info_to_dict_and_flags() -> None:
    info = StringInfo(value="test", address="0x0", length=4, encoding="ascii", is_suspicious=True)
    data = info.to_dict()
    assert data["value"] == "test"
