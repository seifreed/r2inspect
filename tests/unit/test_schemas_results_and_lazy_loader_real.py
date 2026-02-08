from __future__ import annotations

from datetime import UTC, datetime, timezone

import pytest

from r2inspect.lazy_loader import LazyAnalyzerLoader, get_global_lazy_loader
from r2inspect.schemas import results as results_schema


def test_results_dataclasses_methods() -> None:
    hashing = results_schema.HashingResult(ssdeep="a", tlsh=" ", simhash="b")
    assert hashing.has_hash("ssdeep") is True
    assert hashing.has_hash("tlsh") is False
    assert hashing.has_hash("missing") is False

    security = results_schema.SecurityFeatures(
        nx=True,
        pie=True,
        canary=True,
        relro="full",
        aslr=True,
        guard_cf=True,
        authenticode=True,
        fortify=True,
        high_entropy_va=True,
    )
    enabled = security.get_enabled_features()
    assert "nx" in enabled
    assert "relro_full" in enabled
    assert security.security_score() == 95

    section = results_schema.SectionInfo(suspicious_indicators=["packed"])
    assert section.is_suspicious() is True

    anti = results_schema.AntiAnalysisResult(anti_debug=True)
    assert anti.has_evasion() is True

    crypto = results_schema.CryptoResult(algorithms=[{"name": "AES"}])
    assert crypto.has_crypto() is True

    indicators = [
        results_schema.Indicator(type="api", description="x", severity="High"),
        results_schema.Indicator(type="api", description="y", severity="Low"),
    ]
    analysis = results_schema.AnalysisResult(
        file_info=results_schema.FileInfo(name="sample", file_type="PE", size=10),
        hashing=hashing,
        security=security,
        imports=[results_schema.ImportInfo(name="CreateFileA")],
        exports=[results_schema.ExportInfo(name="exp")],
        sections=[section],
        strings=["abc"],
        yara_matches=[results_schema.YaraMatch(rule="rule")],
        functions=[results_schema.FunctionInfo(name="main", size=1)],
        anti_analysis=anti,
        packer=results_schema.PackerResult(is_packed=True, packer_type="UPX"),
        crypto=crypto,
        indicators=indicators,
        error="boom",
        execution_time=1.25,
    )
    summary = analysis.summary()
    assert summary["file_name"] == "sample"
    assert summary["is_packed"] is True
    assert summary["has_crypto"] is True
    assert analysis.has_error() is True
    assert analysis.is_suspicious() is True
    assert len(analysis.get_high_severity_indicators()) == 1
    as_dict = analysis.to_dict()
    assert as_dict["file_info"]["name"] == "sample"
    assert "timestamp" in as_dict


def test_results_from_dict_loaders() -> None:
    ts = datetime(2025, 1, 2, tzinfo=UTC).isoformat()
    data = {
        "file_info": {
            "name": "sample",
            "path": "/tmp/sample",
            "size": 12,
            "md5": "m",
            "sha1": "s1",
            "sha256": "s256",
            "file_type": "PE",
            "architecture": "x86",
            "bits": 32,
            "endian": "little",
            "mime_type": "application/octet-stream",
        },
        "hashing": {"ssdeep": "ss", "tlsh": "tt"},
        "security": {"nx": True, "relro": "partial", "aslr": True},
        "imports": [{"name": "CreateFileA", "library": "KERNEL32.dll"}],
        "exports": [{"name": "Export", "address": "0x1"}],
        "sections": [{"name": ".text", "permissions": "r-x", "entropy": 6.5}],
        "strings": ["cmd.exe"],
        "yara_matches": [{"rule": "r", "namespace": "ns"}],
        "functions": [{"name": "main", "address": 1, "size": 10}],
        "anti_analysis": {"anti_vm": True, "techniques": [{"name": "vm"}]},
        "packer": {"is_packed": True, "packer_type": "UPX", "confidence": 80},
        "crypto": {"constants": [{"name": "AES"}]},
        "indicators": [{"type": "api", "description": "x", "severity": "Critical"}],
        "error": "boom",
        "timestamp": ts,
        "execution_time": 2.5,
    }
    result = results_schema.from_dict(data)
    assert result.file_info.name == "sample"
    assert result.hashing.ssdeep == "ss"
    assert result.security.relro == "partial"
    assert result.imports[0].library == "KERNEL32.dll"
    assert result.exports[0].name == "Export"
    assert result.sections[0].name == ".text"
    assert result.strings == ["cmd.exe"]
    assert result.yara_matches[0].rule == "r"
    assert result.functions[0].name == "main"
    assert result.anti_analysis.anti_vm is True
    assert result.packer.is_packed is True
    assert result.crypto.constants
    assert result.indicators[0].severity == "Critical"
    assert result.error == "boom"
    assert result.execution_time == 2.5

    bad_ts = results_schema.from_dict({"timestamp": "not-a-time"})
    assert isinstance(bad_ts.timestamp, datetime)

    dt_ts = datetime(2024, 1, 1)
    dt_result = results_schema.from_dict({"timestamp": dt_ts})
    assert dt_result.timestamp == dt_ts

    strings_only = results_schema.from_dict({"strings": ["a", "b"]})
    assert strings_only.strings == ["a", "b"]


def test_lazy_loader_real() -> None:
    loader = LazyAnalyzerLoader()
    loader.register(
        "pe",
        "r2inspect.modules.pe_analyzer",
        "PEAnalyzer",
        category="format",
        formats={"PE", "PE32"},
    )
    assert loader.is_registered("pe") is True
    assert loader.is_loaded("pe") is False
    cls = loader.get_analyzer_class("pe")
    assert cls is not None
    assert loader.is_loaded("pe") is True

    stats = loader.get_stats()
    assert stats["registered"] == 1
    assert stats["loaded"] == 1

    listed = loader.list_registered()
    assert listed["pe"]["loaded"] is True

    assert loader.unload("pe") is True
    assert loader.is_loaded("pe") is False
    assert loader.unregister("pe") is True
    assert loader.is_registered("pe") is False

    loader.register("pe", "r2inspect.modules.pe_analyzer", "PEAnalyzer", category="format")
    loader.register("elf", "r2inspect.modules.elf_analyzer", "ELFAnalyzer", category="format")
    preloaded = loader.preload_category("format")
    assert preloaded["pe"] is True
    assert preloaded["elf"] is True

    cleared = loader.clear_cache()
    assert cleared >= 0

    with pytest.raises(ImportError):
        loader.register("bad", "r2inspect.no_such_module", "Nope")
        loader.get_analyzer_class("bad")

    with pytest.raises(AttributeError):
        loader.register("bad_attr", "r2inspect.modules.pe_analyzer", "NoSuchClass")
        loader.get_analyzer_class("bad_attr")


def test_global_lazy_loader_singleton() -> None:
    loader1 = get_global_lazy_loader()
    loader2 = get_global_lazy_loader()
    assert loader1 is loader2
