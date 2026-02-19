#!/usr/bin/env python3
"""Branch path tests for r2inspect/schemas/results_models.py covering missing lines."""

from __future__ import annotations

from datetime import datetime

import pytest

from r2inspect.schemas.results_models import (
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
    StringInfo,
    YaraMatch,
    _default_security_features,
)


# ---------------------------------------------------------------------------
# _default_security_features() - line 11
# ---------------------------------------------------------------------------


def test_default_security_features_returns_all_false():
    """_default_security_features creates SecurityFeatures with all False values (line 11)."""
    features = _default_security_features()
    assert features.aslr is False
    assert features.dep is False
    assert features.seh is False
    assert features.guard_cf is False
    assert features.authenticode is False
    assert features.nx is False
    assert features.stack_canary is False
    assert features.canary is False
    assert features.pie is False
    assert features.relro is False
    assert features.rpath is False
    assert features.runpath is False
    assert features.fortify is False
    assert features.high_entropy_va is False


# ---------------------------------------------------------------------------
# FileInfo.to_dict() - line 62
# ---------------------------------------------------------------------------


def test_file_info_to_dict_returns_all_fields():
    """FileInfo.to_dict() serializes all fields to a dictionary (line 62)."""
    fi = FileInfo(
        name="malware.exe",
        path="/samples/malware.exe",
        size=4096,
        md5="abc123",
        sha1="def456",
        sha256="ghi789",
        file_type="PE",
        architecture="x86",
        bits=32,
        endian="little",
        mime_type="application/x-dosexec",
    )
    d = fi.to_dict()
    assert d["name"] == "malware.exe"
    assert d["size"] == 4096
    assert d["bits"] == 32
    assert d["architecture"] == "x86"


def test_file_info_to_dict_defaults():
    """FileInfo.to_dict() works with default-initialized instance."""
    d = FileInfo().to_dict()
    assert d["name"] == ""
    assert d["size"] == 0


# ---------------------------------------------------------------------------
# HashingResult.to_dict() and has_hash() - lines 96, 100-101
# ---------------------------------------------------------------------------


def test_hashing_result_to_dict_contains_all_hash_types():
    """HashingResult.to_dict() returns dict with all hash fields (line 96)."""
    hr = HashingResult(
        ssdeep="3:abc",
        tlsh="T1234",
        imphash="imp123",
        impfuzzy="fuz456",
        ccbhash="ccb789",
        simhash="sim000",
        telfhash="telf111",
        rich_hash="rich222",
        machoc_hash="mac333",
    )
    d = hr.to_dict()
    assert d["ssdeep"] == "3:abc"
    assert d["imphash"] == "imp123"
    assert d["machoc_hash"] == "mac333"


def test_hashing_result_has_hash_true_for_non_empty():
    """HashingResult.has_hash() returns True when hash value is non-empty (lines 100-101)."""
    hr = HashingResult(ssdeep="3:abcdef", tlsh="")
    assert hr.has_hash("ssdeep") is True
    assert hr.has_hash("tlsh") is False


def test_hashing_result_has_hash_whitespace_only():
    """HashingResult.has_hash() returns False for whitespace-only values."""
    hr = HashingResult(ssdeep="   ")
    assert hr.has_hash("ssdeep") is False


def test_hashing_result_has_hash_missing_attribute():
    """HashingResult.has_hash() returns False for non-existent attribute."""
    hr = HashingResult()
    assert hr.has_hash("nonexistent_hash") is False


# ---------------------------------------------------------------------------
# ImportInfo.to_dict() - line 131
# ---------------------------------------------------------------------------


def test_import_info_to_dict_all_fields():
    """ImportInfo.to_dict() serializes all import fields (line 131)."""
    imp = ImportInfo(
        name="VirtualAlloc",
        library="kernel32.dll",
        address="0x7ffe1234",
        ordinal=0,
        category="memory",
        risk_score=75,
        risk_level="High",
        risk_tags=["process_injection", "memory"],
    )
    d = imp.to_dict()
    assert d["name"] == "VirtualAlloc"
    assert d["library"] == "kernel32.dll"
    assert d["risk_score"] == 75
    assert d["risk_tags"] == ["process_injection", "memory"]


# ---------------------------------------------------------------------------
# ExportInfo.to_dict() - line 153
# ---------------------------------------------------------------------------


def test_export_info_to_dict_all_fields():
    """ExportInfo.to_dict() serializes all export fields (line 153)."""
    exp = ExportInfo(name="DllMain", address="0x401000", ordinal=1, size=256)
    d = exp.to_dict()
    assert d["name"] == "DllMain"
    assert d["address"] == "0x401000"
    assert d["ordinal"] == 1
    assert d["size"] == 256


# ---------------------------------------------------------------------------
# YaraMatch.to_dict() - line 177
# ---------------------------------------------------------------------------


def test_yara_match_to_dict_all_fields():
    """YaraMatch.to_dict() serializes rule match data (line 177)."""
    ym = YaraMatch(
        rule="MalwareFamily",
        namespace="custom",
        tags=["malware", "ransomware"],
        meta={"author": "analyst", "description": "Sample rule"},
        strings=[{"offset": 0x1000, "identifier": "$a", "data": "evil"}],
    )
    d = ym.to_dict()
    assert d["rule"] == "MalwareFamily"
    assert d["tags"] == ["malware", "ransomware"]
    assert len(d["strings"]) == 1


# ---------------------------------------------------------------------------
# StringInfo.to_dict() - line 201
# ---------------------------------------------------------------------------


def test_string_info_to_dict_all_fields():
    """StringInfo.to_dict() serializes string info fields (line 201)."""
    si = StringInfo(
        value="http://evil.com",
        address="0x402000",
        length=15,
        encoding="ascii",
        is_suspicious=True,
    )
    d = si.to_dict()
    assert d["value"] == "http://evil.com"
    assert d["is_suspicious"] is True
    assert d["length"] == 15


# ---------------------------------------------------------------------------
# FunctionInfo.to_dict() - line 229
# ---------------------------------------------------------------------------


def test_function_info_to_dict_all_fields():
    """FunctionInfo.to_dict() serializes all function fields (line 229)."""
    fi = FunctionInfo(
        name="sub_401000",
        address=0x401000,
        size=128,
        complexity=5,
        basic_blocks=8,
        call_refs=3,
        data_refs=2,
    )
    d = fi.to_dict()
    assert d["name"] == "sub_401000"
    assert d["address"] == 0x401000
    assert d["complexity"] == 5


# ---------------------------------------------------------------------------
# AntiAnalysisResult.to_dict() and has_evasion() - lines 253, 257
# ---------------------------------------------------------------------------


def test_anti_analysis_result_to_dict_with_techniques():
    """AntiAnalysisResult.to_dict() serializes evasion flags (line 253)."""
    aa = AntiAnalysisResult(
        anti_debug=True,
        anti_vm=False,
        anti_sandbox=True,
        timing_checks=False,
        techniques=[{"type": "RDTSC", "description": "Timing check"}],
    )
    d = aa.to_dict()
    assert d["anti_debug"] is True
    assert d["anti_sandbox"] is True
    assert len(d["techniques"]) == 1


def test_anti_analysis_has_evasion_true_when_any_flag_set():
    """AntiAnalysisResult.has_evasion() returns True if any flag is True (line 257)."""
    aa = AntiAnalysisResult(anti_debug=True)
    assert aa.has_evasion() is True

    aa2 = AntiAnalysisResult(anti_vm=True)
    assert aa2.has_evasion() is True

    aa3 = AntiAnalysisResult(anti_sandbox=True)
    assert aa3.has_evasion() is True

    aa4 = AntiAnalysisResult(timing_checks=True)
    assert aa4.has_evasion() is True


def test_anti_analysis_has_evasion_false_when_no_flags():
    """AntiAnalysisResult.has_evasion() returns False when all flags are False."""
    aa = AntiAnalysisResult()
    assert aa.has_evasion() is False


# ---------------------------------------------------------------------------
# PackerResult.to_dict() - line 279
# ---------------------------------------------------------------------------


def test_packer_result_to_dict_packed():
    """PackerResult.to_dict() serializes packer info (line 279)."""
    pr = PackerResult(
        is_packed=True,
        packer_type="UPX",
        confidence=95,
        indicators=["High entropy", "UPX strings"],
    )
    d = pr.to_dict()
    assert d["is_packed"] is True
    assert d["packer_type"] == "UPX"
    assert d["confidence"] == 95


# ---------------------------------------------------------------------------
# CryptoResult.to_dict() and has_crypto() - lines 299, 303
# ---------------------------------------------------------------------------


def test_crypto_result_to_dict_with_data():
    """CryptoResult.to_dict() serializes crypto findings (line 299)."""
    cr = CryptoResult(
        algorithms=[{"name": "AES", "confidence": 0.9}],
        constants=[{"type": "aes_sbox", "value": "0x63"}],
        functions=["BCryptEncrypt"],
    )
    d = cr.to_dict()
    assert len(d["algorithms"]) == 1
    assert len(d["constants"]) == 1
    assert "BCryptEncrypt" in d["functions"]


def test_crypto_result_has_crypto_true_with_algorithms():
    """CryptoResult.has_crypto() returns True when algorithms list is non-empty (line 303)."""
    cr = CryptoResult(algorithms=[{"name": "AES"}])
    assert cr.has_crypto() is True


def test_crypto_result_has_crypto_true_with_constants():
    """CryptoResult.has_crypto() returns True when constants list is non-empty."""
    cr = CryptoResult(constants=[{"type": "aes_sbox"}])
    assert cr.has_crypto() is True


def test_crypto_result_has_crypto_false_when_empty():
    """CryptoResult.has_crypto() returns False when both lists are empty."""
    cr = CryptoResult()
    assert cr.has_crypto() is False


# ---------------------------------------------------------------------------
# Indicator.to_dict() - line 323
# ---------------------------------------------------------------------------


def test_indicator_to_dict_all_fields():
    """Indicator.to_dict() serializes indicator data (line 323)."""
    ind = Indicator(type="Packer", description="UPX detected", severity="High")
    d = ind.to_dict()
    assert d["type"] == "Packer"
    assert d["description"] == "UPX detected"
    assert d["severity"] == "High"


# ---------------------------------------------------------------------------
# AnalysisResult.to_dict() - lines 376-438
# ---------------------------------------------------------------------------


def test_analysis_result_to_dict_empty():
    """AnalysisResult.to_dict() serializes empty result (lines 376-438)."""
    ar = AnalysisResult()
    d = ar.to_dict()
    assert "file_info" in d
    assert "hashing" in d
    assert "security" in d
    assert "imports" in d
    assert "exports" in d
    assert "sections" in d
    assert "strings" in d
    assert "yara_matches" in d
    assert "functions" in d
    assert "anti_analysis" in d
    assert "packer" in d
    assert "crypto" in d
    assert "indicators" in d
    assert "error" in d
    assert "timestamp" in d
    assert "execution_time" in d


def test_analysis_result_to_dict_with_nested_objects():
    """AnalysisResult.to_dict() serializes nested lists of objects (lines 382-421)."""
    ar = AnalysisResult()
    ar.imports = [ImportInfo(name="VirtualAlloc", library="kernel32.dll")]
    ar.exports = [ExportInfo(name="DllMain")]
    ar.yara_matches = [YaraMatch(rule="TestRule")]
    ar.functions = [FunctionInfo(name="func1", address=0x1000)]
    ar.indicators = [Indicator(type="Packer", severity="High")]
    ar.error = "test error"

    d = ar.to_dict()
    assert len(d["imports"]) == 1
    assert d["imports"][0]["name"] == "VirtualAlloc"
    assert len(d["exports"]) == 1
    assert len(d["yara_matches"]) == 1
    assert d["error"] == "test error"
    assert isinstance(d["timestamp"], str)


def test_analysis_result_to_dict_timestamp_is_iso_string():
    """AnalysisResult.to_dict() converts datetime to ISO format string (line 424)."""
    ar = AnalysisResult(timestamp=datetime(2024, 1, 15, 12, 30, 0))
    d = ar.to_dict()
    assert "2024-01-15" in d["timestamp"]


# ---------------------------------------------------------------------------
# AnalysisResult.has_error() - line 426
# ---------------------------------------------------------------------------


def test_analysis_result_has_error_when_error_set():
    """AnalysisResult.has_error() returns True when error field is set (line 426)."""
    ar = AnalysisResult(error="Something went wrong")
    assert ar.has_error() is True


def test_analysis_result_has_error_false_when_none():
    """AnalysisResult.has_error() returns False when error is None."""
    ar = AnalysisResult()
    assert ar.has_error() is False


# ---------------------------------------------------------------------------
# AnalysisResult.is_suspicious() - line 430
# ---------------------------------------------------------------------------


def test_analysis_result_is_suspicious_with_indicators():
    """AnalysisResult.is_suspicious() returns True when indicators are present (line 430)."""
    ar = AnalysisResult()
    ar.indicators = [Indicator(type="Packer", severity="High")]
    assert ar.is_suspicious() is True


def test_analysis_result_is_suspicious_with_packed():
    """AnalysisResult.is_suspicious() returns True when packer.is_packed is True."""
    ar = AnalysisResult()
    ar.packer = PackerResult(is_packed=True)
    assert ar.is_suspicious() is True


def test_analysis_result_is_suspicious_with_evasion():
    """AnalysisResult.is_suspicious() returns True when anti_analysis detects evasion."""
    ar = AnalysisResult()
    ar.anti_analysis = AntiAnalysisResult(anti_debug=True)
    assert ar.is_suspicious() is True


def test_analysis_result_is_suspicious_false_when_clean():
    """AnalysisResult.is_suspicious() returns False for a clean result."""
    ar = AnalysisResult()
    assert ar.is_suspicious() is False


# ---------------------------------------------------------------------------
# AnalysisResult.get_high_severity_indicators() - line 434
# ---------------------------------------------------------------------------


def test_get_high_severity_indicators_filters_correctly():
    """get_high_severity_indicators() returns only High and Critical indicators (line 434)."""
    ar = AnalysisResult()
    ar.indicators = [
        Indicator(type="Packer", severity="High"),
        Indicator(type="AntiDebug", severity="Critical"),
        Indicator(type="Entropy", severity="Medium"),
        Indicator(type="String", severity="Low"),
    ]
    high = ar.get_high_severity_indicators()
    assert len(high) == 2
    assert all(ind.severity in ("High", "Critical") for ind in high)


def test_get_high_severity_indicators_empty_when_none():
    """get_high_severity_indicators() returns empty list when no high severity indicators."""
    ar = AnalysisResult()
    assert ar.get_high_severity_indicators() == []


# ---------------------------------------------------------------------------
# AnalysisResult.summary() - line 438 (and line 447)
# ---------------------------------------------------------------------------


def test_analysis_result_summary_contains_expected_keys():
    """AnalysisResult.summary() returns dict with expected summary fields (lines 438, 447)."""
    ar = AnalysisResult()
    ar.file_info = FileInfo(name="test.exe", file_type="PE", size=1024, md5="abc", sha256="def")
    ar.packer = PackerResult(is_packed=True, packer_type="UPX")
    ar.indicators = [Indicator(type="Packer", severity="High")]

    s = ar.summary()
    assert s["file_name"] == "test.exe"
    assert s["file_type"] == "PE"
    assert s["is_packed"] is True
    assert s["packer_type"] == "UPX"
    assert s["total_imports"] == 0
    assert s["indicators_count"] == 1
    assert s["high_severity_count"] == 1


def test_analysis_result_summary_packed_type_none_when_not_packed():
    """summary() sets packer_type to None when not packed (line 443)."""
    ar = AnalysisResult()
    ar.file_info = FileInfo(name="clean.exe")
    s = ar.summary()
    assert s["is_packed"] is False
    assert s["packer_type"] is None
