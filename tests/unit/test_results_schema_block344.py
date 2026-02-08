from __future__ import annotations

from datetime import datetime

from r2inspect.schemas import results


def _sample_data() -> dict[str, object]:
    return {
        "file_info": {
            "name": "sample.bin",
            "path": "/tmp/sample.bin",
            "size": 123,
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256",
            "file_type": "PE",
            "architecture": "x86_64",
            "bits": 64,
            "endian": "little",
            "mime_type": "application/octet-stream",
        },
        "hashing": {
            "ssdeep": "3:abc:def",
            "tlsh": "T123",
            "imphash": "imp",
            "impfuzzy": "fuzzy",
            "ccbhash": "ccb",
            "simhash": "sim",
            "telfhash": "telf",
            "rich_hash": "rich",
            "machoc_hash": "mach",
        },
        "security": {
            "nx": True,
            "pie": True,
            "canary": True,
            "relro": "partial",
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
                "address": "0x1000",
                "ordinal": 1,
                "category": "file",
                "risk_score": 10,
                "risk_level": "Low",
                "risk_tags": ["file"],
            }
        ],
        "exports": [{"name": "Exported", "address": "0x2000", "ordinal": 2, "size": 10}],
        "sections": [
            {
                "name": ".text",
                "virtual_address": 4096,
                "virtual_size": 8192,
                "raw_size": 4096,
                "entropy": 6.5,
                "permissions": "r-x",
                "is_executable": True,
                "is_writable": False,
                "is_readable": True,
                "suspicious_indicators": ["packed"],
            }
        ],
        "strings": ["http://example.com"],
        "yara_matches": [
            {
                "rule": "test_rule",
                "namespace": "default",
                "tags": ["tag"],
                "meta": {"author": "unit"},
                "strings": [{"identifier": "$a", "offset": 10, "data": "abc"}],
            }
        ],
        "functions": [
            {
                "name": "main",
                "address": 4096,
                "size": 128,
                "complexity": 3,
                "basic_blocks": 2,
                "call_refs": 1,
                "data_refs": 0,
            }
        ],
        "anti_analysis": {
            "anti_debug": True,
            "anti_vm": False,
            "anti_sandbox": False,
            "timing_checks": True,
            "techniques": [{"name": "IsDebuggerPresent"}],
        },
        "packer": {
            "is_packed": True,
            "packer_type": "UPX",
            "confidence": 90,
            "indicators": ["UPX0"],
        },
        "crypto": {
            "algorithms": [{"name": "AES"}],
            "constants": [{"name": "RC4"}],
            "functions": ["CryptEncrypt"],
        },
        "indicators": [
            {"type": "Packer", "description": "Packed", "severity": "High"},
            {"type": "Anti-Debug", "description": "Anti-debug", "severity": "Low"},
        ],
        "error": "boom",
        "timestamp": "2026-01-01T00:00:00",
        "execution_time": 1.5,
    }


def test_results_from_dict_full_and_methods() -> None:
    data = _sample_data()
    result = results.from_dict(data)

    assert result.file_info.name == "sample.bin"
    assert result.hashing.has_hash("ssdeep") is True
    assert result.security.get_enabled_features()
    assert result.security.security_score() > 0
    result.security.relro = "full"
    assert result.security.security_score() > 0
    assert result.sections[0].is_suspicious() is True
    assert result.anti_analysis.has_evasion() is True
    assert result.packer.is_packed is True
    assert result.crypto.has_crypto() is True

    assert result.has_error() is True
    assert result.is_suspicious() is True
    assert len(result.get_high_severity_indicators()) == 1

    summary = result.summary()
    assert summary["file_name"] == "sample.bin"
    assert summary["packer_type"] == "UPX"

    dumped = result.to_dict()
    assert dumped["file_info"]["name"] == "sample.bin"
    assert dumped["execution_time"] == 1.5

    string_info = results.StringInfo(value="abc", address="0x1000", length=3)
    assert string_info.to_dict()["value"] == "abc"


def test_results_from_dict_minimal_and_timestamp_handling() -> None:
    minimal = results.from_dict({})
    assert minimal.file_info.name == ""
    assert minimal.hashing.has_hash("ssdeep") is False
    assert minimal.is_suspicious() is False

    bad_ts = results.from_dict({"timestamp": "not-a-date"})
    assert isinstance(bad_ts.timestamp, datetime)

    now = datetime.utcnow()
    with_dt = results.from_dict({"timestamp": now})
    assert with_dt.timestamp == now
