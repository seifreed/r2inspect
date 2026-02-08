from __future__ import annotations

from datetime import datetime

from r2inspect.schemas import results


def test_results_from_dict_and_summary() -> None:
    data = {
        "file_info": {
            "name": "sample.exe",
            "path": "/tmp/sample.exe",
            "size": 123,
            "md5": "md5",
            "sha256": "sha256",
            "file_type": "PE",
        },
        "hashing": {"ssdeep": "3:abc:def"},
        "security": {"nx": True, "relro": "partial"},
        "imports": [
            {"name": "CreateFileW", "library": "kernel32.dll", "risk_level": "High"},
        ],
        "exports": [{"name": "Exported", "address": "0x401000"}],
        "sections": [
            {"name": ".text", "entropy": 6.0, "is_executable": True},
        ],
        "strings": ["http://example.com"],
        "yara_matches": [{"rule": "test", "namespace": "default"}],
        "functions": [{"name": "main", "address": 0x401000, "size": 10}],
        "anti_analysis": {"anti_debug": True, "techniques": ["IsDebuggerPresent"]},
        "packer": {"is_packed": True, "packer_type": "UPX"},
        "crypto": {"algorithms": ["AES"]},
        "indicators": [
            {"type": "suspicious", "description": "flag", "severity": "High"},
            {"type": "info", "description": "note", "severity": "Low"},
        ],
        "error": "failed",
        "timestamp": datetime.utcnow().isoformat(),
        "execution_time": 1.2,
    }

    result = results.from_dict(data)
    assert result.file_info.name == "sample.exe"
    assert result.hashing.has_hash("ssdeep") is True
    assert result.security.get_enabled_features() == ["nx", "relro_partial"]
    assert result.has_error() is True
    assert result.is_suspicious() is True
    assert len(result.get_high_severity_indicators()) == 1

    summary = result.summary()
    assert summary["file_name"] == "sample.exe"
    assert summary["is_packed"] is True
    assert summary["has_crypto"] is True


def test_results_timestamp_and_defaults() -> None:
    result = results.from_dict({"timestamp": "not-a-timestamp"})
    assert isinstance(result.timestamp, datetime)

    empty = results.from_dict({})
    assert empty.hashing.has_hash("ssdeep") is False
    assert empty.security.security_score() >= 0
    assert empty.to_dict()["error"] is None
