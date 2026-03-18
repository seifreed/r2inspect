from __future__ import annotations

from datetime import datetime

from r2inspect.schemas.results_loader import from_dict


def test_from_dict_populates_defaults_for_empty_payload() -> None:
    result = from_dict({})
    assert result.error is None
    assert result.execution_time == 0.0
    assert result.imports == []
    assert result.exports == []
    assert result.sections == []
    assert result.strings == []
    assert result.yara_matches == []
    assert result.functions == []
    assert result.indicators == []


def test_from_dict_maps_structured_sections_imports_and_functions() -> None:
    payload = {
        "file_info": {"name": "test.exe", "size": 1024, "architecture": "x86"},
        "imports": [
            {
                "name": "CreateFile",
                "library": "kernel32.dll",
                "address": "0x1000",
                "ordinal": 0,
                "category": "file",
                "risk_score": 3,
                "risk_level": "Medium",
                "risk_tags": ["file_ops"],
            }
        ],
        "exports": [{"name": "DllMain", "address": "0x2000", "ordinal": 1, "size": 100}],
        "sections": [
            {
                "name": ".text",
                "virtual_address": 0x1000,
                "virtual_size": 0x2000,
                "raw_size": 0x2000,
                "entropy": 6.5,
                "permissions": "r-x",
                "is_executable": True,
                "is_writable": False,
                "is_readable": True,
                "flags": "CODE",
                "suspicious_indicators": [],
            }
        ],
        "functions": [
            {
                "name": "main",
                "address": 0x1000,
                "size": 200,
                "complexity": 5,
                "basic_blocks": 8,
                "call_refs": 3,
                "data_refs": 1,
            }
        ],
    }

    result = from_dict(payload)

    assert result.file_info.name == "test.exe"
    assert result.imports[0].risk_level == "Medium"
    assert result.exports[0].name == "DllMain"
    assert result.sections[0].entropy == 6.5
    assert result.functions[0].basic_blocks == 8


def test_from_dict_handles_timestamp_error_and_optional_sections() -> None:
    result = from_dict(
        {
            "strings": ["hello", "world"],
            "yara_matches": [{"rule": "MalwareRule", "tags": ["malware"]}],
            "anti_analysis": {"anti_debug": True, "techniques": ["IsDebuggerPresent"]},
            "packer": {"is_packed": True, "packer_type": "UPX", "confidence": 90},
            "crypto": {"algorithms": ["AES", "RC4"]},
            "indicators": [
                {"type": "suspicious_import", "description": "Loads kernel32", "severity": "High"}
            ],
            "error": "Analysis failed: file not found",
            "timestamp": "not-a-date",
        }
    )

    assert result.strings == ["hello", "world"]
    assert result.yara_matches[0].rule == "MalwareRule"
    assert result.anti_analysis.anti_debug is True
    assert result.packer.packer_type == "UPX"
    assert result.crypto.algorithms == ["AES", "RC4"]
    assert result.indicators[0].severity == "High"
    assert result.error == "Analysis failed: file not found"
    assert isinstance(result.timestamp, datetime)
