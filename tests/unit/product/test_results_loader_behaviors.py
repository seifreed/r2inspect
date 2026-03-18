from __future__ import annotations

from datetime import UTC, datetime

from r2inspect.schemas.results_loader import from_dict


def test_from_dict_populates_nested_models_from_behavioral_payload() -> None:
    payload = {
        "file_info": {
            "name": "sample.exe",
            "path": "/tmp/sample.exe",
            "size": 100,
            "file_type": "PE",
        },
        "hashing": {"tlsh": "TLSH", "ssdeep": "SSDEEP"},
        "security": {"nx": True, "aslr": True},
        "imports": [{"name": "CreateFileA", "library": "KERNEL32.dll"}],
        "sections": [{"name": ".text", "entropy": 6.5, "permissions": "r-x"}],
        "anti_analysis": {"anti_debug": True, "techniques": [{"name": "IsDebuggerPresent"}]},
        "packer": {"is_packed": True, "packer_type": "UPX", "confidence": 80},
        "crypto": {"algorithms": [{"name": "AES"}]},
        "timestamp": datetime(2026, 1, 2, tzinfo=UTC).isoformat(),
        "execution_time": 1.5,
    }

    result = from_dict(payload)

    assert result.file_info.name == "sample.exe"
    assert result.hashing.tlsh == "TLSH"
    assert result.security.nx is True
    assert result.imports[0].name == "CreateFileA"
    assert result.sections[0].name == ".text"
    assert result.anti_analysis.anti_debug is True
    assert result.packer.packer_type == "UPX"
    assert result.crypto.algorithms == [{"name": "AES"}]
    assert result.execution_time == 1.5


def test_from_dict_keeps_defaults_when_optional_sections_are_missing() -> None:
    result = from_dict({"file_info": {"name": "tiny.bin"}})
    assert result.file_info.name == "tiny.bin"
    assert result.imports == []
    assert result.sections == []
    assert result.error is None
