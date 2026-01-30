from datetime import datetime

from r2inspect.schemas.results import from_dict


def test_from_dict_minimal():
    data = {"file_info": {"name": "sample", "size": 1}}
    result = from_dict(data)
    assert result.file_info.name == "sample"
    assert result.file_info.size == 1


def test_from_dict_full_fields():
    payload = {
        "file_info": {
            "name": "sample",
            "path": "/tmp/sample",
            "size": 123,
            "md5": "m",
            "sha1": "s1",
            "sha256": "s2",
            "file_type": "PE",
            "architecture": "x86",
            "bits": 32,
            "endian": "Little",
            "mime_type": "application/octet-stream",
        },
        "hashing": {
            "ssdeep": "ss",
            "tlsh": "tl",
            "imphash": "im",
            "impfuzzy": "if",
            "ccbhash": "cc",
            "simhash": "si",
            "telfhash": "te",
            "rich_hash": "rh",
            "machoc_hash": "mh",
        },
        "security": {"nx": True, "pie": False, "relro": "full"},
        "imports": [
            {
                "name": "CreateFileW",
                "library": "kernel32.dll",
                "address": "0x1",
                "ordinal": 1,
                "category": "file",
                "risk_score": 10,
                "risk_level": "Low",
                "risk_tags": ["tag"],
            }
        ],
        "exports": [{"name": "Export", "address": "0x2", "ordinal": 2, "size": 10}],
        "sections": [
            {
                "name": ".text",
                "virtual_address": 4096,
                "virtual_size": 100,
                "raw_size": 100,
                "entropy": 5.0,
                "permissions": "r-x",
                "is_executable": True,
                "is_writable": False,
                "is_readable": True,
                "suspicious_indicators": [],
            }
        ],
        "strings": ["hello"],
        "yara_matches": [
            {"rule": "rule1", "namespace": "ns", "tags": [], "meta": {}, "strings": []}
        ],
        "functions": [
            {
                "name": "fn",
                "address": 4096,
                "size": 10,
                "complexity": 1,
                "basic_blocks": 1,
                "call_refs": 0,
                "data_refs": 0,
            }
        ],
        "anti_analysis": {
            "anti_debug": True,
            "anti_vm": False,
            "anti_sandbox": False,
            "timing_checks": True,
            "techniques": [],
        },
        "packer": {
            "is_packed": False,
            "packer_type": "",
            "confidence": 0,
            "indicators": [],
        },
        "crypto": {"algorithms": [], "constants": [], "functions": []},
        "indicators": [{"type": "t", "description": "d", "severity": "Low"}],
        "timestamp": datetime.utcnow().isoformat(),
        "execution_time": 1.23,
    }

    result = from_dict(payload)
    assert result.file_info.name == "sample"
    assert result.hashing.ssdeep == "ss"
    assert result.security.nx is True
    assert len(result.imports) == 1
    assert len(result.sections) == 1
    assert result.execution_time == 1.23
