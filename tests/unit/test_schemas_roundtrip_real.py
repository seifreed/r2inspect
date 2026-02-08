from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from r2inspect.schemas import results as results_schema
from r2inspect.schemas.base import AnalysisResultBase, FileInfoBase
from r2inspect.schemas.converters import ResultConverter, dict_to_model, model_to_dict
from r2inspect.schemas.hashing import HashAnalysisResult


def _load_expected(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def test_results_roundtrip_from_expected(samples_dir: Path) -> None:
    expected_root = samples_dir / "expected"
    data = _load_expected(expected_root / "hello_pe.json")

    result = results_schema.from_dict(data)
    assert result.file_info.name

    dumped = result.to_dict()
    assert "file_info" in dumped
    assert "hashing" in dumped
    assert "security" in dumped

    assert result.summary()["file_type"]
    assert result.has_error() is False
    assert isinstance(result.is_suspicious(), bool)
    assert isinstance(result.get_high_severity_indicators(), list)


def test_results_roundtrip_full_payload() -> None:
    payload = {
        "file_info": {
            "name": "sample.bin",
            "path": "/tmp/sample.bin",
            "size": 123,
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256",
            "file_type": "PE",
            "architecture": "x86",
            "bits": 32,
            "endian": "little",
            "mime_type": "application/octet-stream",
        },
        "hashing": {
            "ssdeep": "3:abc:def",
            "tlsh": "T1",
            "imphash": "imh",
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
            "relro": "full",
            "aslr": True,
            "seh": True,
            "guard_cf": True,
            "authenticode": True,
            "fortify": True,
            "rpath": True,
            "runpath": True,
            "high_entropy_va": True,
        },
        "imports": [{"name": "CreateFileA", "library": "KERNEL32.dll"}],
        "exports": [{"name": "exported", "address": "0x1000"}],
        "sections": [{"name": ".text", "virtual_address": "0x1000", "virtual_size": 4096}],
        "strings": ["hello"],
        "yara_matches": [{"rule": "demo", "namespace": "default"}],
        "functions": [{"name": "main", "address": "0x2000"}],
        "anti_analysis": {"detects": ["sleep"], "available": True},
        "packer": {"is_packed": True, "packer_type": "UPX"},
        "crypto": {"has_crypto": True, "algorithms": ["AES"]},
        "indicators": [{"category": "evasion", "severity": "High"}],
        "error": None,
        "timestamp": datetime.utcnow().isoformat(),
        "execution_time": 1.23,
    }

    result = results_schema.from_dict(payload)
    dumped = result.to_dict()
    assert dumped["file_info"]["name"] == "sample.bin"
    assert dumped["security"]["relro"] == "full"
    assert dumped["packer"]["is_packed"] is True
    assert dumped["crypto"]["has_crypto"] is True

    assert result.is_suspicious() is True
    assert result.get_high_severity_indicators()


def test_schema_converters_strict_and_relaxed() -> None:
    valid = {
        "available": True,
        "hash_type": "ssdeep",
        "hash_value": "3:abc:def",
        "method_used": "python_library",
        "file_size": 10,
    }
    model = dict_to_model(valid, HashAnalysisResult)
    assert isinstance(model, HashAnalysisResult)
    assert model.is_valid_hash() is True

    data = model_to_dict(model)
    assert data["hash_type"] == "ssdeep"

    invalid = {
        "available": True,
        "hash_type": "invalid",
        "hash_value": "hash",
    }
    with pytest.raises(ValidationError):
        dict_to_model(invalid, HashAnalysisResult, strict=True)

    relaxed = dict_to_model(invalid, HashAnalysisResult, strict=False)
    assert relaxed.hash_type == "invalid"


def test_result_converter_registry() -> None:
    ResultConverter.register_schema("ssdeep", HashAnalysisResult)
    converted = ResultConverter.convert_result(
        "ssdeep",
        {"available": True, "hash_type": "ssdeep", "hash_value": "3:abc:def"},
    )
    assert isinstance(converted, HashAnalysisResult)


def test_schema_base_validators() -> None:
    base = AnalysisResultBase(available=True, analyzer_name=" PE ")
    assert base.analyzer_name == "pe"
    assert "analyzer_name" in base.model_dump_safe()
    assert "available" in base.to_json()

    info = FileInfoBase(file_extension=".EXE")
    assert info.file_extension == "exe"
