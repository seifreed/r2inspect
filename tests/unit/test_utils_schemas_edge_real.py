from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from r2inspect.schemas.converters import ResultConverter, dict_to_model, model_to_dict
from r2inspect.schemas.hashing import HashAnalysisResult
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
    YaraMatch,
)
from r2inspect.utils.hashing import calculate_hashes, calculate_imphash, calculate_ssdeep


def test_hashing_utils_edge_cases(tmp_path: Path) -> None:
    missing = calculate_hashes(str(tmp_path / "missing.bin"))
    assert missing["md5"] == ""

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"hello")
    hashes = calculate_hashes(str(sample))
    assert hashes["md5"]
    assert hashes["sha256"]

    assert calculate_imphash([]) is None
    assert calculate_imphash([{"library": "", "name": ""}]) is None
    imp_hash = calculate_imphash([{"library": "KERNEL32.dll", "name": "CreateFileA"}])
    assert imp_hash is not None

    ssdeep_hash = calculate_ssdeep(str(sample))
    assert ssdeep_hash is None or isinstance(ssdeep_hash, str)


def test_hash_schema_validators() -> None:
    result = HashAnalysisResult(
        available=True,
        hash_value="abc",
        hash_type="SSDEEP",
        method_used="python_library",
        file_size=100,
    )
    assert result.hash_type == "ssdeep"
    assert result.is_valid_hash() is True

    with pytest.raises(ValueError):
        HashAnalysisResult(available=True, hash_type="bad", hash_value="x")

    with pytest.raises(ValueError):
        HashAnalysisResult(
            available=True, hash_type="ssdeep", file_size=10 * 1024 * 1024 * 1024 + 1
        )

    custom = HashAnalysisResult(
        available=True,
        hash_value="abc",
        hash_type="tlsh",
        method_used="custom_method",
    )
    assert custom.method_used == "custom_method"


def test_result_converter_roundtrip() -> None:
    ResultConverter.register_schema("ssdeep", HashAnalysisResult)
    data = {"available": True, "hash_type": "ssdeep", "hash_value": "x"}
    model = ResultConverter.convert_result("ssdeep", data)
    assert model.hash_type == "ssdeep"
    restored = model_to_dict(model)
    assert restored["hash_type"] == "ssdeep"

    strict_data = {"available": True, "hash_type": "bad", "hash_value": "x"}
    with pytest.raises(ValidationError):
        dict_to_model(strict_data, HashAnalysisResult, strict=True)


def test_results_dataclasses_to_dict() -> None:
    result = AnalysisResult(
        file_info=FileInfo(
            path="/tmp/sample.bin",
            size=123,
            md5="md5",
            sha1="sha1",
            sha256="sha256",
            file_type="PE",
        ),
        hashing=HashingResult(
            ssdeep="ssdeep",
            tlsh="tlsh",
            imphash="imphash",
        ),
        security=SecurityFeatures(aslr=True, nx=False),
        imports=[ImportInfo(library="kernel32.dll", name="CreateFileA")],
        exports=[ExportInfo(name="export", address="0x1000")],
        sections=[
            SectionInfo(
                name=".text",
                virtual_address=4096,
                virtual_size=10,
                raw_size=10,
                entropy=1.0,
                permissions="r-x",
                is_executable=True,
                is_readable=True,
            )
        ],
        strings=["http://example.com"],
        yara_matches=[YaraMatch(rule="rule", tags=["tag"], strings=["$a"])],
        functions=[FunctionInfo(name="func", address="0x2000")],
        anti_analysis=AntiAnalysisResult(anti_vm=True, techniques=[{"name": "vm"}]),
        packer=PackerResult(is_packed=False, packer_type="none", confidence=1),
        crypto=CryptoResult(constants=[{"name": "aes"}]),
        indicators=[Indicator(type="suspicious", description="desc", severity="high")],
        error=None,
        timestamp=datetime(2025, 1, 1),
        execution_time=1.23,
    )
    as_dict = result.to_dict()
    assert as_dict["file_info"]["md5"] == "md5"
    assert as_dict["hashing"]["ssdeep"] == "ssdeep"
    assert as_dict["security"]["aslr"] is True
