"""Unit tests for domain/entities.py."""

from __future__ import annotations

from r2inspect.domain.entities import (
    ExportInfo,
    FileInfo,
    HashingResult,
    ImportInfo,
)


def test_file_info_to_dict() -> None:
    info = FileInfo(
        name="test.exe",
        path="/path/to/test.exe",
        size=1024,
        md5="abc123",
        sha1="def456",
        sha256="ghi789",
        file_type="PE32",
        architecture="x86",
        bits=32,
        endian="little",
        mime_type="application/octet-stream",
    )
    result = info.to_dict()
    assert result["name"] == "test.exe"
    assert result["size"] == 1024
    assert result["architecture"] == "x86"


def test_file_info_defaults() -> None:
    info = FileInfo()
    assert info.name == ""
    assert info.size == 0
    assert info.md5 == ""


def test_hashing_result_to_dict() -> None:
    result = HashingResult(
        ssdeep="3:abc:def",
        tlsh="abcd1234",
        imphash="hash1",
    )
    d = result.to_dict()
    assert d["ssdeep"] == "3:abc:def"
    assert d["tlsh"] == "abcd1234"


def test_hashing_result_has_hash_true() -> None:
    result = HashingResult(ssdeep="3:abc:def")
    assert result.has_hash("ssdeep") is True


def test_hashing_result_has_hash_false_empty() -> None:
    result = HashingResult()
    assert result.has_hash("ssdeep") is False


def test_hashing_result_has_hash_false_whitespace() -> None:
    result = HashingResult(ssdeep="   ")
    assert result.has_hash("ssdeep") is False


def test_import_info_to_dict() -> None:
    info = ImportInfo(
        name="CreateFile",
        library="kernel32.dll",
        address="0x1000",
        ordinal=1,
        category="filesystem",
        risk_score=50,
        risk_level="Medium",
        risk_tags=["suspicious"],
    )
    d = info.to_dict()
    assert d["name"] == "CreateFile"
    assert d["library"] == "kernel32.dll"
    assert d["risk_score"] == 50


def test_import_info_defaults() -> None:
    info = ImportInfo()
    assert info.name == ""
    assert info.risk_tags == []


def test_export_info_to_dict() -> None:
    info = ExportInfo(
        name="ExportedFunc",
        address="0x2000",
    )
    d = info.to_dict()
    assert d["name"] == "ExportedFunc"
    assert d["address"] == "0x2000"


def test_export_info_defaults() -> None:
    info = ExportInfo()
    assert info.name == ""
    assert info.address == ""
