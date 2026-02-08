from __future__ import annotations

import pytest
from pydantic import ValidationError

from r2inspect.schemas.converters import (
    ResultConverter,
    dict_to_model,
    safe_convert,
    validate_result,
)
from r2inspect.schemas.format import FormatAnalysisResult, SectionInfo
from r2inspect.schemas.hashing import HashAnalysisResult


def test_converters_strict_and_non_strict() -> None:
    data = {"available": True, "hash_type": "bad"}
    model = dict_to_model(data, HashAnalysisResult, strict=False)
    assert model.hash_type == "bad"

    with pytest.raises(ValidationError):
        dict_to_model(data, HashAnalysisResult, strict=True)

    converted = ResultConverter.convert_results({"hash": None}, strict=False)
    assert converted["hash"] is None

    assert safe_convert("bad", HashAnalysisResult) is None

    invalid = HashAnalysisResult.model_construct(available=True, hash_type="bad")
    assert validate_result(invalid) is False

    with pytest.raises(ValidationError):
        HashAnalysisResult(available=True, hash_type="ssdeep", file_size=11 * 1024 * 1024 * 1024)


def test_format_schema_permissions_and_helpers() -> None:
    section = SectionInfo(name=".text", is_executable=True, is_writable=False, is_readable=True)
    assert section.has_permission("x") is True
    assert section.has_permission("w") is False

    with pytest.raises(ValidationError):
        SectionInfo(name=" ", entropy=1.0)

    with pytest.raises(ValidationError):
        SectionInfo(name=".text", entropy=9.0)

    with pytest.raises(ValidationError):
        FormatAnalysisResult(available=True, format="bad")

    with pytest.raises(ValidationError):
        FormatAnalysisResult(available=True, format="PE32", bits=16)

    with pytest.raises(ValidationError):
        FormatAnalysisResult(available=True, format="PE32", endian="weird")

    result = FormatAnalysisResult(
        available=True,
        format="ELF64",
        bits=64,
        sections=[SectionInfo(name=".text", is_executable=True)],
    )
    assert result.is_elf() is True
    assert result.is_64bit() is True
