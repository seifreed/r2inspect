from __future__ import annotations

import pytest

from r2inspect.schemas.converters import safe_convert
from r2inspect.schemas.format import FormatAnalysisResult, SectionInfo
from r2inspect.schemas.hashing import HashAnalysisResult


class _BadModel:
    def __init__(self, **_kwargs: object) -> None:
        raise RuntimeError("boom")


def test_format_entropy_and_endian_edges() -> None:
    with pytest.raises(ValueError):
        SectionInfo(name=".text", entropy=9.0)

    result = FormatAnalysisResult(
        available=True,
        format="pe32",
        endian=None,
    )
    assert result.endian is None


def test_hashing_method_and_size_validation() -> None:
    result = HashAnalysisResult(
        available=True,
        hash_type="ssdeep",
        method_used=None,
        file_size=1,
    )
    assert result.method_used is None

    custom = HashAnalysisResult(
        available=True,
        hash_type="tlsh",
        method_used="CustomMethod",
        file_size=2,
    )
    assert custom.method_used == "custommethod"

    with pytest.raises(ValueError):
        HashAnalysisResult(available=True, hash_type="ssdeep", file_size=-1)


def test_safe_convert_variants() -> None:
    converted = safe_convert({"available": True, "hash_type": "ssdeep"}, HashAnalysisResult)
    assert isinstance(converted, HashAnalysisResult)

    assert safe_convert("not-a-dict", HashAnalysisResult, default=None) is None

    assert safe_convert({"a": 1}, _BadModel, default=None) is None
