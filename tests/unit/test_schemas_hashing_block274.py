from __future__ import annotations

import pytest
from pydantic import ValidationError

from r2inspect.schemas.hashing import HashAnalysisResult


@pytest.mark.unit
def test_hash_analysis_result_validations() -> None:
    result = HashAnalysisResult(
        available=True,
        hash_value="3:abc:def",
        hash_type="SSDeep",
        method_used="Python_Library",
        file_size=123,
    )
    assert result.hash_type == "ssdeep"
    assert result.method_used == "python_library"
    assert result.is_valid_hash() is True

    with pytest.raises(ValidationError):
        HashAnalysisResult(available=True, hash_type="invalid")

    with pytest.raises(ValidationError):
        HashAnalysisResult(available=True, hash_type="ssdeep", file_size=-1)

    with pytest.raises(ValidationError):
        HashAnalysisResult(available=True, hash_type="ssdeep", file_size=11 * 1024 * 1024 * 1024)


@pytest.mark.unit
def test_hash_analysis_custom_method() -> None:
    result = HashAnalysisResult(
        available=True,
        hash_type="tlsh",
        method_used="custom",
    )
    assert result.method_used == "custom"
    assert result.is_valid_hash() is False
