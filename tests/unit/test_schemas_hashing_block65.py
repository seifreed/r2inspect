from __future__ import annotations

import pytest

from r2inspect.schemas.hashing import HashAnalysisResult


def test_hash_analysis_validators():
    with pytest.raises(ValueError):
        HashAnalysisResult(available=True, hash_type="unknown")

    with pytest.raises(ValueError):
        HashAnalysisResult(available=True, hash_type="ssdeep", file_size=-1)

    with pytest.raises(ValueError):
        HashAnalysisResult(available=True, hash_type="ssdeep", file_size=11 * 1024**3)

    result = HashAnalysisResult(
        available=True,
        hash_type=" TLSH ",
        method_used="PYTHON_LIBRARY",
        hash_value="abc",
        file_size=123,
    )
    assert result.hash_type == "tlsh"
    assert result.method_used == "python_library"
    assert result.is_valid_hash() is True

    custom = HashAnalysisResult(available=True, hash_type="ssdeep", method_used="custom")
    assert custom.method_used == "custom"
    assert custom.is_valid_hash() is False
