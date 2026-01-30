import pytest

from r2inspect.schemas.hashing import HashAnalysisResult


def test_hash_analysis_validators_and_helpers():
    result = HashAnalysisResult(
        available=True,
        hash_type="SSDEEP",
        hash_value="3:abc:def",
        method_used="python_library",
        file_size=123,
    )
    assert result.hash_type == "ssdeep"
    assert result.is_valid_hash() is True

    with pytest.raises(ValueError):
        HashAnalysisResult(available=True, hash_type="bad")

    with pytest.raises(ValueError):
        HashAnalysisResult(available=True, hash_type="ssdeep", file_size=-1)

    with pytest.raises(ValueError):
        HashAnalysisResult(available=True, hash_type="ssdeep", file_size=11 * 1024**3)
