"""Branch-path coverage for r2inspect/schemas/hashing.py."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from r2inspect.schemas.hashing import HashAnalysisResult


# ---------------------------------------------------------------------------
# validate_hash_type (lines 52-56)
# ---------------------------------------------------------------------------


def test_validate_hash_type_accepted_ssdeep():
    result = HashAnalysisResult(available=True, hash_type="ssdeep")
    assert result.hash_type == "ssdeep"


def test_validate_hash_type_accepted_tlsh():
    result = HashAnalysisResult(available=True, hash_type="tlsh")
    assert result.hash_type == "tlsh"


def test_validate_hash_type_accepted_impfuzzy():
    result = HashAnalysisResult(available=True, hash_type="impfuzzy")
    assert result.hash_type == "impfuzzy"


def test_validate_hash_type_accepted_ccbhash():
    result = HashAnalysisResult(available=True, hash_type="ccbhash")
    assert result.hash_type == "ccbhash"


def test_validate_hash_type_accepted_simhash():
    result = HashAnalysisResult(available=True, hash_type="simhash")
    assert result.hash_type == "simhash"


def test_validate_hash_type_accepted_telfhash():
    result = HashAnalysisResult(available=True, hash_type="telfhash")
    assert result.hash_type == "telfhash"


def test_validate_hash_type_uppercase_normalized():
    result = HashAnalysisResult(available=True, hash_type="SSDEEP")
    assert result.hash_type == "ssdeep"


def test_validate_hash_type_with_surrounding_whitespace_stripped():
    result = HashAnalysisResult(available=True, hash_type="  tlsh  ")
    assert result.hash_type == "tlsh"


def test_validate_hash_type_invalid_raises_validation_error():
    with pytest.raises(ValidationError) as exc_info:
        HashAnalysisResult(available=True, hash_type="sha256")
    assert "hash_type" in str(exc_info.value).lower() or "sha256" in str(exc_info.value)


def test_validate_hash_type_empty_string_raises_validation_error():
    with pytest.raises(ValidationError):
        HashAnalysisResult(available=True, hash_type="")


# ---------------------------------------------------------------------------
# validate_method_used – None branch (lines 62-63)
# ---------------------------------------------------------------------------


def test_validate_method_used_none_passes_through():
    result = HashAnalysisResult(available=True, hash_type="ssdeep", method_used=None)
    assert result.method_used is None


# ---------------------------------------------------------------------------
# validate_method_used – known methods normalized (lines 65-72)
# ---------------------------------------------------------------------------


def test_validate_method_used_python_library_normalized():
    result = HashAnalysisResult(available=True, hash_type="ssdeep", method_used="python_library")
    assert result.method_used == "python_library"


def test_validate_method_used_system_binary_normalized():
    result = HashAnalysisResult(available=True, hash_type="ssdeep", method_used="system_binary")
    assert result.method_used == "system_binary"


def test_validate_method_used_r2pipe_normalized():
    result = HashAnalysisResult(available=True, hash_type="ssdeep", method_used="r2pipe")
    assert result.method_used == "r2pipe"


def test_validate_method_used_direct_read_normalized():
    result = HashAnalysisResult(available=True, hash_type="ssdeep", method_used="direct_read")
    assert result.method_used == "direct_read"


def test_validate_method_used_uppercase_normalized_to_lowercase():
    result = HashAnalysisResult(available=True, hash_type="ssdeep", method_used="R2PIPE")
    assert result.method_used == "r2pipe"


def test_validate_method_used_unknown_method_allowed_and_normalized():
    result = HashAnalysisResult(available=True, hash_type="ssdeep", method_used="custom_method")
    assert result.method_used == "custom_method"


def test_validate_method_used_whitespace_stripped():
    result = HashAnalysisResult(available=True, hash_type="ssdeep", method_used="  r2pipe  ")
    assert result.method_used == "r2pipe"


# ---------------------------------------------------------------------------
# validate_file_size (lines 78-83)
# ---------------------------------------------------------------------------


def test_validate_file_size_none_passes_through():
    result = HashAnalysisResult(available=True, hash_type="ssdeep", file_size=None)
    assert result.file_size is None


def test_validate_file_size_zero_is_valid():
    result = HashAnalysisResult(available=True, hash_type="ssdeep", file_size=0)
    assert result.file_size == 0


def test_validate_file_size_positive_value_valid():
    result = HashAnalysisResult(available=True, hash_type="ssdeep", file_size=4096)
    assert result.file_size == 4096


def test_validate_file_size_negative_raises_validation_error():
    with pytest.raises(ValidationError):
        HashAnalysisResult(available=True, hash_type="ssdeep", file_size=-1)


def test_validate_file_size_exceeds_10gb_raises_validation_error():
    with pytest.raises(ValidationError):
        HashAnalysisResult(
            available=True,
            hash_type="ssdeep",
            file_size=11 * 1024 * 1024 * 1024,
        )


def test_validate_file_size_exactly_10gb_is_valid():
    limit = 10 * 1024 * 1024 * 1024
    result = HashAnalysisResult(available=True, hash_type="ssdeep", file_size=limit)
    assert result.file_size == limit


# ---------------------------------------------------------------------------
# is_valid_hash (line 92)
# ---------------------------------------------------------------------------


def test_is_valid_hash_returns_true_for_non_empty_hash_value():
    result = HashAnalysisResult(available=True, hash_type="ssdeep", hash_value="3:abc:def")
    assert result.is_valid_hash() is True


def test_is_valid_hash_returns_false_for_none_hash_value():
    result = HashAnalysisResult(available=True, hash_type="ssdeep", hash_value=None)
    assert result.is_valid_hash() is False


def test_is_valid_hash_returns_false_for_empty_string():
    result = HashAnalysisResult(available=True, hash_type="ssdeep", hash_value="")
    assert result.is_valid_hash() is False


def test_is_valid_hash_returns_false_for_whitespace_only():
    result = HashAnalysisResult(available=True, hash_type="ssdeep", hash_value="   ")
    assert result.is_valid_hash() is False


def test_is_valid_hash_returns_true_for_hash_with_surrounding_spaces():
    result = HashAnalysisResult(available=True, hash_type="ssdeep", hash_value=" abc ")
    assert result.is_valid_hash() is True


def test_is_valid_hash_returns_true_for_single_char_hash():
    result = HashAnalysisResult(available=True, hash_type="ssdeep", hash_value="x")
    assert result.is_valid_hash() is True
