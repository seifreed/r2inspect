"""Comprehensive tests for r2inspect/schemas/hashing.py"""

import pytest
from pydantic import ValidationError

from r2inspect.schemas.hashing import HashAnalysisResult


def test_hash_analysis_result_creation():
    result = HashAnalysisResult(
        available=True,
        hash_value="3:abc123:def456",
        hash_type="ssdeep",
        method_used="python_library",
        file_size=1024,
    )
    assert result.available is True
    assert result.hash_value == "3:abc123:def456"
    assert result.hash_type == "ssdeep"


def test_hash_analysis_result_required_fields():
    with pytest.raises(ValidationError):
        HashAnalysisResult()


def test_hash_analysis_result_hash_type_required():
    with pytest.raises(ValidationError):
        HashAnalysisResult(available=True)


def test_hash_analysis_result_ssdeep():
    result = HashAnalysisResult(
        available=True, hash_value="test", hash_type="ssdeep"
    )
    assert result.hash_type == "ssdeep"


def test_hash_analysis_result_tlsh():
    result = HashAnalysisResult(
        available=True, hash_value="T1234", hash_type="tlsh"
    )
    assert result.hash_type == "tlsh"


def test_hash_analysis_result_impfuzzy():
    result = HashAnalysisResult(
        available=True, hash_value="fuzzy:hash", hash_type="impfuzzy"
    )
    assert result.hash_type == "impfuzzy"


def test_hash_analysis_result_ccbhash():
    result = HashAnalysisResult(
        available=True, hash_value="ccb123", hash_type="ccbhash"
    )
    assert result.hash_type == "ccbhash"


def test_hash_analysis_result_simhash():
    result = HashAnalysisResult(
        available=True, hash_value="sim123", hash_type="simhash"
    )
    assert result.hash_type == "simhash"


def test_hash_analysis_result_telfhash():
    result = HashAnalysisResult(
        available=True, hash_value="telf123", hash_type="telfhash"
    )
    assert result.hash_type == "telfhash"


def test_hash_analysis_result_invalid_hash_type():
    with pytest.raises(ValidationError):
        HashAnalysisResult(
            available=True, hash_value="test", hash_type="invalid"
        )


def test_hash_analysis_result_hash_type_case_insensitive():
    result = HashAnalysisResult(
        available=True, hash_value="test", hash_type="SSDEEP"
    )
    assert result.hash_type == "ssdeep"


def test_hash_analysis_result_hash_type_strip():
    result = HashAnalysisResult(
        available=True, hash_value="test", hash_type="  tlsh  "
    )
    assert result.hash_type == "tlsh"


def test_hash_analysis_result_method_python_library():
    result = HashAnalysisResult(
        available=True,
        hash_value="test",
        hash_type="ssdeep",
        method_used="python_library",
    )
    assert result.method_used == "python_library"


def test_hash_analysis_result_method_system_binary():
    result = HashAnalysisResult(
        available=True,
        hash_value="test",
        hash_type="ssdeep",
        method_used="system_binary",
    )
    assert result.method_used == "system_binary"


def test_hash_analysis_result_method_r2pipe():
    result = HashAnalysisResult(
        available=True,
        hash_value="test",
        hash_type="ssdeep",
        method_used="r2pipe",
    )
    assert result.method_used == "r2pipe"


def test_hash_analysis_result_method_direct_read():
    result = HashAnalysisResult(
        available=True,
        hash_value="test",
        hash_type="ssdeep",
        method_used="direct_read",
    )
    assert result.method_used == "direct_read"


def test_hash_analysis_result_method_custom():
    result = HashAnalysisResult(
        available=True,
        hash_value="test",
        hash_type="ssdeep",
        method_used="custom_method",
    )
    assert result.method_used == "custom_method"


def test_hash_analysis_result_method_none():
    result = HashAnalysisResult(
        available=True, hash_value="test", hash_type="ssdeep", method_used=None
    )
    assert result.method_used is None


def test_hash_analysis_result_method_case_insensitive():
    result = HashAnalysisResult(
        available=True,
        hash_value="test",
        hash_type="ssdeep",
        method_used="PYTHON_LIBRARY",
    )
    assert result.method_used == "python_library"


def test_hash_analysis_result_file_size_positive():
    result = HashAnalysisResult(
        available=True, hash_value="test", hash_type="ssdeep", file_size=1024
    )
    assert result.file_size == 1024


def test_hash_analysis_result_file_size_zero():
    result = HashAnalysisResult(
        available=True, hash_value="test", hash_type="ssdeep", file_size=0
    )
    assert result.file_size == 0


def test_hash_analysis_result_file_size_negative():
    with pytest.raises(ValidationError):
        HashAnalysisResult(
            available=True,
            hash_value="test",
            hash_type="ssdeep",
            file_size=-1,
        )


def test_hash_analysis_result_file_size_large():
    result = HashAnalysisResult(
        available=True,
        hash_value="test",
        hash_type="ssdeep",
        file_size=1024 * 1024 * 1024,
    )
    assert result.file_size == 1024 * 1024 * 1024


def test_hash_analysis_result_file_size_exceeds_max():
    with pytest.raises(ValidationError):
        HashAnalysisResult(
            available=True,
            hash_value="test",
            hash_type="ssdeep",
            file_size=11 * 1024 * 1024 * 1024,
        )


def test_hash_analysis_result_file_size_none():
    result = HashAnalysisResult(
        available=True, hash_value="test", hash_type="ssdeep", file_size=None
    )
    assert result.file_size is None


def test_hash_analysis_result_is_valid_hash():
    result = HashAnalysisResult(
        available=True, hash_value="3:abc:def", hash_type="ssdeep"
    )
    assert result.is_valid_hash() is True


def test_hash_analysis_result_is_valid_hash_empty():
    result = HashAnalysisResult(
        available=True, hash_value="", hash_type="ssdeep"
    )
    assert result.is_valid_hash() is False


def test_hash_analysis_result_is_valid_hash_none():
    result = HashAnalysisResult(
        available=True, hash_value=None, hash_type="ssdeep"
    )
    assert result.is_valid_hash() is False


def test_hash_analysis_result_is_valid_hash_whitespace():
    result = HashAnalysisResult(
        available=True, hash_value="   ", hash_type="ssdeep"
    )
    assert result.is_valid_hash() is False


def test_hash_analysis_result_is_valid_hash_with_spaces():
    result = HashAnalysisResult(
        available=True, hash_value=" test ", hash_type="ssdeep"
    )
    assert result.is_valid_hash() is True


def test_hash_analysis_result_with_error():
    result = HashAnalysisResult(
        available=False, hash_value=None, hash_type="ssdeep", error="Test error"
    )
    assert result.available is False
    assert result.error == "Test error"


def test_hash_analysis_result_serialization():
    result = HashAnalysisResult(
        available=True,
        hash_value="3:abc:def",
        hash_type="ssdeep",
        method_used="python_library",
        file_size=1024,
    )
    data = result.model_dump()
    assert data["hash_value"] == "3:abc:def"
    assert data["hash_type"] == "ssdeep"
    assert data["file_size"] == 1024


def test_hash_analysis_result_model_dump_safe():
    result = HashAnalysisResult(
        available=True, hash_value="test", hash_type="ssdeep"
    )
    data = result.model_dump_safe()
    assert "hash_value" in data
    assert "error" not in data


def test_hash_analysis_result_to_json():
    result = HashAnalysisResult(
        available=True, hash_value="test", hash_type="ssdeep"
    )
    json_str = result.to_json()
    assert "hash_value" in json_str
    assert "ssdeep" in json_str


def test_hash_analysis_result_all_fields():
    result = HashAnalysisResult(
        available=True,
        hash_value="3:abc:def",
        hash_type="ssdeep",
        method_used="python_library",
        file_size=2048,
        execution_time=0.5,
        analyzer_name="ssdeep_analyzer",
        error=None,
    )
    assert result.available is True
    assert result.hash_value == "3:abc:def"
    assert result.hash_type == "ssdeep"
    assert result.method_used == "python_library"
    assert result.file_size == 2048
    assert result.execution_time == 0.5
    assert result.analyzer_name == "ssdeep_analyzer"


def test_hash_analysis_result_inherited_validation():
    result = HashAnalysisResult(
        available=True, hash_value="test", hash_type="ssdeep"
    )
    with pytest.raises(ValidationError):
        result.execution_time = -1.0


def test_hash_analysis_result_file_size_at_max():
    result = HashAnalysisResult(
        available=True,
        hash_value="test",
        hash_type="ssdeep",
        file_size=10 * 1024 * 1024 * 1024,
    )
    assert result.file_size == 10 * 1024 * 1024 * 1024
