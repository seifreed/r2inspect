"""Comprehensive tests for r2inspect/schemas/base.py"""

from datetime import datetime

import pytest
from pydantic import ValidationError

from r2inspect.schemas.base import AnalysisResultBase, FileInfoBase


def test_analysis_result_base_creation():
    result = AnalysisResultBase(available=True, analyzer_name="test")
    assert result.available is True
    assert result.analyzer_name == "test"


def test_analysis_result_base_required_fields():
    with pytest.raises(ValidationError):
        AnalysisResultBase()


def test_analysis_result_base_with_error():
    result = AnalysisResultBase(available=False, error="Test error")
    assert result.available is False
    assert result.error == "Test error"


def test_analysis_result_base_execution_time():
    result = AnalysisResultBase(
        available=True, execution_time=1.5, analyzer_name="test"
    )
    assert result.execution_time == 1.5


def test_analysis_result_base_negative_execution_time():
    with pytest.raises(ValidationError):
        AnalysisResultBase(available=True, execution_time=-1.0)


def test_analysis_result_base_zero_execution_time():
    result = AnalysisResultBase(available=True, execution_time=0.0)
    assert result.execution_time == 0.0


def test_analysis_result_base_timestamp_default():
    result = AnalysisResultBase(available=True)
    assert isinstance(result.timestamp, datetime)


def test_analysis_result_base_timestamp_custom():
    custom_time = datetime(2024, 1, 1, 12, 0, 0)
    result = AnalysisResultBase(available=True, timestamp=custom_time)
    assert result.timestamp == custom_time


def test_analysis_result_base_analyzer_name_normalization():
    result = AnalysisResultBase(available=True, analyzer_name="PE_ANALYZER")
    assert result.analyzer_name == "pe_analyzer"


def test_analysis_result_base_analyzer_name_strip():
    result = AnalysisResultBase(available=True, analyzer_name="  test  ")
    assert result.analyzer_name == "test"


def test_analysis_result_base_analyzer_name_none():
    result = AnalysisResultBase(available=True, analyzer_name=None)
    assert result.analyzer_name is None


def test_analysis_result_base_model_dump_safe():
    result = AnalysisResultBase(
        available=True,
        execution_time=1.0,
        analyzer_name="test",
        error=None,
    )
    data = result.model_dump_safe()
    assert isinstance(data, dict)
    assert "error" not in data
    assert data["available"] is True


def test_analysis_result_base_model_dump_safe_with_error():
    result = AnalysisResultBase(available=False, error="Test error")
    data = result.model_dump_safe()
    assert data["error"] == "Test error"


def test_analysis_result_base_to_json():
    result = AnalysisResultBase(available=True, analyzer_name="test")
    json_str = result.to_json()
    assert isinstance(json_str, str)
    assert "available" in json_str
    assert "true" in json_str


def test_analysis_result_base_to_json_timestamp():
    result = AnalysisResultBase(available=True)
    json_str = result.to_json()
    assert "timestamp" in json_str


def test_analysis_result_base_extra_fields_ignored():
    result = AnalysisResultBase(
        available=True, analyzer_name="test", unknown_field="value"
    )
    assert not hasattr(result, "unknown_field")


def test_analysis_result_base_validate_assignment():
    result = AnalysisResultBase(available=True, execution_time=1.0)
    result.execution_time = 2.0
    assert result.execution_time == 2.0


def test_analysis_result_base_validate_assignment_invalid():
    result = AnalysisResultBase(available=True, execution_time=1.0)
    with pytest.raises(ValidationError):
        result.execution_time = -1.0


def test_file_info_base_creation():
    file_info = FileInfoBase(
        file_size=1024, file_path="/tmp/test.exe", file_extension="exe"
    )
    assert file_info.file_size == 1024
    assert file_info.file_path == "/tmp/test.exe"
    assert file_info.file_extension == "exe"


def test_file_info_base_defaults():
    file_info = FileInfoBase()
    assert file_info.file_size is None
    assert file_info.file_path is None
    assert file_info.file_extension is None


def test_file_info_base_negative_size():
    with pytest.raises(ValidationError):
        FileInfoBase(file_size=-1)


def test_file_info_base_zero_size():
    file_info = FileInfoBase(file_size=0)
    assert file_info.file_size == 0


def test_file_info_base_extension_normalization():
    file_info = FileInfoBase(file_extension="EXE")
    assert file_info.file_extension == "exe"


def test_file_info_base_extension_strip_dot():
    file_info = FileInfoBase(file_extension=".exe")
    assert file_info.file_extension == "exe"


def test_file_info_base_extension_multiple_dots():
    file_info = FileInfoBase(file_extension="...exe")
    assert file_info.file_extension == "exe"


def test_file_info_base_extension_with_spaces():
    file_info = FileInfoBase(file_extension="  .exe  ")
    assert file_info.file_extension == "exe"


def test_file_info_base_extension_none():
    file_info = FileInfoBase(file_extension=None)
    assert file_info.file_extension is None


def test_analysis_result_base_json_encoders():
    custom_time = datetime(2024, 1, 1, 12, 0, 0)
    result = AnalysisResultBase(available=True, timestamp=custom_time)
    json_str = result.to_json()
    assert "2024-01-01" in json_str


def test_analysis_result_base_execution_time_validation():
    result = AnalysisResultBase(available=True)
    assert result.execution_time is None


def test_analysis_result_base_all_fields():
    custom_time = datetime(2024, 1, 1, 12, 0, 0)
    result = AnalysisResultBase(
        available=True,
        error=None,
        execution_time=1.5,
        timestamp=custom_time,
        analyzer_name="test_analyzer",
    )
    assert result.available is True
    assert result.error is None
    assert result.execution_time == 1.5
    assert result.timestamp == custom_time
    assert result.analyzer_name == "test_analyzer"


def test_file_info_base_all_fields():
    file_info = FileInfoBase(
        file_size=2048, file_path="/usr/bin/test", file_extension="bin"
    )
    assert file_info.file_size == 2048
    assert file_info.file_path == "/usr/bin/test"
    assert file_info.file_extension == "bin"


def test_analysis_result_base_model_dump_exclude_none():
    result = AnalysisResultBase(available=True, analyzer_name="test")
    data = result.model_dump_safe()
    assert "error" not in data
    assert "execution_time" not in data


def test_file_info_base_serialization():
    file_info = FileInfoBase(file_size=1024, file_extension="exe")
    data = file_info.model_dump()
    assert data["file_size"] == 1024
    assert data["file_extension"] == "exe"


def test_analysis_result_base_execution_time_none_validation():
    result = AnalysisResultBase(available=True, execution_time=None)
    assert result.execution_time is None
