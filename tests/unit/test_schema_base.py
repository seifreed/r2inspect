from datetime import datetime, timedelta

import pytest

from r2inspect.schemas.base import AnalysisResultBase, FileInfoBase


def test_analysis_result_base_validators():
    result = AnalysisResultBase(available=True, execution_time=1.0, analyzer_name=" PE ")
    assert result.analyzer_name == "pe"
    assert result.execution_time == 1.0
    assert result.model_dump_safe()["available"] is True


def test_analysis_result_base_rejects_negative_execution_time():
    with pytest.raises(ValueError):
        AnalysisResultBase(available=True, execution_time=-1.0)


def test_analysis_result_timestamp_default():
    before = datetime.utcnow() - timedelta(seconds=5)
    result = AnalysisResultBase(available=True)
    assert result.timestamp is not None
    assert result.timestamp >= before


def test_file_info_extension_normalization():
    info = FileInfoBase(file_extension=".ExE")
    assert info.file_extension == "exe"
