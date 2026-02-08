from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from r2inspect.schemas.base import AnalysisResultBase, FileInfoBase


def test_analysis_result_base_validators():
    result = AnalysisResultBase(
        available=True,
        execution_time=0.1,
        analyzer_name=" PE ",
    )
    assert result.analyzer_name == "pe"

    with pytest.raises(ValueError):
        AnalysisResultBase(available=True, execution_time=-1.0, analyzer_name="pe")


def test_model_dump_safe_excludes_none():
    result = AnalysisResultBase(available=True, analyzer_name=None)
    dumped = result.model_dump_safe()
    assert "analyzer_name" not in dumped


def test_file_info_extension_normalization():
    info = FileInfoBase(file_extension=" ..EXE ")
    assert info.file_extension == "exe"

    info2 = FileInfoBase(file_extension=None)
    assert info2.file_extension is None

    # Ensure timestamp default is set
    result = AnalysisResultBase(available=True)
    assert isinstance(result.timestamp, datetime)
    assert result.timestamp >= datetime.utcnow() - timedelta(seconds=5)
