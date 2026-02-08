from __future__ import annotations

import importlib
from datetime import datetime

import pytest

import r2inspect.schemas as schemas
from r2inspect.schemas.base import AnalysisResultBase, FileInfoBase
from r2inspect.schemas.results import (
    ExportInfo,
    FunctionInfo,
    ImportInfo,
    Indicator,
    SectionInfo,
    StringInfo,
    YaraMatch,
    from_dict,
)
from r2inspect.schemas.security import SecurityGrade, SecurityScore


def test_schemas_init_exports() -> None:
    schemas_mod = importlib.import_module("r2inspect.schemas")
    assert "AnalysisResultBase" in schemas_mod.__all__
    assert schemas_mod.__version__ == "1.0.0"


def test_analysis_result_base_validation_and_dump() -> None:
    result = AnalysisResultBase(available=True, execution_time=0.1, analyzer_name=" Pe ")
    assert result.analyzer_name == "pe"
    assert result.model_dump_safe()["available"] is True

    with pytest.raises(ValueError):
        AnalysisResultBase(available=True, execution_time=-1)

    no_name = AnalysisResultBase(available=True, analyzer_name=None)
    assert no_name.analyzer_name is None

    file_info = FileInfoBase(file_extension=None)
    assert file_info.file_extension is None


def test_security_score_valid() -> None:
    score = SecurityScore(score=1, max_score=2, percentage=50.0, grade=SecurityGrade.B)
    assert score.max_score == 2


def test_results_to_dict_helpers_and_timestamp() -> None:
    assert SectionInfo(name="x").to_dict()["name"] == "x"
    assert SectionInfo(suspicious_indicators=["a"]).is_suspicious() is True
    assert ImportInfo(name="i").to_dict()["name"] == "i"
    assert ExportInfo(name="e").to_dict()["name"] == "e"
    assert YaraMatch(rule="r").to_dict()["rule"] == "r"
    assert StringInfo(value="s").to_dict()["value"] == "s"
    assert FunctionInfo(name="f").to_dict()["name"] == "f"
    assert Indicator(type="t").to_dict()["type"] == "t"

    data = {"timestamp": datetime(2024, 1, 1)}
    loaded = from_dict(data)
    assert loaded.timestamp == datetime(2024, 1, 1)
