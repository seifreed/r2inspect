from __future__ import annotations

import pytest
from pydantic import ValidationError

from r2inspect.schemas import converters
from r2inspect.schemas.base import AnalysisResultBase, FileInfoBase


@pytest.mark.unit
def test_analysis_result_base_validators() -> None:
    result = AnalysisResultBase(available=True, execution_time=1.5, analyzer_name=" Pe ")
    assert result.analyzer_name == "pe"

    with pytest.raises(ValidationError):
        AnalysisResultBase(available=True, execution_time=-1)


@pytest.mark.unit
def test_file_info_extension_normalization() -> None:
    info = FileInfoBase(file_extension=".EXE")
    assert info.file_extension == "exe"


@pytest.mark.unit
def test_dict_to_model_strict_and_non_strict() -> None:
    data = {"available": True, "analyzer_name": "pe"}
    result = converters.dict_to_model(data, AnalysisResultBase)
    assert result.available is True

    with pytest.raises(ValidationError):
        converters.dict_to_model({}, AnalysisResultBase, strict=True)

    loose = converters.dict_to_model({}, AnalysisResultBase, strict=False)
    assert isinstance(loose, AnalysisResultBase)


@pytest.mark.unit
def test_result_converter_registry_and_conversion() -> None:
    converters.ResultConverter.register_schema("base", AnalysisResultBase)
    schema = converters.ResultConverter.get_schema("base")
    assert schema is AnalysisResultBase

    model = converters.ResultConverter.convert_result("base", {"available": True})
    assert model.available is True

    results = converters.ResultConverter.convert_results({"base": {"available": True}})
    assert "base" in results


@pytest.mark.unit
def test_safe_convert_and_validate_result() -> None:
    assert converters.safe_convert(None, AnalysisResultBase) is None

    model = AnalysisResultBase(available=True)
    assert converters.safe_convert(model, AnalysisResultBase) is model

    data = {"available": True}
    converted = converters.safe_convert(data, AnalysisResultBase)
    assert isinstance(converted, AnalysisResultBase)

    assert converters.safe_convert("not a dict", AnalysisResultBase) is None

    assert converters.validate_result(model) is True
