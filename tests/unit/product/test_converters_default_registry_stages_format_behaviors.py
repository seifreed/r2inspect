from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError

from r2inspect.pipeline.stages_format import FormatDetectionStage
from r2inspect.registry.default_registry import get_minimal_registry
from r2inspect.schemas.base import AnalysisResultBase
from r2inspect.schemas.converters import (
    ResultConverter,
    dict_to_model,
    model_to_dict,
    safe_convert,
    validate_result,
)


class _Model(BaseModel):
    name: str
    size: int = 0


class _Adapter:
    def __init__(self, info=None):
        self._info = info or {}

    def get_file_info(self):
        return self._info


class _DescMagic:
    def __init__(self, value: str):
        self.value = value

    def from_file(self, _path: str) -> str:
        return self.value


class _MagicProvider:
    def __init__(self, desc: str):
        self.desc = desc

    def get_detectors(self):
        return (None, _DescMagic(self.desc))


def test_converters_roundtrip_and_safe_convert_defaults() -> None:
    model = dict_to_model({"name": "demo", "size": 12}, _Model)

    assert model.name == "demo"
    assert model_to_dict(model)["name"] == "demo"
    assert isinstance(ResultConverter.list_registered_schemas(), dict)
    assert safe_convert("bad-input", _Model, default=_Model(name="fallback")).name == "fallback"


def test_converters_strict_and_validation_behaviors() -> None:
    with pytest.raises(ValidationError):
        dict_to_model({"name": "ok", "size": "not_int"}, _Model, strict=True)

    loose = dict_to_model({"name": 123, "size": "bad"}, _Model, strict=False)
    assert loose is not None

    base = AnalysisResultBase(available=True, error=None)
    assert "error" not in model_to_dict(base, exclude_none=True)
    assert validate_result(base) is True

    ResultConverter._schema_registry.clear()
    ResultConverter.register_schema("demo_hash", AnalysisResultBase)
    converted = ResultConverter.convert_result("demo_hash", {"available": True}, strict=True)
    assert converted.analyzer_name == "demo_hash"

    converted_many = ResultConverter.convert_results(
        {
            "demo_hash": {"available": True},
            "unknown_hash": {"available": True},
        },
        strict=False,
    )
    assert set(converted_many) == {"demo_hash", "unknown_hash"}
    assert isinstance(ResultConverter.list_registered_schemas(), dict)

    assert safe_convert(None, _Model, default=_Model(name="fallback")).name == "fallback"


def test_default_registry_minimal_contains_required_analyzers() -> None:
    registry = get_minimal_registry()
    analyzers = registry.list_analyzers()
    assert analyzers
    assert all(item["required"] is True for item in analyzers)


def test_format_detection_uses_magic_provider_and_header_fallback(tmp_path: Path) -> None:
    elf_file = tmp_path / "hello.elf"
    elf_file.write_bytes(b"\x7fELFrest")
    stage = FormatDetectionStage(
        _Adapter(), str(elf_file), magic_detector_provider=_MagicProvider("ELF 64-bit")
    )
    context = {"results": {}, "metadata": {}}
    assert stage._execute(context)["format_detection"]["file_format"] == "ELF"

    pe_file = tmp_path / "hello.exe"
    pe_file.write_bytes(b"MZ\x00\x00rest")
    stage_no_magic = FormatDetectionStage(
        _Adapter(info={}), str(pe_file), magic_detector_provider=None
    )
    assert stage_no_magic._detect_via_basic_magic() == "PE"
