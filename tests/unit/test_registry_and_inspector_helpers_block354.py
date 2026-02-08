from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from r2inspect.abstractions.base_analyzer import BaseAnalyzer
from r2inspect.core.inspector_helpers import InspectorExecutionMixin
from r2inspect.core.result_aggregator import ResultAggregator
from r2inspect.registry.analyzer_registry import (
    AnalyzerCategory,
    AnalyzerMetadata,
    AnalyzerRegistry,
)


class DummyAnalyzer(BaseAnalyzer):
    def analyze(self) -> dict[str, Any]:
        return {"available": True, "value": 1}

    def get_category(self) -> str:
        return "metadata"

    def get_supported_formats(self) -> set[str]:
        return {"PE"}

    def get_description(self) -> str:
        return "dummy analyzer"


class StringAnalyzer(BaseAnalyzer):
    def analyze(self) -> dict[str, Any]:
        return {"strings": ["a"]}

    def get_category(self) -> str:
        return "behavioral"

    def extract_strings(self) -> list[str]:
        return ["one", "two"]

    def search_xor(self, search_string: str) -> list[dict[str, Any]]:
        return [{"original_string": search_string, "xor_key": 1}]


class CryptoAnalyzer(BaseAnalyzer):
    def analyze(self) -> dict[str, Any]:
        return {"algorithms": [], "constants": []}

    def get_category(self) -> str:
        return "detection"

    def detect(self) -> dict[str, Any]:
        return {"algorithms": ["AES"], "constants": []}


class PackerDetector(BaseAnalyzer):
    def analyze(self) -> dict[str, Any]:
        return {"is_packed": False}

    def get_category(self) -> str:
        return "detection"

    def detect(self) -> dict[str, Any]:
        return {"is_packed": True, "packer_type": "upx"}


class AdapterStub:
    def __init__(self, fmt: str = "PE") -> None:
        self._fmt = fmt

    def get_file_info(self) -> dict[str, Any]:
        return {"bin": {"format": self._fmt}}


class DummyInspector(InspectorExecutionMixin):
    def __init__(self, registry: AnalyzerRegistry, filename: str) -> None:
        self.adapter = AdapterStub()
        self.config = None
        self.filename = filename
        self.registry = registry
        self._result_aggregator = ResultAggregator()


def test_analyzer_metadata_and_registry(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        AnalyzerMetadata(name="", analyzer_class=DummyAnalyzer, category=AnalyzerCategory.METADATA)

    meta = AnalyzerMetadata(
        name="dummy",
        analyzer_class=DummyAnalyzer,
        category=AnalyzerCategory.METADATA,
        file_formats={"PE"},
        required=True,
        dependencies={"file_info"},
    )
    assert meta.supports_format("pe")
    assert meta.to_dict()["name"] == "dummy"

    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register(
        name="dummy",
        analyzer_class=DummyAnalyzer,
        required=True,
        auto_extract=True,
    )
    assert registry.is_registered("dummy")
    assert registry.get_analyzer_class("dummy") is DummyAnalyzer
    assert registry.get_by_category(AnalyzerCategory.METADATA)["dummy"] is DummyAnalyzer
    assert registry.get_required_analyzers()["dummy"] is DummyAnalyzer
    assert "dummy" in registry.get_analyzers_for_format("PE")

    assert registry.get_dependencies("dummy") == set()
    order = registry.resolve_execution_order(["dummy"])
    assert order == ["dummy"]

    registry.unregister("dummy")
    assert registry.is_registered("dummy") is False

    registry.register(
        name="a",
        analyzer_class=DummyAnalyzer,
        category=AnalyzerCategory.METADATA,
        required=False,
        auto_extract=False,
    )
    registry.register(
        name="b",
        analyzer_class=DummyAnalyzer,
        category="metadata",
        required=False,
        dependencies={"a"},
        auto_extract=False,
    )
    assert registry.resolve_execution_order(["b", "a"]) == ["a", "b"]

    with pytest.raises(ValueError):
        registry.register(name="", analyzer_class=DummyAnalyzer)

    with pytest.raises(ValueError):
        registry._resolve_registration_mode(None, None, None)

    registry.clear()
    assert len(registry) == 0


def test_inspector_helpers_and_aggregator(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x7fELF" + b"\x00" * 32)

    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register("string_analyzer", StringAnalyzer, category="behavioral", auto_extract=False)
    registry.register("crypto_analyzer", CryptoAnalyzer, category="detection", auto_extract=False)
    registry.register("packer_detector", PackerDetector, category="detection", auto_extract=False)
    registry.register("pe_analyzer", DummyAnalyzer, category="metadata", auto_extract=False)

    inspector = DummyInspector(registry, str(sample))
    assert inspector.get_strings() == ["one", "two"]
    assert inspector.search_xor("abc")[0]["original_string"] == "abc"
    assert inspector.detect_crypto()["algorithms"] == ["AES"]
    assert inspector.detect_packer()["packer_type"] == "upx"
    assert inspector.get_pe_info()["value"] == 1

    format_name = inspector._detect_file_format()
    assert format_name in {"PE", "ELF", "Mach-O", "Unknown"}

    analysis_results = {
        "file_info": {"name": "x", "file_type": "PE", "size": 1},
        "security": {"authenticode": False},
        "packer": {"is_packed": True, "packer_type": "upx"},
        "imports": [{"name": "VirtualAlloc"}],
        "yara_matches": [{"rule": "Test"}],
        "sections": [{"entropy": 7.5, "name": ".text"}],
        "crypto": {"matches": [1]},
        "anti_analysis": {"anti_debug": True},
        "functions": {"count": 2},
    }
    indicators = inspector.generate_indicators(analysis_results)
    assert any(item["type"] == "Packer" for item in indicators)

    summary = inspector.generate_executive_summary(analysis_results)
    assert summary["file_overview"]["filename"] == "x"
