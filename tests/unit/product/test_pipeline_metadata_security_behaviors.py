from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tests.helpers import FakeAdapter, FakeConfig, make_stage_context

from r2inspect.pipeline.stages_metadata import MetadataStage
from r2inspect.pipeline.stages_security import SecurityStage
from r2inspect.registry.analyzer_registry import AnalyzerCategory, AnalyzerRegistry


class SectionAnalyzer:
    def __init__(self, **_: Any) -> None:
        pass

    def analyze_sections(self) -> list[dict[str, str]]:
        return [{"name": ".text"}]


class ImportAnalyzer:
    def __init__(self, **_: Any) -> None:
        pass

    def get_imports(self) -> list[dict[str, str]]:
        return [{"name": "CreateFileA"}]


class FunctionAnalyzer:
    def __init__(self, **_: Any) -> None:
        pass

    def analyze_functions(self) -> dict[str, int]:
        return {"count": 1}


class PEAnalyzer:
    def __init__(self, **_: Any) -> None:
        pass

    def get_security_features(self) -> dict[str, bool]:
        return {"nx": True, "aslr": True}


class MitigationAnalyzer:
    def __init__(self, **_: Any) -> None:
        pass

    def analyze(self) -> dict[str, bool]:
        return {"stack_canary": True}


def test_metadata_stage_extracts_registered_metadata_and_respects_options() -> None:
    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register("section_analyzer", SectionAnalyzer, AnalyzerCategory.METADATA)
    registry.register("import_analyzer", ImportAnalyzer, AnalyzerCategory.METADATA)
    registry.register("function_analyzer", FunctionAnalyzer, AnalyzerCategory.METADATA)

    stage = MetadataStage(
        registry=registry,
        adapter=FakeAdapter({"bin": {"format": "pe"}}),
        config=FakeConfig(),
        filename="sample.exe",
        options={"analyze_functions": False},
    )
    context = make_stage_context()

    result = stage.execute(context)

    assert result["sections"][0]["name"] == ".text"
    assert result["imports"][0]["name"] == "CreateFileA"
    assert "functions" not in result


def test_security_stage_merges_pe_security_and_mitigations_for_pe() -> None:
    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register("pe_analyzer", PEAnalyzer, AnalyzerCategory.SECURITY)
    registry.register("exploit_mitigation", MitigationAnalyzer, AnalyzerCategory.SECURITY)

    stage = SecurityStage(
        registry=registry,
        adapter=FakeAdapter(),
        config=FakeConfig(),
        filename="sample.exe",
    )
    context = make_stage_context()
    context["metadata"]["file_format"] = "PE"

    result = stage.execute(context)

    assert result["security"]["nx"] is True
    assert result["security"]["stack_canary"] is True


def test_security_stage_runs_only_mitigations_for_non_pe_formats() -> None:
    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register("exploit_mitigation", MitigationAnalyzer, AnalyzerCategory.SECURITY)

    stage = SecurityStage(
        registry=registry,
        adapter=FakeAdapter(),
        config=FakeConfig(),
        filename="sample.elf",
    )
    context = make_stage_context()
    context["metadata"]["file_format"] = "ELF"

    result = stage.execute(context)

    assert result["security"]["stack_canary"] is True
    assert "nx" not in result["security"]
