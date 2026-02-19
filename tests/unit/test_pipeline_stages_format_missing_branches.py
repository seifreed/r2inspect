#!/usr/bin/env python3
"""Tests targeting missing coverage branches in pipeline/stages_format.py."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from r2inspect.pipeline.stages_format import (
    FileInfoStage,
    FormatAnalysisStage,
    FormatDetectionStage,
)
from r2inspect.registry.analyzer_registry import AnalyzerRegistry

FIXTURE = Path("samples/fixtures/hello_pe.exe")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class FakeAdapter:
    def __init__(self, bin_info: dict | None = None) -> None:
        self._bin_info = bin_info

    def get_file_info(self) -> dict | None:
        return self._bin_info


class FakeConfig:
    analyze_authenticode: bool = False
    analyze_overlay: bool = False
    analyze_resources: bool = False
    analyze_mitigations: bool = False


def make_context() -> dict[str, Any]:
    return {"options": {}, "results": {}, "metadata": {}}


# ---------------------------------------------------------------------------
# FileInfoStage
# ---------------------------------------------------------------------------


def test_file_info_stage_name_is_file_info():
    stage = FileInfoStage(adapter=FakeAdapter(), filename=str(FIXTURE))
    assert stage.name == "file_info"


def test_file_info_stage_is_not_optional():
    stage = FileInfoStage(adapter=FakeAdapter(), filename=str(FIXTURE))
    assert stage.optional is False


def test_file_info_stage_execute_populates_size_and_name():
    stage = FileInfoStage(adapter=FakeAdapter(), filename=str(FIXTURE))
    result = stage._execute(make_context())
    info = result["file_info"]
    assert info["size"] > 0
    assert info["name"] == FIXTURE.name


def test_file_info_stage_execute_populates_absolute_path():
    stage = FileInfoStage(adapter=FakeAdapter(), filename=str(FIXTURE))
    result = stage._execute(make_context())
    assert FIXTURE.name in result["file_info"]["path"]


def test_file_info_stage_execute_populates_hashes():
    stage = FileInfoStage(adapter=FakeAdapter(), filename=str(FIXTURE))
    result = stage._execute(make_context())
    info = result["file_info"]
    assert any(k in info for k in ("md5", "sha256", "sha1"))


def test_file_info_stage_execute_stores_result_in_context():
    stage = FileInfoStage(adapter=FakeAdapter(), filename=str(FIXTURE))
    context = make_context()
    stage._execute(context)
    assert "file_info" in context["results"]


def test_file_info_stage_execute_with_x86_64_adapter_sets_arch():
    adapter = FakeAdapter(
        bin_info={"bin": {"arch": "x86", "bits": 64, "endian": "little", "format": "pe"}}
    )
    stage = FileInfoStage(adapter=adapter, filename=str(FIXTURE))
    result = stage._execute(make_context())
    assert result["file_info"]["architecture"] == "x86-64"
    assert result["file_info"]["bits"] == 64


def test_file_info_stage_execute_with_x86_32_adapter_sets_arch():
    adapter = FakeAdapter(
        bin_info={"bin": {"arch": "x86", "bits": 32, "endian": "little", "format": "pe"}}
    )
    stage = FileInfoStage(adapter=adapter, filename=str(FIXTURE))
    result = stage._execute(make_context())
    assert result["file_info"]["architecture"] == "x86"


def test_file_info_stage_execute_without_r2_info_omits_arch():
    stage = FileInfoStage(adapter=FakeAdapter(bin_info=None), filename=str(FIXTURE))
    result = stage._execute(make_context())
    assert "architecture" not in result["file_info"]


def test_file_info_stage_execute_populates_enhanced_detection():
    stage = FileInfoStage(adapter=FakeAdapter(), filename=str(FIXTURE))
    result = stage._execute(make_context())
    assert "enhanced_detection" in result["file_info"]


def test_file_info_stage_execute_high_confidence_sets_precise_format():
    stage = FileInfoStage(adapter=FakeAdapter(), filename=str(FIXTURE))
    result = stage._execute(make_context())
    info = result["file_info"]
    if info["enhanced_detection"]["confidence"] > 0.7:
        assert "precise_format" in info
        assert "format_category" in info
        assert "threat_level" in info


# ---------------------------------------------------------------------------
# FormatDetectionStage
# ---------------------------------------------------------------------------


def test_format_detection_stage_name_is_format_detection():
    stage = FormatDetectionStage(adapter=FakeAdapter(), filename=str(FIXTURE))
    assert stage.name == "format_detection"


def test_format_detection_stage_is_not_optional():
    stage = FormatDetectionStage(adapter=FakeAdapter(), filename=str(FIXTURE))
    assert stage.optional is False


def test_format_detection_stage_depends_on_file_info():
    stage = FormatDetectionStage(adapter=FakeAdapter(), filename=str(FIXTURE))
    assert "file_info" in stage.dependencies


def test_format_detection_stage_detects_pe_via_r2():
    adapter = FakeAdapter(bin_info={"bin": {"format": "pe", "arch": "x86", "bits": 32}})
    stage = FormatDetectionStage(adapter=adapter, filename=str(FIXTURE))
    context = make_context()
    result = stage._execute(context)
    assert result["format_detection"]["file_format"] == "PE"
    assert context["metadata"]["file_format"] == "PE"


def test_format_detection_stage_detects_elf_via_r2():
    adapter = FakeAdapter(bin_info={"bin": {"format": "elf64", "arch": "x86", "bits": 64}})
    stage = FormatDetectionStage(adapter=adapter, filename=str(FIXTURE))
    context = make_context()
    result = stage._execute(context)
    assert result["format_detection"]["file_format"] == "ELF"


def test_format_detection_stage_detects_macho_via_r2():
    adapter = FakeAdapter(bin_info={"bin": {"format": "mach064", "arch": "arm", "bits": 64}})
    stage = FormatDetectionStage(adapter=adapter, filename=str(FIXTURE))
    context = make_context()
    result = stage._execute(context)
    assert result["format_detection"]["file_format"] == "Mach-O"


def test_format_detection_stage_falls_back_when_r2_returns_none():
    stage = FormatDetectionStage(adapter=FakeAdapter(bin_info=None), filename=str(FIXTURE))
    context = make_context()
    result = stage._execute(context)
    assert "file_format" in result["format_detection"]


def test_format_detection_stage_falls_back_when_r2_has_no_bin_key():
    adapter = FakeAdapter(bin_info={"other": {}})
    stage = FormatDetectionStage(adapter=adapter, filename=str(FIXTURE))
    context = make_context()
    result = stage._execute(context)
    assert "file_format" in result["format_detection"]


def test_format_detection_stage_creates_metadata_key_if_missing():
    adapter = FakeAdapter(bin_info={"bin": {"format": "pe"}})
    stage = FormatDetectionStage(adapter=adapter, filename=str(FIXTURE))
    context: dict[str, Any] = {"options": {}, "results": {}}
    stage._execute(context)
    assert context["metadata"]["file_format"] == "PE"


def test_detect_via_r2_returns_none_for_unknown_format():
    adapter = FakeAdapter(bin_info={"bin": {"format": "unknown_fmt"}})
    stage = FormatDetectionStage(adapter=adapter, filename=str(FIXTURE))
    assert stage._detect_via_r2() is None


def test_detect_via_enhanced_magic_returns_format_or_none():
    stage = FormatDetectionStage(adapter=FakeAdapter(), filename=str(FIXTURE))
    result = stage._detect_via_enhanced_magic()
    assert result is None or isinstance(result, str)


def test_detect_via_basic_magic_returns_string_or_none():
    stage = FormatDetectionStage(adapter=FakeAdapter(), filename=str(FIXTURE))
    result = stage._detect_via_basic_magic()
    assert result is None or isinstance(result, str)


# ---------------------------------------------------------------------------
# FormatAnalysisStage
# ---------------------------------------------------------------------------


def test_format_analysis_stage_name_is_format_analysis():
    registry = AnalyzerRegistry()
    stage = FormatAnalysisStage(
        registry=registry,
        adapter=FakeAdapter(),
        config=FakeConfig(),
        filename=str(FIXTURE),
    )
    assert stage.name == "format_analysis"


def test_format_analysis_stage_is_optional():
    registry = AnalyzerRegistry()
    stage = FormatAnalysisStage(
        registry=registry,
        adapter=FakeAdapter(),
        config=FakeConfig(),
        filename=str(FIXTURE),
    )
    assert stage.optional is True


def test_format_analysis_stage_depends_on_format_detection():
    registry = AnalyzerRegistry()
    stage = FormatAnalysisStage(
        registry=registry,
        adapter=FakeAdapter(),
        config=FakeConfig(),
        filename=str(FIXTURE),
    )
    assert "format_detection" in stage.dependencies


def test_format_analysis_stage_condition_true_for_pe():
    registry = AnalyzerRegistry()
    stage = FormatAnalysisStage(
        registry=registry,
        adapter=FakeAdapter(),
        config=FakeConfig(),
        filename=str(FIXTURE),
    )
    assert stage.should_execute({"metadata": {"file_format": "PE"}}) is True


def test_format_analysis_stage_condition_false_for_unknown():
    registry = AnalyzerRegistry()
    stage = FormatAnalysisStage(
        registry=registry,
        adapter=FakeAdapter(),
        config=FakeConfig(),
        filename=str(FIXTURE),
    )
    assert stage.should_execute({"metadata": {"file_format": "Unknown"}}) is False


def test_format_analysis_stage_execute_returns_empty_when_no_pe_analyzer():
    registry = AnalyzerRegistry()
    stage = FormatAnalysisStage(
        registry=registry,
        adapter=FakeAdapter(),
        config=FakeConfig(),
        filename=str(FIXTURE),
    )
    context = make_context()
    context["metadata"]["file_format"] = "PE"
    assert stage._execute(context) == {}


def test_format_analysis_stage_execute_returns_empty_when_no_elf_analyzer():
    registry = AnalyzerRegistry()
    stage = FormatAnalysisStage(
        registry=registry,
        adapter=FakeAdapter(),
        config=FakeConfig(),
        filename=str(FIXTURE),
    )
    context = make_context()
    context["metadata"]["file_format"] = "ELF"
    assert stage._execute(context) == {}


def test_format_analysis_stage_execute_returns_empty_when_no_macho_analyzer():
    registry = AnalyzerRegistry()
    stage = FormatAnalysisStage(
        registry=registry,
        adapter=FakeAdapter(),
        config=FakeConfig(),
        filename=str(FIXTURE),
    )
    context = make_context()
    context["metadata"]["file_format"] = "Mach-O"
    assert stage._execute(context) == {}


def test_format_analysis_stage_execute_returns_empty_for_unknown_format():
    registry = AnalyzerRegistry()
    stage = FormatAnalysisStage(
        registry=registry,
        adapter=FakeAdapter(),
        config=FakeConfig(),
        filename=str(FIXTURE),
    )
    context = make_context()
    context["metadata"]["file_format"] = "PDF"
    assert stage._execute(context) == {}


def test_format_analysis_stage_execute_with_pe_analyzer_registered():
    class FakePEAnalyzer:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def analyze(self) -> dict[str, Any]:
            return {"sections": [], "imports": []}

    registry = AnalyzerRegistry()
    registry.register(
        name="pe_analyzer",
        analyzer_class=FakePEAnalyzer,
        category="format",
        file_formats={"PE"},
        required=False,
    )
    stage = FormatAnalysisStage(
        registry=registry,
        adapter=FakeAdapter(),
        config=FakeConfig(),
        filename=str(FIXTURE),
    )
    context = make_context()
    context["metadata"]["file_format"] = "PE"
    result = stage._execute(context)
    assert "pe_info" in result
    assert context["results"]["pe_info"]["sections"] == []


def test_format_analysis_stage_execute_with_elf_analyzer_registered():
    class FakeELFAnalyzer:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def analyze(self) -> dict[str, Any]:
            return {"symbols": []}

    registry = AnalyzerRegistry()
    registry.register(
        name="elf_analyzer",
        analyzer_class=FakeELFAnalyzer,
        category="format",
        file_formats={"ELF"},
        required=False,
    )
    stage = FormatAnalysisStage(
        registry=registry,
        adapter=FakeAdapter(),
        config=FakeConfig(),
        filename=str(FIXTURE),
    )
    context = make_context()
    context["metadata"]["file_format"] = "ELF"
    result = stage._execute(context)
    assert "elf_info" in result
    assert context["results"]["elf_info"]["symbols"] == []


def test_format_analysis_stage_execute_with_macho_analyzer_registered():
    class FakeMachoAnalyzer:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def analyze(self) -> dict[str, Any]:
            return {"load_commands": []}

    registry = AnalyzerRegistry()
    registry.register(
        name="macho_analyzer",
        analyzer_class=FakeMachoAnalyzer,
        category="format",
        file_formats={"MACHO"},
        required=False,
    )
    stage = FormatAnalysisStage(
        registry=registry,
        adapter=FakeAdapter(),
        config=FakeConfig(),
        filename=str(FIXTURE),
    )
    context = make_context()
    context["metadata"]["file_format"] = "Mach-O"
    result = stage._execute(context)
    assert "macho_info" in result
    assert context["results"]["macho_info"]["load_commands"] == []


def test_run_optional_pe_analyzers_skips_when_config_flag_false():
    class FakePEAnalyzer:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def analyze(self) -> dict[str, Any]:
            return {}

    class FakeResourceAnalyzer:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def analyze(self) -> dict[str, Any]:
            return {"count": 3}

    registry = AnalyzerRegistry()
    registry.register(
        name="pe_analyzer",
        analyzer_class=FakePEAnalyzer,
        category="format",
        file_formats={"PE"},
        required=False,
    )
    registry.register(
        name="resource_analyzer",
        analyzer_class=FakeResourceAnalyzer,
        category="format",
        file_formats={"PE"},
        required=False,
    )
    config = FakeConfig()
    config.analyze_resources = False
    stage = FormatAnalysisStage(
        registry=registry,
        adapter=FakeAdapter(),
        config=config,
        filename=str(FIXTURE),
    )
    context = make_context()
    context["metadata"]["file_format"] = "PE"
    result = stage._execute(context)
    assert "resources" not in result.get("pe_info", {})


def test_run_optional_pe_analyzers_runs_when_config_flag_true():
    class FakePEAnalyzer:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def analyze(self) -> dict[str, Any]:
            return {}

    class FakeResourceAnalyzer:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def analyze(self) -> dict[str, Any]:
            return {"count": 3}

    registry = AnalyzerRegistry()
    registry.register(
        name="pe_analyzer",
        analyzer_class=FakePEAnalyzer,
        category="format",
        file_formats={"PE"},
        required=False,
    )
    registry.register(
        name="resource_analyzer",
        analyzer_class=FakeResourceAnalyzer,
        category="format",
        file_formats={"PE"},
        required=False,
    )
    config = FakeConfig()
    config.analyze_resources = True
    stage = FormatAnalysisStage(
        registry=registry,
        adapter=FakeAdapter(),
        config=config,
        filename=str(FIXTURE),
    )
    context = make_context()
    context["metadata"]["file_format"] = "PE"
    result = stage._execute(context)
    assert result["pe_info"]["resources"] == {"count": 3}
