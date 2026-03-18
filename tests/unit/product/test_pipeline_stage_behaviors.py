from __future__ import annotations

from pathlib import Path
import sys
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tests.helpers import make_stage_context, write_minimal_pe_file

from r2inspect.pipeline.stages_detection import DetectionStage
from r2inspect.pipeline.stages_format import FileInfoStage, FormatDetectionStage
from r2inspect.pipeline.stages_hashing import HashingStage
from r2inspect.registry.analyzer_registry import AnalyzerCategory, AnalyzerRegistry


class FakeAdapter:
    def __init__(self, info: dict[str, Any] | None = None) -> None:
        self._info = info

    def get_file_info(self) -> dict[str, Any] | None:
        return self._info


class FakeConfig:
    pass


class PackerDetector:
    def __init__(self, **_: Any) -> None:
        pass

    def detect(self) -> dict[str, Any]:
        return {"packed": False}


class CompilerDetector:
    def __init__(self, **_: Any) -> None:
        pass

    def detect_compiler(self) -> dict[str, Any]:
        return {"compiler": "gcc"}


class YaraAnalyzer:
    def __init__(self, **_: Any) -> None:
        pass

    def scan(self, _rules=None) -> list[dict[str, str]]:
        return [{"rule": "demo"}]


class TLSHAnalyzer:
    def __init__(self, **_: Any) -> None:
        pass

    def analyze_sections(self) -> dict[str, str]:
        return {"tlsh": "abc"}


class BasicHashAnalyzer:
    def __init__(self, **_: Any) -> None:
        pass

    def analyze(self) -> dict[str, str]:
        return {"ssdeep": "def"}


class CryptoAnalyzer:
    def __init__(self, **_: Any) -> None:
        pass

    def detect(self) -> dict[str, Any]:
        return {"algorithms": ["AES"]}


def test_detection_stage_runs_enabled_detectors_and_yara() -> None:
    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register(
        "packer_detector",
        PackerDetector,
        AnalyzerCategory.DETECTION,
        file_formats={"ANY"},
    )
    registry.register(
        "compiler_detector",
        CompilerDetector,
        AnalyzerCategory.DETECTION,
        file_formats={"ANY"},
    )
    registry.register(
        "yara_analyzer",
        YaraAnalyzer,
        AnalyzerCategory.DETECTION,
        file_formats={"ANY"},
    )

    stage = DetectionStage(
        registry=registry,
        adapter=FakeAdapter(),
        config=FakeConfig(),
        filename="sample.bin",
        options={"detect_packer": True, "detect_crypto": False},
    )
    context = make_stage_context()

    result = stage._execute(context)

    assert result["packer"]["packed"] is False
    assert result["compiler"]["compiler"] == "gcc"
    assert result["yara_matches"][0]["rule"] == "demo"
    assert "crypto" not in result


def test_detection_stage_respects_disabled_packer_and_enabled_crypto() -> None:
    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register(
        "packer_detector",
        PackerDetector,
        AnalyzerCategory.DETECTION,
        file_formats={"ANY"},
    )
    registry.register(
        "crypto_analyzer",
        CryptoAnalyzer,
        AnalyzerCategory.DETECTION,
        file_formats={"ANY"},
    )

    stage = DetectionStage(
        registry=registry,
        adapter=FakeAdapter(),
        config=FakeConfig(),
        filename="sample.bin",
        options={"detect_packer": False, "detect_crypto": True},
    )
    context = make_stage_context()

    result = stage._execute(context)

    assert "packer" not in result
    assert result["crypto"]["algorithms"] == ["AES"]


def test_file_info_stage_collects_basic_metadata_and_hashes(tmp_path: Path) -> None:
    sample = write_minimal_pe_file(tmp_path / "sample.exe")
    stage = FileInfoStage(
        adapter=FakeAdapter({"bin": {"arch": "x86", "bits": 64, "endian": "little"}}),
        filename=str(sample),
    )
    context = make_stage_context()

    result = stage._execute(context)

    info = result["file_info"]
    assert info["name"] == "sample.exe"
    assert info["size"] > 0
    assert info["architecture"] == "x86-64"
    assert "sha256" in info


def test_format_detection_stage_falls_back_to_header_bytes_without_r2_info(
    tmp_path: Path,
) -> None:
    sample = write_minimal_pe_file(tmp_path / "header_only.exe")
    stage = FormatDetectionStage(adapter=FakeAdapter(None), filename=str(sample))
    context = make_stage_context()

    result = stage._execute(context)

    assert result["format_detection"]["file_format"] == "PE"
    assert context["metadata"]["file_format"] == "PE"


def test_format_detection_stage_prefers_r2_format_mapping_when_available() -> None:
    stage = FormatDetectionStage(
        adapter=FakeAdapter({"bin": {"format": "elf64", "arch": "x86", "bits": 64}}),
        filename="sample.elf",
    )
    context = make_stage_context()

    result = stage._execute(context)

    assert result["format_detection"]["file_format"] == "ELF"


def test_hashing_stage_runs_format_supported_hashers() -> None:
    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register("tlsh", TLSHAnalyzer, AnalyzerCategory.HASHING, file_formats={"PE"})
    registry.register("ssdeep", BasicHashAnalyzer, AnalyzerCategory.HASHING, file_formats={"PE"})

    stage = HashingStage(
        registry=registry,
        adapter=FakeAdapter(),
        config=FakeConfig(),
        filename="sample.exe",
    )
    context = make_stage_context()
    context["metadata"]["file_format"] = "PE"

    result = stage._execute(context)

    assert result["tlsh"]["tlsh"] == "abc"
    assert result["ssdeep"]["ssdeep"] == "def"
    assert context["results"]["tlsh"]["tlsh"] == "abc"


def test_hashing_stage_skips_hashers_for_unsupported_format() -> None:
    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register("ssdeep", BasicHashAnalyzer, AnalyzerCategory.HASHING, file_formats={"PE"})

    stage = HashingStage(
        registry=registry,
        adapter=FakeAdapter(),
        config=FakeConfig(),
        filename="sample.elf",
    )
    context = make_stage_context()
    context["metadata"]["file_format"] = "ELF"

    result = stage._execute(context)

    assert result == {}
    assert "ssdeep" not in context["results"]
