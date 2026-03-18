from __future__ import annotations

import json
from pathlib import Path

import pytest
import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.config import Config
from r2inspect.core.pipeline_builder import PipelineBuilder
from r2inspect.factory import create_inspector
from r2inspect.infrastructure.r2_session import R2Session
from r2inspect.pipeline.analysis_pipeline import AnalysisPipeline, AnalysisStage
from r2inspect.pipeline.stages_format import (
    FileInfoStage,
    FormatAnalysisStage,
    FormatDetectionStage,
)
from r2inspect.registry.default_registry import create_default_registry


pytestmark = pytest.mark.requires_r2

FIXTURES = {
    "hello_macho": "samples/fixtures/hello_macho",
    "hello_pe": "samples/fixtures/hello_pe.exe",
    "hello_elf": "samples/fixtures/hello_elf",
}


def _minimal_options() -> dict:
    return {
        "analyze_functions": False,
        "detect_packer": True,
        "detect_crypto": True,
    }


def _build_pipeline(path: str, tmp_path: Path):
    config = Config(str(tmp_path / "r2inspect_phase2.json"))
    registry = create_default_registry()
    r2 = r2pipe.open(path)
    adapter = R2PipeAdapter(r2)
    pipeline = PipelineBuilder(adapter, registry, config, path).build(_minimal_options())
    return pipeline, r2


def _open_adapter(sample: Path) -> tuple[R2Session, R2PipeAdapter]:
    session = R2Session(str(sample))
    size_mb = sample.stat().st_size / (1024 * 1024)
    r2 = session.open(size_mb)
    return session, R2PipeAdapter(r2)


def test_real_pipeline_reports_progress_in_stage_order(tmp_path: Path) -> None:
    pipeline, r2 = _build_pipeline(FIXTURES["hello_pe"], tmp_path)
    progress: list[str] = []

    try:
        results = pipeline.execute_with_progress(
            lambda name, current, total: progress.append(name), _minimal_options()
        )
    finally:
        r2.quit()

    assert progress == pipeline.list_stages()
    assert "file_info" in results
    assert "format_detection" in results


@pytest.mark.parametrize(
    ("fixture", "expected_format", "format_key"),
    [
        (FIXTURES["hello_pe"], "PE", "pe_info"),
        (FIXTURES["hello_elf"], "ELF", "elf_info"),
        (FIXTURES["hello_macho"], "Mach-O", "macho_info"),
    ],
)
def test_real_pipeline_runs_format_analysis_for_supported_formats(
    tmp_path: Path, fixture: str, expected_format: str, format_key: str
) -> None:
    pipeline, r2 = _build_pipeline(fixture, tmp_path)
    try:
        results = pipeline.execute(_minimal_options(), parallel=False)
    finally:
        r2.quit()

    assert results["format_detection"]["file_format"] == expected_format
    assert format_key in results


def test_real_format_stages_detect_pe_and_analyze_metadata(samples_dir: Path) -> None:
    sample = samples_dir / "hello_pe.exe"
    session, adapter = _open_adapter(sample)
    try:
        context = {"results": {}, "metadata": {}}
        file_info = FileInfoStage(adapter, str(sample)).execute(context)
        detection = FormatDetectionStage(adapter, str(sample)).execute(context)
        stage = FormatAnalysisStage(create_default_registry(), adapter, Config(), str(sample))
        result = stage.execute(context)
    finally:
        session.close()

    assert "file_info" in file_info
    assert detection["format_detection"]["file_format"] == "PE"
    assert "pe_info" in result


def test_real_inspector_can_disable_packer_and_crypto(tmp_path: Path) -> None:
    config = Config(str(tmp_path / "r2inspect_phase2_options.json"))
    with create_inspector(FIXTURES["hello_pe"], config=config, verbose=False) as inspector:
        results = inspector.analyze(
            analyze_functions=False,
            detect_packer=False,
            detect_crypto=False,
        )

    assert "packer" not in results
    assert "crypto" not in results


class _Stage(AnalysisStage):
    def __init__(self, name: str, *, dependencies: list[str] | None = None) -> None:
        super().__init__(
            name=name, description="test stage", optional=False, dependencies=dependencies
        )

    def _execute(self, context: dict[str, object]) -> dict[str, object]:
        context.setdefault("results", {})
        context["results"][self.name] = {"success": True}
        return {self.name: {"success": True}}


def test_parallel_pipeline_respects_dependencies_in_memory() -> None:
    pipeline = AnalysisPipeline(max_workers=2)
    pipeline.add_stage(_Stage("stage_a"))
    pipeline.add_stage(_Stage("stage_b", dependencies=["stage_a"]))

    results = pipeline.execute(parallel=True)

    assert results["stage_a"]["success"] is True
    assert results["stage_b"]["success"] is True
