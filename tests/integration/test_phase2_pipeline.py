import json
from pathlib import Path

import pytest
import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.config import Config
from r2inspect.core.pipeline_builder import PipelineBuilder
from r2inspect.factory import create_inspector
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


def test_pipeline_progress_order_sequential(tmp_path):
    pipeline, r2 = _build_pipeline(FIXTURES["hello_pe"], tmp_path)
    progress = []

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
def test_pipeline_sequential_format_analysis_branches(
    tmp_path, fixture, expected_format, format_key
):
    pipeline, r2 = _build_pipeline(fixture, tmp_path)
    try:
        results = pipeline.execute(_minimal_options(), parallel=False)
    finally:
        r2.quit()

    assert results["format_detection"]["file_format"] == expected_format
    assert format_key in results
    assert "ssdeep" in results
    if expected_format == "PE":
        assert "security" in results
    else:
        assert "security_features" in results.get(format_key, {})


def test_pipeline_parallel_core_results(tmp_path):
    pipeline, r2 = _build_pipeline(FIXTURES["hello_pe"], tmp_path)
    try:
        results = pipeline.execute(_minimal_options(), parallel=True)
    finally:
        r2.quit()

    assert "file_info" in results
    assert "format_detection" in results


def test_inspector_options_disable_detection(tmp_path):
    config = Config(str(tmp_path / "r2inspect_phase2_options.json"))
    options = {
        "analyze_functions": False,
        "detect_packer": False,
        "detect_crypto": False,
    }
    with create_inspector(FIXTURES["hello_pe"], config=config, verbose=False) as inspector:
        results = inspector.analyze(**options)

    assert "packer" not in results
    assert "crypto" not in results
    assert "anti_analysis" in results
    assert "compiler" in results
    assert "yara_matches" in results
