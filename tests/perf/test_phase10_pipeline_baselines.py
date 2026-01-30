from __future__ import annotations

import time
from pathlib import Path

import psutil
import pytest

from r2inspect.config import Config
from r2inspect.core.inspector import R2Inspector

pytestmark = [pytest.mark.slow, pytest.mark.requires_r2]

FIXTURES = Path("samples/fixtures")


def _config(tmp_path: Path) -> Config:
    return Config(str(tmp_path / "r2inspect_phase10.json"))


def _minimal_options() -> dict:
    return {
        "analyze_functions": False,
        "detect_packer": False,
        "detect_crypto": False,
    }


def test_pipeline_timing_baseline(tmp_path: Path) -> None:
    config = _config(tmp_path)
    start = time.perf_counter()
    with R2Inspector(str(FIXTURES / "hello_pe.exe"), config=config, verbose=False) as inspector:
        results = inspector.analyze(**_minimal_options())
    elapsed = time.perf_counter() - start

    assert "file_info" in results
    assert "format_detection" in results
    assert elapsed < 30.0


def test_memory_baseline_for_fixture_analysis(tmp_path: Path) -> None:
    config = _config(tmp_path)
    process = psutil.Process()
    before_mb = process.memory_info().rss / 1024 / 1024

    with R2Inspector(
        str(FIXTURES / "edge_high_entropy.bin"), config=config, verbose=False
    ) as inspector:
        inspector.analyze(**_minimal_options())

    after_mb = process.memory_info().rss / 1024 / 1024
    assert after_mb - before_mb < 1024


def test_regression_edge_cases_do_not_crash(tmp_path: Path) -> None:
    config = _config(tmp_path)

    for fixture in ("edge_bad_pe.bin", "edge_tiny.bin"):
        with R2Inspector(str(FIXTURES / fixture), config=config, verbose=False) as inspector:
            results = inspector.analyze(**_minimal_options())

        assert "file_info" in results
        assert "format_detection" in results
