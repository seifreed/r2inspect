from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from r2inspect.cli import batch_output
from r2inspect.cli.batch_processing import setup_analysis_options
from r2inspect.config import Config

pytestmark = [pytest.mark.requires_r2, pytest.mark.integration]

FIXTURE_DIR = Path("samples/fixtures")


def _prepare_batch_dir(tmp_path: Path) -> Path:
    batch_dir = tmp_path / "batch_real"
    batch_dir.mkdir()
    shutil.copy(FIXTURE_DIR / "hello_pe.exe", batch_dir / "hello_pe.exe")
    shutil.copy(FIXTURE_DIR / "hello_elf", batch_dir / "hello_elf.elf")
    return batch_dir


def test_batch_output_json_real_flow(tmp_path: Path) -> None:
    batch_dir = _prepare_batch_dir(tmp_path)
    output_dir = tmp_path / "batch_json_out"
    config = Config(str(tmp_path / "r2inspect_batch_output.json"))

    batch_output.run_batch_analysis(
        batch_dir=str(batch_dir),
        options=setup_analysis_options(None, None),
        output_json=True,
        output_csv=False,
        output_dir=str(output_dir),
        recursive=True,
        extensions="exe,elf",
        verbose=False,
        config_obj=config,
        auto_detect=False,
        threads=1,
        quiet=True,
    )

    summary_files = list(output_dir.glob("r2inspect_batch_*.json"))
    assert summary_files

    per_file_json = {path.name for path in output_dir.glob("*_analysis.json")}
    assert {"hello_pe_analysis.json", "hello_elf_analysis.json"}.issubset(per_file_json)


def test_batch_output_csv_real_flow(tmp_path: Path) -> None:
    batch_dir = _prepare_batch_dir(tmp_path)
    output_csv = tmp_path / "batch_results.csv"
    config = Config(str(tmp_path / "r2inspect_batch_output_csv.json"))

    batch_output.run_batch_analysis(
        batch_dir=str(batch_dir),
        options=setup_analysis_options(None, None),
        output_json=False,
        output_csv=True,
        output_dir=str(output_csv),
        recursive=True,
        extensions="exe,elf",
        verbose=False,
        config_obj=config,
        auto_detect=False,
        threads=1,
        quiet=True,
    )

    assert output_csv.exists()
    content = output_csv.read_text(encoding="utf-8")
    assert "md5" in content
