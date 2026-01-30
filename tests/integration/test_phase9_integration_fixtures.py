from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from r2inspect.cli.batch_processing import run_batch_analysis
from r2inspect.config import Config
from r2inspect.core.inspector import R2Inspector

pytestmark = pytest.mark.requires_r2

FIXTURE_DIR = Path("samples/fixtures")
EXPECTED_DIR = FIXTURE_DIR / "expected"


def _load_expected(path: Path) -> dict:
    return json.loads(path.read_text())


def _minimal_options() -> dict:
    return {
        "analyze_functions": False,
        "detect_packer": False,
        "detect_crypto": False,
    }


def _analyze(path: Path) -> dict:
    config = Config(str(Path("/tmp") / "r2inspect_phase9_config.json"))
    with R2Inspector(str(path), config=config, verbose=False) as inspector:
        return inspector.analyze(**_minimal_options())


def _assert_expected(results: dict, expected: dict) -> None:
    assert results["format_detection"]["file_format"] == expected["file_format"]
    file_info = results["file_info"]
    assert file_info["name"] == expected["name"]
    assert file_info["size"] == expected["size"]
    assert file_info["md5"] == expected["hashes"]["md5"]
    assert file_info["sha256"] == expected["hashes"]["sha256"]


def test_end_to_end_fixtures_match_expected_snapshots() -> None:
    expected_files = sorted(EXPECTED_DIR.glob("*.json"))
    assert expected_files

    for expected_path in expected_files:
        expected = _load_expected(expected_path)
        fixture_path = FIXTURE_DIR / expected["name"]
        assert fixture_path.exists()
        results = _analyze(fixture_path)
        _assert_expected(results, expected)


def _cli_path() -> str:
    return str(Path(sys.executable).parent / "r2inspect")


def test_batch_mode_mixed_files_and_csv_output(tmp_path: Path) -> None:
    batch_dir = tmp_path / "batch_fixtures"
    batch_dir.mkdir()
    shutil.copy(FIXTURE_DIR / "hello_pe.exe", batch_dir / "hello_pe.exe")
    shutil.copy(FIXTURE_DIR / "hello_elf", batch_dir / "hello_elf.elf")
    shutil.copy(FIXTURE_DIR / "edge_bad_pe.bin", batch_dir / "edge_bad_pe.bin")

    output_dir = tmp_path / "batch_out"
    config = Config(str(tmp_path / "r2inspect_batch_config.json"))
    options = {"analyze_functions": False}

    run_batch_analysis(
        batch_dir=str(batch_dir),
        options=options,
        output_json=True,
        output_csv=True,
        output_dir=str(output_dir),
        recursive=True,
        extensions="exe,elf,bin",
        verbose=False,
        config_obj=config,
        auto_detect=False,
        threads=1,
        quiet=True,
    )

    csv_files = list(output_dir.glob("*.csv"))
    json_files = list(output_dir.glob("*.json"))
    assert csv_files
    assert json_files

    expected_json = {
        "hello_pe_analysis.json",
        "hello_elf_analysis.json",
        "edge_bad_pe_analysis.json",
    }
    assert expected_json.issubset({path.name for path in json_files})


def test_interactive_mode_scripted_commands() -> None:
    cmd = [
        _cli_path(),
        str(FIXTURE_DIR / "hello_pe.exe"),
        "-i",
        "--quiet",
    ]
    result = subprocess.run(
        cmd,
        input="help\nquit\n",
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "Available commands" in result.stdout
    assert "Command error" not in result.stdout
