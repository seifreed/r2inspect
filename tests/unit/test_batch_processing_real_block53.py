from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.cli.batch_processing import (
    create_json_batch_summary,
    display_no_files_message,
    find_files_by_extensions,
    find_files_to_process,
    process_files_parallel,
    process_single_file,
    setup_batch_output_directory,
    setup_rate_limiter,
)
from r2inspect.config import Config


def _sample_path() -> Path:
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("sample binary missing")
    return sample


def test_process_single_file_and_parallel(tmp_path: Path):
    sample = _sample_path()
    local_file = tmp_path / sample.name
    local_file.write_bytes(sample.read_bytes())

    output_path = tmp_path / "out"
    output_path.mkdir()

    rate_limiter = setup_rate_limiter(threads=1, verbose=False)
    options = {"full_analysis": False}

    file_path, results, error = process_single_file(
        local_file,
        tmp_path,
        Config(),
        options,
        True,
        output_path,
        rate_limiter,
    )

    assert error is None
    assert results is not None
    assert (output_path / f"{local_file.stem}_analysis.json").exists()

    all_results: dict = {}
    failed_files: list = []
    process_files_parallel(
        [local_file],
        all_results,
        failed_files,
        output_path,
        tmp_path,
        Config(),
        options,
        False,
        1,
        rate_limiter,
    )

    assert local_file.name in all_results
    assert failed_files == []


def test_find_files_and_summary(tmp_path: Path, capsys):
    sample = _sample_path()
    local_file = tmp_path / sample.name
    local_file.write_bytes(sample.read_bytes())

    found = find_files_by_extensions(tmp_path, "exe", recursive=False)
    assert local_file in found

    files = find_files_to_process(
        tmp_path,
        auto_detect=False,
        extensions="exe",
        recursive=False,
        verbose=False,
        quiet=True,
    )
    assert local_file in files

    # No extensions provided with auto_detect False returns []
    files_empty = find_files_to_process(
        tmp_path,
        auto_detect=False,
        extensions=None,
        recursive=False,
        verbose=False,
        quiet=True,
    )
    assert files_empty == []

    display_no_files_message(auto_detect=True, extensions=None)
    display_no_files_message(auto_detect=False, extensions="exe")
    out = capsys.readouterr().out
    assert "No" in out

    output_path = tmp_path / "output"
    output_path.mkdir()
    summary_name = create_json_batch_summary(
        {local_file.name: {"file_info": {"name": local_file.name}}},
        [],
        output_path,
        "20260131_000000",
    )
    assert summary_name.endswith("individual JSONs")
    assert (output_path / "r2inspect_batch_20260131_000000.json").exists()


def test_setup_batch_output_directory(tmp_path: Path):
    out_dir = setup_batch_output_directory(str(tmp_path / "outdir"), False, False)
    assert out_dir.exists()

    out_file = setup_batch_output_directory(str(tmp_path / "out.csv"), False, False)
    assert out_file.parent.exists()

    out_default = setup_batch_output_directory(None, True, False)
    assert out_default.name == "output"
