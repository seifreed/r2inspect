from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.cli.batch_output import (
    _build_large_row,
    _build_small_row,
    _collect_yara_matches,
    _compiler_name,
    _extract_compile_time,
    _simplify_file_type,
    create_batch_summary,
    determine_csv_file_path,
    get_csv_fieldnames,
    setup_batch_output_directory,
    write_csv_results,
)
from r2inspect.factory import create_inspector


def test_output_helpers_basic():
    assert _simplify_file_type("PE32 executable, 3 sections") == "PE32 (x86)"
    assert _simplify_file_type("PE32+ executable, 5 sections") == "PE32+ (x64)"
    assert _simplify_file_type("ELF 64-bit") == "ELF"

    assert _collect_yara_matches({"yara_matches": []}) == "None"
    assert _collect_yara_matches({"yara_matches": [{"rule": "A"}]}) == "A"
    assert _collect_yara_matches({"yara_matches": ["x"]}) == "x"

    result = {"compiler": {"detected": True, "compiler": "GCC", "version": "9"}}
    assert _compiler_name(result) == "GCC 9"

    result = {"pe_info": {"compile_time": "2020"}}
    assert _extract_compile_time(result) == "2020"


def test_rows_and_csv(tmp_path: Path):
    result = {
        "file_info": {"name": "sample", "file_type": "PE32 executable", "md5": "x"},
        "compiler": {"detected": False},
        "pe_info": {"compile_time": "N/A"},
    }
    small = _build_small_row("k", result)
    assert small[0] == "sample"

    large = _build_large_row("k", result)
    assert large[0] == "x"

    fields = get_csv_fieldnames()
    assert "md5" in fields

    output_dir = setup_batch_output_directory(str(tmp_path / "out"), True, False)
    csv_file, name = determine_csv_file_path(output_dir, "20260101_000000")
    assert csv_file.suffix == ".csv"


def test_create_batch_summary_csv(tmp_path: Path):
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("sample binary missing")

    with create_inspector(str(sample)) as inspector:
        results = inspector.analyze(full_analysis=False)

    output_dir = tmp_path / "out"
    output_dir.mkdir()
    output_filename = create_batch_summary({"sample": results}, [], output_dir, False, True)
    assert output_filename is not None
    assert any(p.suffix == ".csv" for p in output_dir.iterdir())


def test_write_csv_results(tmp_path: Path):
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("sample binary missing")

    with create_inspector(str(sample)) as inspector:
        results = inspector.analyze(full_analysis=False)

    csv_file = tmp_path / "results.csv"
    write_csv_results(csv_file, {"sample": results})
    assert csv_file.exists()
