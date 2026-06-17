"""Regression tests for loop iteration 2.

Batch per-file JSON reports were named ``<stem>_analysis.json``, so two files
sharing a stem — same basename in different subdirectories, or same stem with
different extensions — silently overwrote each other's report (data loss in a
forensics tool). The per-file name is now derived from the unique batch-relative
path.
"""

from __future__ import annotations

import json

from r2inspect.cli.batch_output_json import per_file_json_name, write_individual_json_results


def test_per_file_json_name_disambiguates_by_relative_path() -> None:
    assert per_file_json_name("dir1/mal.bin") == "dir1_mal.bin_analysis.json"
    assert per_file_json_name("dir2/mal.bin") == "dir2_mal.bin_analysis.json"
    assert per_file_json_name("sample.exe") == "sample.exe_analysis.json"
    assert per_file_json_name("sample.dll") == "sample.dll_analysis.json"
    assert per_file_json_name("\\win\\sub\\a.bin") == "win_sub_a.bin_analysis.json"


def test_write_individual_json_results_no_overwrite_on_stem_collision(tmp_path) -> None:
    all_results = {
        "/corpus/dir1/mal.bin": {"relative_path": "dir1/mal.bin", "data": 1},
        "/corpus/dir2/mal.bin": {"relative_path": "dir2/mal.bin", "data": 2},
        "/corpus/sample.exe": {"relative_path": "sample.exe", "data": 3},
        "/corpus/sample.dll": {"relative_path": "sample.dll", "data": 4},
    }

    write_individual_json_results(all_results, tmp_path)

    written = sorted(p.name for p in tmp_path.glob("*_analysis.json"))
    assert written == [
        "dir1_mal.bin_analysis.json",
        "dir2_mal.bin_analysis.json",
        "sample.dll_analysis.json",
        "sample.exe_analysis.json",
    ]
    assert json.loads((tmp_path / "dir1_mal.bin_analysis.json").read_text())["data"] == 1
    assert json.loads((tmp_path / "dir2_mal.bin_analysis.json").read_text())["data"] == 2


def test_write_individual_json_results_fallback_without_relative_path(tmp_path) -> None:
    write_individual_json_results(
        {"/x/sample.exe": {"file_info": {"name": "sample.exe"}}}, tmp_path
    )
    assert (tmp_path / "sample.exe_analysis.json").exists()
