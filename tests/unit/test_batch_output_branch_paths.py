"""Tests covering branch paths in r2inspect/cli/batch_output.py."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from r2inspect.cli.batch_output import (
    _build_large_row,
    _build_small_row,
    _collect_yara_matches,
    _prepare_batch_run,
    create_batch_summary,
    find_files_to_process,
    run_batch_analysis,
)


def test_find_files_to_process_auto_detect_not_quiet_prints_message(
    tmp_path: Path, capsys
) -> None:
    """find_files_to_process with auto_detect=True and quiet=False prints auto-detect message."""
    find_files_to_process(
        tmp_path,
        auto_detect=True,
        extensions=None,
        recursive=False,
        verbose=False,
        quiet=False,
    )
    out = capsys.readouterr().out
    assert "Auto-detecting" in out


def test_find_files_to_process_extensions_not_quiet_prints_message(
    tmp_path: Path, capsys
) -> None:
    """find_files_to_process with extensions and quiet=False prints searching message."""
    (tmp_path / "file.exe").touch()
    find_files_to_process(
        tmp_path,
        auto_detect=False,
        extensions="exe",
        recursive=False,
        verbose=False,
        quiet=False,
    )
    out = capsys.readouterr().out
    assert "Searching for files" in out


def test_find_files_to_process_none_extensions_returns_empty(tmp_path: Path) -> None:
    """find_files_to_process with auto_detect=False and extensions=None returns empty list."""
    result = find_files_to_process(
        tmp_path,
        auto_detect=False,
        extensions=None,
        recursive=False,
        verbose=False,
        quiet=True,
    )
    assert result == []


def test_prepare_batch_run_not_quiet_prints_file_and_thread_count(
    tmp_path: Path, capsys
) -> None:
    """_prepare_batch_run with quiet=False prints found file count and thread count."""
    (tmp_path / "test.exe").touch()
    result = _prepare_batch_run(
        batch_path=tmp_path,
        auto_detect=False,
        extensions="exe",
        recursive=False,
        verbose=False,
        quiet=False,
        output_dir=None,
        output_json=False,
        output_csv=False,
        threads=4,
    )
    assert result is not None
    out = capsys.readouterr().out
    assert "Found" in out
    assert "4" in out


def test_create_batch_summary_both_formats_csv_suffix_path(tmp_path: Path) -> None:
    """create_batch_summary case 2 uses output_path.name when suffix is .csv."""
    results: dict[str, Any] = {"file.exe": {"file_info": {"name": "file.exe"}}}
    csv_output = tmp_path / "results.csv"
    output_filename = create_batch_summary(results, [], csv_output, True, True)
    assert output_filename is not None
    assert "results.csv" in output_filename
    assert "individual JSONs" in output_filename


def test_collect_yara_matches_object_with_rule_attribute() -> None:
    """_collect_yara_matches handles match objects exposing a .rule attribute."""

    class YaraMatch:
        rule = "my_yara_rule"

    result: dict[str, Any] = {"yara_matches": [YaraMatch()]}
    matches = _collect_yara_matches(result)
    assert "my_yara_rule" in matches


def test_collect_yara_matches_plain_value_uses_str_fallback() -> None:
    """_collect_yara_matches converts non-dict, non-attribute matches via str()."""
    result: dict[str, Any] = {"yara_matches": [42]}
    matches = _collect_yara_matches(result)
    assert matches == "42"


def test_build_small_row_none_file_info_returns_error_tuple() -> None:
    """_build_small_row returns error tuple when file_info is None (triggers except branch)."""
    filename, file_type, compiler, compile_time = _build_small_row(
        "key.exe", {"file_info": None}
    )
    assert filename == "key.exe"
    assert file_type == "Error"
    assert compiler == "Error"
    assert compile_time == "Error"


def test_build_large_row_none_file_info_returns_error_tuple() -> None:
    """_build_large_row returns error tuple when file_info is None (triggers except branch)."""
    md5, file_type, compiler, compile_time, yara = _build_large_row(
        "key.exe", {"file_info": None}
    )
    assert md5 == "key.exe"
    assert file_type == "Error"
    assert compiler == "Error"
    assert compile_time == "Error"
    assert yara == "Error"


def test_run_batch_analysis_delegates_to_processing_module(tmp_path: Path) -> None:
    """run_batch_analysis in batch_output delegates to batch_processing.run_batch_analysis."""
    run_batch_analysis(
        batch_dir=str(tmp_path),
        options={},
        output_json=False,
        output_csv=False,
        output_dir=None,
        recursive=False,
        extensions="exe",
        verbose=False,
        config_obj=None,
        auto_detect=False,
        threads=1,
        quiet=True,
    )
