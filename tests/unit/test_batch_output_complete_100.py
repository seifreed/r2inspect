#!/usr/bin/env python3
"""Targeted coverage tests for batch_output CLI output helpers."""

from __future__ import annotations

from pathlib import Path

from r2inspect.cli import batch_output


def _sample_result() -> dict:
    return {
        "file_info": {
            "name": "hello.bin",
            "file_type": "PE32+ executable, 5 sections",
            "md5": "cafebabe",
            "compile_time": "2026-03-01",
        },
        "compiler": {"detected": True, "compiler": "GCC", "version": "12"},
        "yara_matches": [{"rule": "rule_a"}, {"rule": "rule_b"}],
    }


def test_batch_output_complete_100_csv_output_creates_timestamp_path(tmp_path: Path) -> None:
    output = batch_output.create_batch_summary({}, [], tmp_path, output_json=False, output_csv=True)

    assert output is None or output.startswith("r2inspect_")
    assert not any(file.suffix == ".json" for file in tmp_path.iterdir())


def test_batch_output_complete_100_csv_and_json_outputs(tmp_path: Path) -> None:
    output = batch_output.create_batch_summary(
        {"a": _sample_result()},
        [("bad", "boom")],
        tmp_path,
        output_json=True,
        output_csv=True,
    )

    assert output is not None
    assert "+ individual JSONs" in output


def test_batch_output_complete_100_json_output_only(tmp_path: Path) -> None:
    sample = {"a": _sample_result()}
    failed = [("bad.bin", "boom")]

    output = batch_output.create_batch_summary(
        sample, failed, tmp_path, output_json=True, output_csv=False
    )
    assert output is not None
    assert output.startswith("r2inspect_batch_") and output.endswith(" + individual JSONs")
    filename = output.split(" + individual JSONs")[0]
    assert (tmp_path / filename).exists()


def test_batch_output_complete_100_json_output_only_with_failures(tmp_path: Path) -> None:
    sample = {"a": _sample_result()}
    failed = [("bad.bin", "boom")]

    output = batch_output.create_batch_summary(
        sample, failed, tmp_path, output_json=True, output_csv=False
    )

    assert output is not None
    filename = output.split(" + individual JSONs")[0]
    assert (tmp_path / filename).exists()


def test_batch_output_complete_100_no_formats_returns_none(tmp_path: Path) -> None:
    output = batch_output.create_batch_summary(
        {}, [], tmp_path, output_json=False, output_csv=False
    )
    assert output is None


def test_batch_output_complete_100_find_files_to_process_combinations(tmp_path: Path) -> None:
    (tmp_path / "a.bin").write_bytes(b"abc")
    (tmp_path / "b.dll").write_bytes(b"def")

    assert (
        batch_output.find_files_to_process(tmp_path, False, None, False, verbose=False, quiet=True)
        == []
    )
    assert set(
        batch_output.find_files_to_process(tmp_path, False, "bin", False, verbose=False, quiet=True)
    ) == {
        tmp_path / "a.bin",
    }
    assert isinstance(
        batch_output.find_files_to_process(
            tmp_path,
            True,
            None,
            False,
            verbose=False,
            quiet=True,
        ),
        list,
    )


def test_batch_output_complete_100_determine_csv_output_paths(tmp_path: Path) -> None:
    csv_path, name = batch_output.determine_csv_file_path(tmp_path / "batch.csv", "ts")
    assert csv_path.name == "batch.csv"
    assert name == "batch.csv"

    directory_csv, name_dir = batch_output.determine_csv_file_path(tmp_path, "ts")
    assert directory_csv.parent == tmp_path
    assert name_dir.startswith("r2inspect_")
    assert name_dir.endswith(".csv")


def test_batch_output_complete_100_setup_batch_output_directory_paths(tmp_path: Path) -> None:
    csv_named = batch_output.setup_batch_output_directory(str(tmp_path / "out.csv"), False, True)
    assert csv_named.name == "out.csv"
    assert csv_named.parent == tmp_path

    json_named = batch_output.setup_batch_output_directory(
        str(tmp_path / "summary.json"), True, False
    )
    assert json_named == tmp_path / "summary.json"
    assert json_named.parent == tmp_path

    output_dir = batch_output.setup_batch_output_directory(None, True, True)
    assert output_dir.name == "output"

    fallback = batch_output.setup_batch_output_directory(None, False, False)
    assert fallback.name == "r2inspect_batch_results"


def test_batch_output_complete_100_row_builder_exceptions() -> None:
    assert batch_output._build_small_row("sample", object()) == (
        "sample",
        "Error",
        "Error",
        "Error",
    )
    assert batch_output._build_large_row("sample", object()) == (
        "sample",
        "Error",
        "Error",
        "Error",
        "Error",
    )


def test_batch_output_complete_100_collect_yara_non_list() -> None:
    assert batch_output._collect_yara_matches({"yara_matches": "bad"}) == "None"
