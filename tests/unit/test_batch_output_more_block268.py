from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.cli.batch_output import (
    collect_batch_statistics,
    create_batch_summary,
    create_json_batch_summary,
    determine_csv_file_path,
    find_files_by_extensions,
    find_files_to_process,
    setup_batch_output_directory,
)


@pytest.mark.unit
def test_batch_output_statistics_and_paths(tmp_path: Path) -> None:
    result = {
        "packer_info": {"detected": True, "name": "UPX"},
        "crypto_info": ["AES"],
        "indicators": [{"type": "Anti-VM"}],
        "file_info": {"file_type": "PE", "architecture": "x86"},
        "compiler": {"compiler": "MSVC", "detected": True},
    }
    stats = collect_batch_statistics({"sample": result})
    assert stats["packers_detected"][0]["packer"] == "UPX"
    assert stats["crypto_patterns"][0]["pattern"] == "AES"
    assert stats["suspicious_indicators"][0]["type"] == "Anti-VM"
    assert stats["file_types"]["PE"] == 1
    assert stats["architectures"]["x86"] == 1
    assert stats["compilers"]["MSVC"] == 1

    csv_path, name = determine_csv_file_path(tmp_path / "out.csv", "ts")
    assert csv_path.name == "out.csv"
    assert name == "out.csv"

    csv_path, name = determine_csv_file_path(tmp_path, "ts")
    assert name.startswith("r2inspect_")


@pytest.mark.unit
def test_batch_output_find_files_and_setup_dirs(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "b.bin").write_text("b")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "c.bin").write_text("c")

    files = find_files_by_extensions(tmp_path, "bin", recursive=False)
    assert (tmp_path / "b.bin") in files

    files = find_files_by_extensions(tmp_path, "bin", recursive=True)
    assert (tmp_path / "sub" / "c.bin") in files

    files = find_files_to_process(
        tmp_path, auto_detect=False, extensions=None, recursive=False, verbose=False
    )
    assert files == []

    files = find_files_to_process(
        tmp_path, auto_detect=False, extensions="bin", recursive=True, verbose=False
    )
    assert len(files) == 2

    files = find_files_to_process(
        tmp_path, auto_detect=True, extensions=None, recursive=False, verbose=False
    )
    assert isinstance(files, list)

    output_path = setup_batch_output_directory(str(tmp_path / "out.csv"), True, True)
    assert output_path.parent.exists()

    output_path = setup_batch_output_directory(None, True, False)
    assert output_path.name == "output"

    output_path = setup_batch_output_directory(None, False, False)
    assert output_path.name == "r2inspect_batch_results"


@pytest.mark.unit
def test_batch_output_summary_files(tmp_path: Path) -> None:
    results = {
        "file": {
            "file_info": {"name": "file", "size": 1},
            "compiler": {"compiler": "MSVC", "detected": True},
        }
    }
    failed = [("bad.bin", "error")]

    label = create_json_batch_summary(results, failed, tmp_path, "stamp")
    assert label.startswith("r2inspect_batch_")
    assert (tmp_path / "r2inspect_batch_stamp.json").exists()

    output = create_batch_summary(results, failed, tmp_path, output_json=False, output_csv=True)
    assert output is not None

    output = create_batch_summary(results, failed, tmp_path, output_json=True, output_csv=False)
    assert output is not None

    output = create_batch_summary(results, failed, tmp_path, output_json=True, output_csv=True)
    assert output is not None

    output = create_batch_summary(results, failed, tmp_path, output_json=False, output_csv=False)
    assert output is None
