from __future__ import annotations

import time
from pathlib import Path

import pytest

from r2inspect.cli.batch_processing import (
    _is_executable_signature,
    check_executable_signature,
    determine_csv_file_path,
    display_failed_files,
    display_rate_limiter_stats,
    get_csv_fieldnames,
    is_elf_executable,
    is_macho_executable,
    is_pe_executable,
    is_script_executable,
    setup_analysis_options,
    setup_batch_mode,
    setup_single_file_output,
    update_crypto_stats,
    update_packer_stats,
    write_csv_results,
)
from r2inspect.factory import create_inspector


def test_signature_helpers(tmp_path: Path):
    pe = Path("samples/fixtures/hello_pe.exe")
    if pe.exists():
        assert check_executable_signature(pe) is True

    assert is_elf_executable(b"\x7fELF") is True
    assert is_macho_executable(b"\xfe\xed\xfa\xce") is True
    assert is_script_executable(b"#!") is True

    with open(pe, "rb") as f:
        header = f.read(64)
        assert is_pe_executable(header, f) is True


def test_executable_signature_matching():
    assert _is_executable_signature("application/x-dosexec", "") is True
    assert _is_executable_signature("", "PE32 executable") is True
    assert _is_executable_signature("text/plain", "text") is False


def test_setup_batch_and_analysis_options():
    recursive, auto, output = setup_batch_mode("batch", None, True, False, None)
    assert recursive is True
    assert auto is True
    assert output == "output"

    opts = setup_analysis_options("rules", "AA")
    assert opts["custom_yara"] == "rules"
    assert opts["xor_search"] == "AA"


def test_setup_single_file_output(tmp_path: Path):
    filename = tmp_path / "sample.bin"
    filename.write_bytes(b"data")

    out = setup_single_file_output(True, False, None, str(filename))
    assert str(out).endswith("sample_analysis.json")

    out = setup_single_file_output(False, True, None, str(filename))
    assert str(out).endswith("sample_analysis.csv")


def test_csv_helpers(tmp_path: Path):
    fields = get_csv_fieldnames()
    assert "md5" in fields

    output_dir = tmp_path / "out"
    output_dir.mkdir()
    csv_file, name = determine_csv_file_path(output_dir, "20260101_000000")
    assert name.startswith("r2inspect_")
    assert csv_file.suffix == ".csv"


def test_write_csv_results(tmp_path: Path):
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("sample binary missing")

    with create_inspector(str(sample)) as inspector:
        results = inspector.analyze(full_analysis=False)

    csv_file = tmp_path / "results.csv"
    write_csv_results(csv_file, {"sample": results})
    assert csv_file.exists()


def test_stats_helpers(capsys):
    stats = {"packers_detected": [], "crypto_patterns": []}
    update_packer_stats(stats, "file", {"packer_info": {"detected": True, "name": "UPX"}})
    update_crypto_stats(stats, "file", {"crypto_info": ["AES"]})
    assert stats["packers_detected"][0]["packer"] == "UPX"
    assert stats["crypto_patterns"][0]["pattern"] == "AES"

    display_rate_limiter_stats({"success_rate": 1.0, "avg_wait_time": 0.0, "current_rate": 5.0})
    display_failed_files([("file", "error")], verbose=False)
    out = capsys.readouterr().out
    assert "Failed" in out
