from __future__ import annotations

from pathlib import Path

import r2inspect.cli.batch_processing as batch_processing

from r2inspect.cli.batch_processing import (
    _is_executable_signature,
    create_json_batch_summary,
    determine_csv_file_path,
    display_no_files_message,
    display_failed_files,
    display_rate_limiter_stats,
    find_executable_files_by_magic,
    find_files_by_extensions,
    find_files_to_process,
    get_csv_fieldnames,
    process_files_parallel,
    run_batch_analysis,
    setup_analysis_options,
    setup_batch_mode,
    setup_batch_output_directory,
    setup_rate_limiter,
    setup_single_file_output,
    update_crypto_stats,
    update_packer_stats,
)


def _write_pe_file(path: Path) -> Path:
    data = bytearray(128)
    data[0:2] = b"MZ"
    data[60:64] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\x00\x00"
    path.write_bytes(data)
    return path


def test_batch_processing_auto_detects_real_executable_files(tmp_path: Path) -> None:
    exe_file = _write_pe_file(tmp_path / "sample.exe")
    (tmp_path / "notes.txt").write_text("not executable")

    files = find_files_to_process(
        tmp_path,
        auto_detect=True,
        extensions=None,
        recursive=False,
        verbose=False,
        quiet=True,
    )

    assert files == [exe_file]


def test_batch_processing_extension_mode_returns_matching_files(tmp_path: Path) -> None:
    exe_file = tmp_path / "a.exe"
    dll_file = tmp_path / "b.dll"
    txt_file = tmp_path / "c.txt"
    exe_file.write_text("x")
    dll_file.write_text("x")
    txt_file.write_text("x")

    files = find_files_to_process(
        tmp_path,
        auto_detect=False,
        extensions="exe,dll",
        recursive=False,
        verbose=False,
        quiet=True,
    )

    assert sorted(path.name for path in files) == ["a.exe", "b.dll"]


def test_batch_processing_reports_when_directory_has_no_supported_files(
    tmp_path: Path, capsys
) -> None:
    output_dir = setup_batch_output_directory(str(tmp_path / "out"), False, False)

    run_batch_analysis(
        batch_dir=str(tmp_path),
        options={},
        output_json=False,
        output_csv=False,
        output_dir=str(output_dir),
        recursive=False,
        extensions=None,
        verbose=False,
        config_obj=None,
        auto_detect=True,
        threads=1,
        quiet=False,
    )

    captured = capsys.readouterr().out
    assert "No executable files detected in the directory" in captured


def test_batch_processing_parallel_failure_path_records_failed_file(tmp_path: Path) -> None:
    sample = _write_pe_file(tmp_path / "sample.exe")

    class ImmediateLimiter:
        def acquire(self, timeout: float = 0.0) -> bool:
            return False

        def release_success(self) -> None:
            return None

        def release_error(self, _error: str = "unknown") -> None:
            return None

        def get_stats(self) -> dict[str, float]:
            return {"success_rate": 0.0}

    all_results: dict[str, dict[str, object]] = {}
    failed_files: list[tuple[str, str]] = []

    process_files_parallel(
        [sample],
        all_results,
        failed_files,
        tmp_path,
        tmp_path,
        None,
        {},
        False,
        1,
        ImmediateLimiter(),
    )

    assert all_results == {}
    assert failed_files


def test_batch_processing_display_helpers_render_messages(capsys) -> None:
    display_rate_limiter_stats({"success_rate": 0.5, "avg_wait_time": 0.1, "current_rate": 1.0})
    display_failed_files([("file.bin", "boom")], verbose=False)

    captured = capsys.readouterr().out
    assert "Rate limiter stats" in captured
    assert "Failed" in captured


def test_batch_processing_magic_fallback_uses_header_detection(tmp_path: Path) -> None:
    sample = _write_pe_file(tmp_path / "sample.exe")
    original_magic = batch_processing.magic
    try:
        batch_processing.magic = None
        files = find_executable_files_by_magic(tmp_path, recursive=False, verbose=False)
    finally:
        batch_processing.magic = original_magic

    assert files == [sample]


def test_batch_processing_setup_helpers_cover_default_outputs(tmp_path: Path) -> None:
    recursive, auto_detect, output = setup_batch_mode("batch", None, True, False, None)
    assert recursive is True
    assert auto_detect is True
    assert output == "output"

    single_output = setup_single_file_output(True, False, None, str(tmp_path / "sample.exe"))
    assert str(single_output).endswith("_analysis.json")


def test_batch_processing_support_helpers_cover_output_and_stats(tmp_path: Path, capsys) -> None:
    recursive, auto_detect, output = setup_batch_mode("batch", None, True, False, None)
    assert recursive is True
    assert auto_detect is True
    assert output == "output"

    options = setup_analysis_options("rules.yar", "AA")
    assert options["custom_yara"] == "rules.yar"
    assert options["xor_search"] == "AA"

    output_dir = setup_batch_output_directory(str(tmp_path / "out"), False, False)
    csv_file, csv_name = determine_csv_file_path(output_dir, "20260131_000000")
    assert csv_name.startswith("r2inspect_")
    assert csv_file.suffix == ".csv"
    assert "md5" in get_csv_fieldnames()

    summary_name = create_json_batch_summary(
        {"sample.exe": {"file_info": {"name": "sample.exe"}}},
        [],
        output_dir,
        "20260131_000000",
    )
    assert summary_name.endswith("individual JSONs")
    assert (output_dir / "sample_analysis.json").exists()
    assert (output_dir / "r2inspect_batch_20260131_000000.json").exists()

    stats = {"packers_detected": [], "crypto_patterns": []}
    update_packer_stats(stats, "sample.exe", {"packer_info": {"detected": True, "name": "UPX"}})
    update_crypto_stats(stats, "sample.exe", {"crypto_info": ["AES"]})
    assert stats["packers_detected"][0]["packer"] == "UPX"
    assert stats["crypto_patterns"][0]["pattern"] == "AES"

    display_no_files_message(auto_detect=True, extensions=None)
    captured = capsys.readouterr().out
    assert "No" in captured


def test_batch_processing_file_selection_and_rate_limiter_helpers(tmp_path: Path) -> None:
    exe_file = _write_pe_file(tmp_path / "sample.exe")
    (tmp_path / "readme.txt").write_text("not executable")

    matched = find_files_by_extensions(tmp_path, "exe", recursive=False)
    assert matched == [exe_file]

    assert _is_executable_signature("application/x-dosexec", "") is True
    assert _is_executable_signature("", "PE32 executable") is True
    assert _is_executable_signature("text/plain", "text") is False

    limiter = setup_rate_limiter(threads=1, verbose=False)
    assert limiter.acquire(timeout=0.01) is True
    limiter.release_success()
    assert isinstance(limiter.get_stats(), dict)
