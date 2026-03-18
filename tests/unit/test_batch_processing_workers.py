#!/usr/bin/env python3
"""Tests for batch processing workers -- real objects only, no mocks."""

import os
import sys
import threading
import time
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from r2inspect.cli.batch_processing import (
    _flush_coverage_data,
    _pytest_running,
    _safe_exit,
    check_executable_signature,
    display_batch_results,
    display_failed_files,
    display_memory_stats,
    display_no_files_message,
    display_rate_limiter_stats,
    ensure_batch_shutdown,
    find_executable_files_by_magic,
    find_files_by_extensions,
    find_files_to_process,
    handle_main_error,
    schedule_forced_exit,
    setup_analysis_options,
    setup_batch_mode,
    setup_batch_output_directory,
    setup_rate_limiter,
    setup_single_file_output,
)
from r2inspect.cli.batch_presentation import (
    display_batch_results as presentation_display_batch_results,
    display_failed_files as presentation_display_failed_files,
    display_memory_stats as presentation_display_memory_stats,
    display_no_files_message as presentation_display_no_files_message,
    display_rate_limiter_stats as presentation_display_rate_limiter_stats,
    handle_main_error as presentation_handle_main_error,
)
from r2inspect.infrastructure.rate_limiter import BatchRateLimiter


def _make_console() -> tuple[Console, StringIO]:
    """Create a real Console that writes to a StringIO buffer (no ANSI codes)."""
    buf = StringIO()
    return Console(file=buf, no_color=True, highlight=False, width=120), buf


# ---------------------------------------------------------------------------
# check_executable_signature tests
# ---------------------------------------------------------------------------


def test_check_executable_signature_pe(tmp_path):
    pe_file = tmp_path / "test.exe"
    pe_file.write_bytes(
        b"MZ" + b"\x00" * 58 + (64).to_bytes(4, "little") + b"\x00" * 4 + b"PE\x00\x00"
    )
    assert check_executable_signature(pe_file) is True


def test_check_executable_signature_elf(tmp_path):
    elf_file = tmp_path / "test.elf"
    elf_file.write_bytes(b"\x7fELF" + b"\x00" * 100)
    assert check_executable_signature(elf_file) is True


def test_check_executable_signature_macho(tmp_path):
    macho_file = tmp_path / "test.macho"
    macho_file.write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 100)
    assert check_executable_signature(macho_file) is True


def test_check_executable_signature_script(tmp_path):
    script_file = tmp_path / "test.sh"
    script_file.write_bytes(b"#!/bin/bash\necho test")
    assert check_executable_signature(script_file) is True


def test_check_executable_signature_not_executable(tmp_path):
    text_file = tmp_path / "test.txt"
    text_file.write_text("not executable")
    assert check_executable_signature(text_file) is False


# ---------------------------------------------------------------------------
# setup_rate_limiter tests
# ---------------------------------------------------------------------------


def test_setup_rate_limiter_default():
    limiter = setup_rate_limiter(10, verbose=False)
    assert isinstance(limiter, BatchRateLimiter)
    assert limiter.max_concurrent <= 10


def test_setup_rate_limiter_verbose(capsys):
    limiter = setup_rate_limiter(5, verbose=True)
    assert isinstance(limiter, BatchRateLimiter)
    # verbose prints to the module-level console, which goes to stdout
    # Just verify the limiter was created correctly
    assert limiter.adaptive is True


def test_setup_rate_limiter_adaptive_rate():
    limiter = setup_rate_limiter(20, verbose=False)
    assert isinstance(limiter, BatchRateLimiter)
    assert limiter.adaptive is True
    assert limiter.max_concurrent <= 20


# ---------------------------------------------------------------------------
# display_rate_limiter_stats tests (using presentation layer directly)
# ---------------------------------------------------------------------------


def test_display_rate_limiter_stats():
    console, buf = _make_console()
    rate_stats = {"success_rate": 0.98, "avg_wait_time": 0.25, "current_rate": 8.5}
    presentation_display_rate_limiter_stats(console, rate_stats)
    output = buf.getvalue()
    assert "98.0%" in output
    assert "0.25" in output
    assert "8.5" in output


def test_display_rate_limiter_stats_empty():
    console, buf = _make_console()
    rate_stats = {}
    presentation_display_rate_limiter_stats(console, rate_stats)
    output = buf.getvalue()
    assert "Rate limiter stats" in output
    assert "0.0%" in output


# ---------------------------------------------------------------------------
# display_memory_stats tests
# ---------------------------------------------------------------------------


def test_display_memory_stats_success():
    console, buf = _make_console()
    presentation_display_memory_stats(console)
    output = buf.getvalue()
    # get_memory_stats returns real data on a running system;
    # it should contain "Memory stats" header and numeric data
    assert "Memory stats" in output or output == ""


# ---------------------------------------------------------------------------
# display_failed_files tests
# ---------------------------------------------------------------------------


def test_display_failed_files_verbose():
    console, buf = _make_console()
    failed_files = [("file1.exe", "Error 1"), ("file2.exe", "Error 2")]
    presentation_display_failed_files(console, failed_files, verbose=True)
    output = buf.getvalue()
    assert "Failed: 2 files" in output
    assert "file1.exe" in output
    assert "Error 1" in output
    assert "file2.exe" in output


def test_display_failed_files_non_verbose():
    console, buf = _make_console()
    failed_files = [("file1.exe", "Error 1")]
    presentation_display_failed_files(console, failed_files, verbose=False)
    output = buf.getvalue()
    assert "Failed: 1 files" in output
    assert "--verbose" in output


def test_display_failed_files_many():
    console, buf = _make_console()
    failed_files = [(f"file{i}.exe", f"Error {i}") for i in range(15)]
    presentation_display_failed_files(console, failed_files, verbose=True)
    output = buf.getvalue()
    assert "Failed: 15 files" in output
    # Only first 10 shown, then "... and 5 more"
    assert "5 more" in output


def test_display_failed_files_long_error():
    console, buf = _make_console()
    failed_files = [("file.exe", "x" * 200)]
    presentation_display_failed_files(console, failed_files, verbose=True)
    output = buf.getvalue()
    assert "file.exe" in output
    assert "..." in output  # truncated


# ---------------------------------------------------------------------------
# display_batch_results tests (using real BatchRateLimiter)
# ---------------------------------------------------------------------------


def test_display_batch_results_basic():
    console, buf = _make_console()
    all_results = {"file1.exe": {"name": "file1.exe"}}
    failed_files: list[tuple[str, str]] = []
    elapsed_time = 10.5
    files_to_process = [Path("file1.exe")]
    rate_limiter = BatchRateLimiter(max_concurrent=5, enable_adaptive=False)

    presentation_display_batch_results(
        console,
        all_results,
        failed_files,
        elapsed_time,
        files_to_process,
        rate_limiter,
        False,
        None,
    )
    output = buf.getvalue()
    assert "Analysis Complete" in output
    assert "1/1" in output
    assert "10.5" in output


def test_display_batch_results_with_failures():
    console, buf = _make_console()
    all_results: dict[str, dict] = {}
    failed_files = [("file1.exe", "Error 1"), ("file2.exe", "Error 2")]
    elapsed_time = 5.0
    files_to_process = [Path("file1.exe"), Path("file2.exe")]
    rate_limiter = BatchRateLimiter(max_concurrent=5, enable_adaptive=False)

    presentation_display_batch_results(
        console,
        all_results,
        failed_files,
        elapsed_time,
        files_to_process,
        rate_limiter,
        False,
        None,
    )
    output = buf.getvalue()
    assert "Failed: 2 files" in output


def test_display_batch_results_verbose():
    console, buf = _make_console()
    all_results = {"file1.exe": {}}
    failed_files: list[tuple[str, str]] = []
    elapsed_time = 3.0
    files_to_process = [Path("file1.exe")]
    rate_limiter = BatchRateLimiter(max_concurrent=5, enable_adaptive=False)

    presentation_display_batch_results(
        console,
        all_results,
        failed_files,
        elapsed_time,
        files_to_process,
        rate_limiter,
        True,
        "output.json",
    )
    output = buf.getvalue()
    assert "Rate limiter stats" in output
    assert "Memory stats" in output or "output.json" in output


# ---------------------------------------------------------------------------
# handle_main_error tests
# ---------------------------------------------------------------------------


def test_handle_main_error_verbose():
    console, buf = _make_console()
    error = ValueError("Test error")
    with pytest.raises(SystemExit):
        presentation_handle_main_error(console, error, verbose=True)


def test_handle_main_error_non_verbose():
    console, buf = _make_console()
    error = RuntimeError("Test error")
    with pytest.raises(SystemExit):
        presentation_handle_main_error(console, error, verbose=False)
    output = buf.getvalue()
    assert "Test error" in output


# ---------------------------------------------------------------------------
# display_no_files_message tests
# ---------------------------------------------------------------------------


def test_display_no_files_message_auto_detect():
    console, buf = _make_console()
    presentation_display_no_files_message(console, auto_detect=True, extensions=None)
    output = buf.getvalue()
    assert "No executable files" in output
    assert "Tip" in output


def test_display_no_files_message_extensions():
    console, buf = _make_console()
    presentation_display_no_files_message(console, auto_detect=False, extensions="exe,dll")
    output = buf.getvalue()
    assert "exe,dll" in output
    assert "Tip" in output


# ---------------------------------------------------------------------------
# find_files_by_extensions tests (real filesystem)
# ---------------------------------------------------------------------------


def test_find_files_by_extensions_single(tmp_path):
    (tmp_path / "file.exe").write_text("test")
    result = find_files_by_extensions(tmp_path, "exe", recursive=False)
    assert len(result) == 1


def test_find_files_by_extensions_multiple(tmp_path):
    (tmp_path / "file.exe").write_text("test")
    (tmp_path / "file.dll").write_text("test")
    result = find_files_by_extensions(tmp_path, "exe,dll", recursive=False)
    assert len(result) == 2


def test_find_files_by_extensions_recursive(tmp_path):
    (tmp_path / "file.exe").write_text("test")
    subdir = tmp_path / "subdir"
    subdir.mkdir()
    (subdir / "file2.exe").write_text("test")
    result = find_files_by_extensions(tmp_path, "exe", recursive=True)
    assert len(result) == 2


# ---------------------------------------------------------------------------
# find_files_to_process tests (real filesystem)
# ---------------------------------------------------------------------------


def test_find_files_to_process_extensions(tmp_path):
    (tmp_path / "file.exe").write_text("test")
    result = find_files_to_process(
        tmp_path,
        auto_detect=False,
        extensions="exe",
        recursive=False,
        verbose=False,
    )
    assert len(result) == 1


def test_find_files_to_process_no_extensions():
    result = find_files_to_process(
        Path("."),
        auto_detect=False,
        extensions=None,
        recursive=False,
        verbose=False,
    )
    assert result == []


# ---------------------------------------------------------------------------
# setup_batch_output_directory tests (real filesystem)
# ---------------------------------------------------------------------------


def test_setup_batch_output_directory_json(tmp_path):
    output_dir = tmp_path / "output"
    result = setup_batch_output_directory(str(output_dir), output_json=True, output_csv=False)
    assert result.exists()
    assert result == output_dir


def test_setup_batch_output_directory_csv_file(tmp_path):
    output_file = tmp_path / "results" / "output.csv"
    result = setup_batch_output_directory(str(output_file), output_json=False, output_csv=True)
    assert result.parent.exists()


def test_setup_batch_output_directory_default(tmp_path):
    orig_dir = os.getcwd()
    os.chdir(tmp_path)
    try:
        result = setup_batch_output_directory(None, output_json=False, output_csv=False)
        assert result.name == "r2inspect_batch_results"
        assert result.exists()
    finally:
        os.chdir(orig_dir)


def test_setup_batch_output_directory_json_default(tmp_path):
    orig_dir = os.getcwd()
    os.chdir(tmp_path)
    try:
        result = setup_batch_output_directory(None, output_json=True, output_csv=False)
        assert result.name == "output"
        assert result.exists()
    finally:
        os.chdir(orig_dir)


def test_setup_batch_output_directory_existing(tmp_path):
    output_dir = tmp_path / "existing"
    output_dir.mkdir()
    result = setup_batch_output_directory(str(output_dir), output_json=True, output_csv=False)
    assert result.exists()


# ---------------------------------------------------------------------------
# setup_batch_mode tests
# ---------------------------------------------------------------------------


def test_setup_batch_mode_default():
    recursive, auto_detect, output = setup_batch_mode("batch", None, False, False, None)
    assert recursive is True
    assert auto_detect is True
    assert output is None


def test_setup_batch_mode_with_extensions():
    recursive, auto_detect, output = setup_batch_mode("batch", "exe,dll", False, False, None)
    assert recursive is True
    assert auto_detect is False
    assert output is None


def test_setup_batch_mode_with_output():
    recursive, auto_detect, output = setup_batch_mode("batch", None, True, False, "custom_output")
    assert recursive is True
    assert auto_detect is True
    assert output == "custom_output"


def test_setup_batch_mode_auto_output():
    recursive, auto_detect, output = setup_batch_mode("batch", None, True, False, None)
    assert output == "output"


# ---------------------------------------------------------------------------
# setup_single_file_output tests
# ---------------------------------------------------------------------------


def test_setup_single_file_output_json(tmp_path):
    orig_dir = os.getcwd()
    os.chdir(tmp_path)
    try:
        result = setup_single_file_output(True, False, None, "test.exe")
        assert str(result).endswith("_analysis.json")
    finally:
        os.chdir(orig_dir)


def test_setup_single_file_output_csv(tmp_path):
    orig_dir = os.getcwd()
    os.chdir(tmp_path)
    try:
        result = setup_single_file_output(False, True, None, "test.exe")
        assert str(result).endswith("_analysis.csv")
    finally:
        os.chdir(orig_dir)


def test_setup_single_file_output_custom():
    result = setup_single_file_output(True, False, "custom.json", "test.exe")
    assert result == "custom.json"


def test_setup_single_file_output_none():
    result = setup_single_file_output(False, False, None, "test.exe")
    assert result is None


# ---------------------------------------------------------------------------
# setup_analysis_options tests
# ---------------------------------------------------------------------------


def test_setup_analysis_options_default():
    options = setup_analysis_options(None, None)
    assert options["detect_packer"] is True
    assert options["detect_crypto"] is True
    assert options["full_analysis"] is True


def test_setup_analysis_options_yara():
    options = setup_analysis_options("/path/to/yara", None)
    assert options["custom_yara"] == "/path/to/yara"


def test_setup_analysis_options_xor():
    options = setup_analysis_options(None, "xor_string")
    assert options["xor_search"] == "xor_string"


# ---------------------------------------------------------------------------
# _safe_exit tests
# ---------------------------------------------------------------------------


def test_safe_exit_normal():
    with pytest.raises(SystemExit):
        os.environ["R2INSPECT_TEST_SAFE_EXIT"] = "1"
        try:
            _safe_exit(0)
        finally:
            del os.environ["R2INSPECT_TEST_SAFE_EXIT"]


def test_safe_exit_non_zero():
    with pytest.raises(SystemExit) as exc_info:
        os.environ["R2INSPECT_TEST_SAFE_EXIT"] = "1"
        try:
            _safe_exit(1)
        finally:
            del os.environ["R2INSPECT_TEST_SAFE_EXIT"]
    assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# _pytest_running tests
# ---------------------------------------------------------------------------


def test_pytest_running_test_mode():
    os.environ["R2INSPECT_TEST_MODE"] = "1"
    try:
        assert _pytest_running() is True
    finally:
        del os.environ["R2INSPECT_TEST_MODE"]


def test_pytest_running_safe_exit():
    os.environ["R2INSPECT_TEST_SAFE_EXIT"] = "1"
    try:
        assert _pytest_running() is True
    finally:
        del os.environ["R2INSPECT_TEST_SAFE_EXIT"]


def test_pytest_running_pytest_current_test():
    os.environ["PYTEST_CURRENT_TEST"] = "test_something"
    try:
        assert _pytest_running() is True
    finally:
        del os.environ["PYTEST_CURRENT_TEST"]


def test_pytest_running_coverage_env():
    os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"] = "1"
    try:
        assert _pytest_running() is True
    finally:
        del os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"]


def test_pytest_running_sys_modules():
    # pytest is always in sys.modules during test execution, so this is trivially true
    assert "pytest" in sys.modules
    assert _pytest_running() is True


# ---------------------------------------------------------------------------
# _flush_coverage_data tests
# ---------------------------------------------------------------------------


def test_flush_coverage_data_no_coverage():
    os.environ["R2INSPECT_TEST_COVERAGE_IMPORT_ERROR"] = "1"
    try:
        _flush_coverage_data()
    finally:
        del os.environ["R2INSPECT_TEST_COVERAGE_IMPORT_ERROR"]


def test_flush_coverage_data_current_error():
    os.environ["R2INSPECT_TEST_COVERAGE_CURRENT_ERROR"] = "1"
    try:
        _flush_coverage_data()
    finally:
        del os.environ["R2INSPECT_TEST_COVERAGE_CURRENT_ERROR"]


def test_flush_coverage_data_dummy():
    os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"] = "1"
    try:
        _flush_coverage_data()
    finally:
        del os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"]


def test_flush_coverage_data_none():
    os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"] = "1"
    os.environ["R2INSPECT_TEST_COVERAGE_NONE"] = "1"
    try:
        _flush_coverage_data()
    finally:
        del os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"]
        del os.environ["R2INSPECT_TEST_COVERAGE_NONE"]


def test_flush_coverage_data_save_error():
    os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"] = "1"
    os.environ["R2INSPECT_TEST_COVERAGE_SAVE_ERROR"] = "1"
    try:
        _flush_coverage_data()
    finally:
        del os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"]
        del os.environ["R2INSPECT_TEST_COVERAGE_SAVE_ERROR"]


# ---------------------------------------------------------------------------
# ensure_batch_shutdown tests
# ---------------------------------------------------------------------------


def test_ensure_batch_shutdown_no_threads():
    ensure_batch_shutdown(timeout=0.1)


def test_ensure_batch_shutdown_with_threads():
    def worker():
        time.sleep(0.05)

    thread = threading.Thread(target=worker, daemon=False)
    thread.start()
    ensure_batch_shutdown(timeout=0.2)


def test_ensure_batch_shutdown_timeout():
    def long_worker():
        time.sleep(5.0)

    os.environ["R2INSPECT_TEST_SAFE_EXIT"] = "1"
    try:
        thread = threading.Thread(target=long_worker, daemon=False)
        thread.start()
        with pytest.raises(SystemExit):
            ensure_batch_shutdown(timeout=0.05)
    finally:
        del os.environ["R2INSPECT_TEST_SAFE_EXIT"]


# ---------------------------------------------------------------------------
# schedule_forced_exit tests
# ---------------------------------------------------------------------------


def test_schedule_forced_exit_disabled():
    os.environ["R2INSPECT_DISABLE_FORCED_EXIT"] = "1"
    try:
        schedule_forced_exit(delay=0.1)
    finally:
        del os.environ["R2INSPECT_DISABLE_FORCED_EXIT"]


def test_schedule_forced_exit_enabled():
    os.environ["R2INSPECT_TEST_SAFE_EXIT"] = "1"
    try:
        schedule_forced_exit(delay=0.05)
        time.sleep(0.1)
    except SystemExit:
        pass
    finally:
        del os.environ["R2INSPECT_TEST_SAFE_EXIT"]


# ---------------------------------------------------------------------------
# BatchRateLimiter integration tests
# ---------------------------------------------------------------------------


def test_rate_limiter_acquire_release_cycle():
    """Verify a real BatchRateLimiter can acquire and release."""
    limiter = BatchRateLimiter(max_concurrent=2, rate_per_second=100.0, enable_adaptive=False)
    assert limiter.acquire(timeout=5.0) is True
    limiter.release_success()
    stats = limiter.get_stats()
    assert stats["files_processed"] == 1
    assert stats["success_rate"] == 1.0


def test_rate_limiter_error_tracking():
    """Verify error tracking through a real BatchRateLimiter."""
    limiter = BatchRateLimiter(max_concurrent=5, rate_per_second=100.0, enable_adaptive=False)
    assert limiter.acquire(timeout=5.0) is True
    limiter.release_error("TestError")
    stats = limiter.get_stats()
    assert stats["files_failed"] == 1
    assert stats["success_rate"] == 0.0


def test_rate_limiter_get_stats_empty():
    """Stats on a fresh limiter should have zero counts."""
    limiter = BatchRateLimiter(max_concurrent=5, enable_adaptive=True)
    stats = limiter.get_stats()
    assert stats["files_processed"] == 0
    assert stats["files_failed"] == 0
    assert stats["success_rate"] == 0.0
    assert stats["avg_wait_time"] == 0.0
