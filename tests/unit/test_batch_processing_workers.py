#!/usr/bin/env python3
"""Comprehensive tests for r2inspect/cli/batch_processing.py"""

import os
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, Mock, call, patch

import pytest

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
    run_batch_analysis,
    schedule_forced_exit,
    setup_analysis_options,
    setup_batch_mode,
    setup_batch_output_directory,
    setup_rate_limiter,
    setup_single_file_output,
)


def test_check_executable_signature_pe(tmp_path):
    pe_file = tmp_path / "test.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 58 + (64).to_bytes(4, "little") + b"\x00" * 4 + b"PE\x00\x00")
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


def test_setup_rate_limiter_default():
    with patch("r2inspect.utils.rate_limiter.BatchRateLimiter") as mock_limiter:
        with patch("r2inspect.cli.batch_processing._cap_threads_for_execution", return_value=10):
            setup_rate_limiter(10, verbose=False)
            mock_limiter.assert_called_once()


def test_setup_rate_limiter_verbose():
    with patch("r2inspect.utils.rate_limiter.BatchRateLimiter") as mock_limiter:
        with patch("r2inspect.cli.batch_processing._cap_threads_for_execution", return_value=5):
            with patch("r2inspect.cli.batch_processing.console") as mock_console:
                setup_rate_limiter(5, verbose=True)
                mock_console.print.assert_called_once()


def test_setup_rate_limiter_adaptive_rate():
    with patch("r2inspect.utils.rate_limiter.BatchRateLimiter") as mock_limiter:
        with patch("r2inspect.cli.batch_processing._cap_threads_for_execution", return_value=20):
            setup_rate_limiter(20, verbose=False)
            call_args = mock_limiter.call_args
            assert call_args[1]["enable_adaptive"] is True
            assert call_args[1]["max_concurrent"] == 20


def test_find_executable_files_by_magic_no_magic(tmp_path):
    with patch("r2inspect.cli.batch_processing.magic", None):
        with patch("r2inspect.cli.batch_processing.console") as mock_console:
            with patch("r2inspect.cli.batch_processing.discover_executables_by_magic") as mock_discover:
                mock_discover.return_value = ([], ["Error initializing magic: test"], [], 0)
                result = find_executable_files_by_magic(tmp_path, recursive=False, verbose=False)
                assert result == []
                assert mock_console.print.call_count >= 2


def test_find_executable_files_by_magic_with_verbose(tmp_path):
    pe_file = tmp_path / "test.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)

    with patch("r2inspect.cli.batch_processing.discover_executables_by_magic") as mock_discover:
        mock_discover.return_value = ([pe_file], [], [], 1)
        with patch("r2inspect.cli.batch_processing.console") as mock_console:
            result = find_executable_files_by_magic(tmp_path, recursive=False, verbose=True)
            assert len(result) == 1
            assert mock_console.print.call_count >= 2


def test_find_executable_files_by_magic_with_errors(tmp_path):
    with patch("r2inspect.cli.batch_processing.discover_executables_by_magic") as mock_discover:
        mock_discover.return_value = ([], [], [(Path("file.exe"), "Error reading file")], 1)
        with patch("r2inspect.cli.batch_processing.console") as mock_console:
            result = find_executable_files_by_magic(tmp_path, recursive=False, verbose=True)
            assert result == []
            assert mock_console.print.call_count >= 2


def test_find_executable_files_by_magic_init_error(tmp_path):
    with patch("r2inspect.cli.batch_processing.discover_executables_by_magic") as mock_discover:
        mock_discover.return_value = ([], ["Error initializing magic: test error"], [], 0)
        with patch("r2inspect.cli.batch_processing.console") as mock_console:
            result = find_executable_files_by_magic(tmp_path, recursive=False, verbose=False)
            assert result == []
            assert mock_console.print.call_count >= 2


def test_display_batch_results_basic():
    all_results = {"file1.exe": {"name": "file1.exe"}}
    failed_files = []
    elapsed_time = 10.5
    files_to_process = [Path("file1.exe")]
    rate_limiter = Mock()
    rate_limiter.get_stats.return_value = {"success_rate": 0.95, "avg_wait_time": 0.1, "current_rate": 5.0}

    with patch("r2inspect.cli.batch_processing.console") as mock_console:
        display_batch_results(all_results, failed_files, elapsed_time, files_to_process, rate_limiter, False, None)
        assert mock_console.print.call_count >= 3


def test_display_batch_results_with_failures():
    all_results = {}
    failed_files = [("file1.exe", "Error 1"), ("file2.exe", "Error 2")]
    elapsed_time = 5.0
    files_to_process = [Path("file1.exe"), Path("file2.exe")]
    rate_limiter = Mock()
    rate_limiter.get_stats.return_value = {}

    with patch("r2inspect.cli.batch_processing.console") as mock_console:
        with patch("r2inspect.cli.batch_processing.display_failed_files") as mock_failed:
            display_batch_results(all_results, failed_files, elapsed_time, files_to_process, rate_limiter, False, None)
            mock_failed.assert_called_once()


def test_display_batch_results_verbose():
    all_results = {"file1.exe": {}}
    failed_files = []
    elapsed_time = 3.0
    files_to_process = [Path("file1.exe")]
    rate_limiter = Mock()
    rate_limiter.get_stats.return_value = {"success_rate": 1.0}

    with patch("r2inspect.cli.batch_processing.console"):
        with patch("r2inspect.cli.batch_processing.display_rate_limiter_stats") as mock_rate:
            with patch("r2inspect.cli.batch_processing.display_memory_stats") as mock_mem:
                display_batch_results(
                    all_results, failed_files, elapsed_time, files_to_process, rate_limiter, True, "output.json"
                )
                mock_rate.assert_called_once()
                mock_mem.assert_called_once()


def test_display_rate_limiter_stats():
    rate_stats = {"success_rate": 0.98, "avg_wait_time": 0.25, "current_rate": 8.5}
    with patch("r2inspect.cli.batch_processing.console") as mock_console:
        display_rate_limiter_stats(rate_stats)
        assert mock_console.print.call_count == 4


def test_display_rate_limiter_stats_empty():
    rate_stats = {}
    with patch("r2inspect.cli.batch_processing.console") as mock_console:
        display_rate_limiter_stats(rate_stats)
        assert mock_console.print.call_count == 4


def test_display_memory_stats_success():
    with patch("r2inspect.utils.memory_manager.get_memory_stats") as mock_stats:
        mock_stats.return_value = {
            "status": "ok",
            "peak_memory_mb": 256.5,
            "process_memory_mb": 128.3,
            "gc_count": 10,
        }
        with patch("r2inspect.cli.batch_processing.console") as mock_console:
            display_memory_stats()
            assert mock_console.print.call_count == 4


def test_display_memory_stats_error():
    with patch("r2inspect.utils.memory_manager.get_memory_stats") as mock_stats:
        mock_stats.return_value = {"status": "error"}
        with patch("r2inspect.cli.batch_processing.console") as mock_console:
            display_memory_stats()
            mock_console.print.assert_not_called()


def test_display_memory_stats_missing_fields():
    with patch("r2inspect.utils.memory_manager.get_memory_stats") as mock_stats:
        mock_stats.return_value = {"status": "ok"}
        with patch("r2inspect.cli.batch_processing.console") as mock_console:
            display_memory_stats()
            assert mock_console.print.call_count == 4


def test_display_failed_files_verbose():
    failed_files = [("file1.exe", "Error 1"), ("file2.exe", "Error 2")]
    with patch("r2inspect.cli.batch_processing.console") as mock_console:
        display_failed_files(failed_files, verbose=True)
        assert mock_console.print.call_count >= 3


def test_display_failed_files_non_verbose():
    failed_files = [("file1.exe", "Error 1")]
    with patch("r2inspect.cli.batch_processing.console") as mock_console:
        display_failed_files(failed_files, verbose=False)
        assert mock_console.print.call_count == 2


def test_display_failed_files_many():
    failed_files = [(f"file{i}.exe", f"Error {i}") for i in range(15)]
    with patch("r2inspect.cli.batch_processing.console") as mock_console:
        display_failed_files(failed_files, verbose=True)
        assert mock_console.print.call_count >= 12


def test_display_failed_files_long_error():
    failed_files = [("file.exe", "x" * 200)]
    with patch("r2inspect.cli.batch_processing.console") as mock_console:
        display_failed_files(failed_files, verbose=True)
        mock_console.print.assert_called()


def test_handle_main_error_verbose():
    error = ValueError("Test error")
    with patch("r2inspect.cli.batch_processing.console") as mock_console:
        with patch("traceback.print_exc") as mock_traceback:
            with pytest.raises(SystemExit):
                handle_main_error(error, verbose=True)
            mock_traceback.assert_called_once()


def test_handle_main_error_non_verbose():
    error = RuntimeError("Test error")
    with patch("r2inspect.cli.batch_processing.console") as mock_console:
        with pytest.raises(SystemExit):
            handle_main_error(error, verbose=False)
        mock_console.print.assert_called_once()


def test_find_files_to_process_auto_detect(tmp_path):
    with patch("r2inspect.cli.batch_processing.find_executable_files_by_magic") as mock_find:
        mock_find.return_value = [Path("file1.exe")]
        with patch("r2inspect.cli.batch_processing.console"):
            result = find_files_to_process(tmp_path, auto_detect=True, extensions=None, recursive=True, verbose=False)
            assert len(result) == 1
            mock_find.assert_called_once()


def test_find_files_to_process_extensions(tmp_path):
    (tmp_path / "file.exe").write_text("test")
    with patch("r2inspect.cli.batch_processing.console"):
        result = find_files_to_process(tmp_path, auto_detect=False, extensions="exe", recursive=False, verbose=False)
        assert len(result) == 1


def test_find_files_to_process_no_extensions():
    with patch("r2inspect.cli.batch_processing.console"):
        result = find_files_to_process(
            Path("."), auto_detect=False, extensions=None, recursive=False, verbose=False
        )
        assert result == []


def test_find_files_to_process_quiet(tmp_path):
    with patch("r2inspect.cli.batch_processing.find_executable_files_by_magic") as mock_find:
        mock_find.return_value = []
        with patch("r2inspect.cli.batch_processing.console") as mock_console:
            find_files_to_process(tmp_path, auto_detect=True, extensions=None, recursive=False, verbose=False, quiet=True)
            mock_console.print.assert_not_called()


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


def test_display_no_files_message_auto_detect():
    with patch("r2inspect.cli.batch_processing.console") as mock_console:
        display_no_files_message(auto_detect=True, extensions=None)
        assert mock_console.print.call_count == 2


def test_display_no_files_message_extensions():
    with patch("r2inspect.cli.batch_processing.console") as mock_console:
        display_no_files_message(auto_detect=False, extensions="exe,dll")
        assert mock_console.print.call_count == 2


def test_setup_batch_output_directory_json(tmp_path):
    output_dir = tmp_path / "output"
    result = setup_batch_output_directory(str(output_dir), output_json=True, output_csv=False)
    assert result.exists()
    assert result == output_dir


def test_setup_batch_output_directory_csv_file(tmp_path):
    output_file = tmp_path / "results" / "output.csv"
    result = setup_batch_output_directory(str(output_file), output_json=False, output_csv=True)
    assert result.parent.exists()


def test_setup_batch_output_directory_default():
    result = setup_batch_output_directory(None, output_json=False, output_csv=False)
    assert result.name == "r2inspect_batch_results"


def test_setup_batch_output_directory_json_default():
    with patch("pathlib.Path.mkdir"):
        result = setup_batch_output_directory(None, output_json=True, output_csv=False)
        assert result.name == "output"


def test_setup_batch_output_directory_existing(tmp_path):
    output_dir = tmp_path / "existing"
    output_dir.mkdir()
    result = setup_batch_output_directory(str(output_dir), output_json=True, output_csv=False)
    assert result.exists()


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


def test_setup_single_file_output_json(tmp_path):
    result = setup_single_file_output(True, False, None, "test.exe")
    assert str(result).endswith("_analysis.json")


def test_setup_single_file_output_csv(tmp_path):
    result = setup_single_file_output(False, True, None, "test.exe")
    assert str(result).endswith("_analysis.csv")


def test_setup_single_file_output_custom():
    result = setup_single_file_output(True, False, "custom.json", "test.exe")
    assert result == "custom.json"


def test_setup_single_file_output_none():
    result = setup_single_file_output(False, False, None, "test.exe")
    assert result is None


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
    sys.modules["pytest"] = MagicMock()
    try:
        assert _pytest_running() is True
    finally:
        del sys.modules["pytest"]


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


def test_run_batch_analysis_integration(tmp_path):
    (tmp_path / "test.exe").write_bytes(b"MZ" + b"\x00" * 100)

    with patch("r2inspect.cli.batch_processing.default_batch_service") as mock_service:
        run_batch_analysis(
            batch_dir=str(tmp_path),
            options={},
            output_json=False,
            output_csv=False,
            output_dir=None,
            recursive=False,
            extensions="exe",
            verbose=False,
            config_obj=MagicMock(),
            auto_detect=False,
            threads=1,
            quiet=False,
        )
        mock_service.run_batch_analysis.assert_called_once()


def test_run_batch_analysis_quiet(tmp_path):
    with patch("r2inspect.cli.batch_processing.default_batch_service") as mock_service:
        run_batch_analysis(
            batch_dir=str(tmp_path),
            options={},
            output_json=False,
            output_csv=False,
            output_dir=None,
            recursive=False,
            extensions=None,
            verbose=False,
            config_obj=MagicMock(),
            auto_detect=True,
            threads=1,
            quiet=True,
        )
        mock_service.run_batch_analysis.assert_called_once()
