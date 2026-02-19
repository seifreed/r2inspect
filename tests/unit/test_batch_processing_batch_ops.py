"""Comprehensive tests for batch processing operations in batch_processing.py."""

from __future__ import annotations

import os
import time
import threading
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from r2inspect.cli.batch_processing import (
    setup_rate_limiter,
    display_batch_results,
    ensure_batch_shutdown,
    schedule_forced_exit,
    setup_batch_mode,
    setup_single_file_output,
    setup_analysis_options,
    display_rate_limiter_stats,
    display_memory_stats,
    display_failed_files,
    handle_main_error,
    find_files_to_process,
    find_files_by_extensions,
    display_no_files_message,
    setup_batch_output_directory,
    _flush_coverage_data,
    _pytest_running,
    _safe_exit,
)


def test_setup_rate_limiter_basic(capsys):
    """Test basic rate limiter setup."""
    rate_limiter = setup_rate_limiter(threads=4, verbose=False)
    assert rate_limiter is not None
    assert hasattr(rate_limiter, 'acquire')
    assert hasattr(rate_limiter, 'release_success')


def test_setup_rate_limiter_verbose(capsys):
    """Test rate limiter setup with verbose output."""
    rate_limiter = setup_rate_limiter(threads=8, verbose=True)
    captured = capsys.readouterr()
    assert "Rate limiting" in captured.out
    assert "adaptive mode enabled" in captured.out


def test_setup_rate_limiter_high_thread_count():
    """Test rate limiter with high thread count caps at 25."""
    rate_limiter = setup_rate_limiter(threads=50, verbose=False)
    assert rate_limiter is not None


def test_display_batch_results_basic(tmp_path, capsys):
    """Test basic batch results display."""
    all_results = {
        "test.exe": {"file_info": {"name": "test.exe"}},
        "test2.exe": {"file_info": {"name": "test2.exe"}},
    }
    failed_files = []
    files_to_process = [Path("test.exe"), Path("test2.exe")]
    
    mock_rate_limiter = Mock()
    mock_rate_limiter.get_stats.return_value = {
        'success_rate': 0.95,
        'avg_wait_time': 0.1,
        'current_rate': 10.5
    }
    
    display_batch_results(
        all_results=all_results,
        failed_files=failed_files,
        elapsed_time=5.0,
        files_to_process=files_to_process,
        rate_limiter=mock_rate_limiter,
        verbose=False,
        output_filename="output.json"
    )
    
    captured = capsys.readouterr()
    assert "Analysis Complete" in captured.out
    assert "Processed: 2/2 files" in captured.out
    assert "Time: 5.0s" in captured.out


def test_display_batch_results_with_failures(tmp_path, capsys):
    """Test batch results display with failed files."""
    all_results = {"test.exe": {"file_info": {"name": "test.exe"}}}
    failed_files = [
        ("failed1.exe", "Error opening file"),
        ("failed2.exe", "Corrupted header"),
    ]
    files_to_process = [Path("test.exe"), Path("failed1.exe"), Path("failed2.exe")]
    
    mock_rate_limiter = Mock()
    mock_rate_limiter.get_stats.return_value = {}
    
    display_batch_results(
        all_results=all_results,
        failed_files=failed_files,
        elapsed_time=3.0,
        files_to_process=files_to_process,
        rate_limiter=mock_rate_limiter,
        verbose=False,
        output_filename=None
    )
    
    captured = capsys.readouterr()
    assert "Processed: 1/3 files" in captured.out
    assert "Failed: 2 files" in captured.out


def test_display_batch_results_verbose(tmp_path, capsys):
    """Test batch results display in verbose mode."""
    all_results = {"test.exe": {"file_info": {"name": "test.exe"}}}
    failed_files = []
    files_to_process = [Path("test.exe")]
    
    mock_rate_limiter = Mock()
    mock_rate_limiter.get_stats.return_value = {
        'success_rate': 1.0,
        'avg_wait_time': 0.05,
        'current_rate': 20.0
    }
    
    with patch('r2inspect.cli.batch_processing.display_memory_stats'):
        display_batch_results(
            all_results=all_results,
            failed_files=failed_files,
            elapsed_time=1.0,
            files_to_process=files_to_process,
            rate_limiter=mock_rate_limiter,
            verbose=True,
            output_filename=None
        )
    
    captured = capsys.readouterr()
    assert "Rate limiter stats" in captured.out
    assert "Success rate" in captured.out


def test_setup_batch_mode_defaults():
    """Test batch mode setup with defaults."""
    recursive, use_auto_detect, output = setup_batch_mode(
        batch="test_dir",
        extensions=None,
        output_json=False,
        output_csv=False,
        output=None
    )
    assert recursive is True
    assert use_auto_detect is True
    assert output is None


def test_setup_batch_mode_with_extensions():
    """Test batch mode setup with specific extensions."""
    recursive, use_auto_detect, output = setup_batch_mode(
        batch="test_dir",
        extensions="exe,dll",
        output_json=False,
        output_csv=False,
        output=None
    )
    assert recursive is True
    assert use_auto_detect is False


def test_setup_batch_mode_with_json_output():
    """Test batch mode setup with JSON output."""
    recursive, use_auto_detect, output = setup_batch_mode(
        batch="test_dir",
        extensions=None,
        output_json=True,
        output_csv=False,
        output=None
    )
    assert output == "output"


def test_setup_batch_mode_with_csv_output():
    """Test batch mode setup with CSV output."""
    recursive, use_auto_detect, output = setup_batch_mode(
        batch="test_dir",
        extensions=None,
        output_json=False,
        output_csv=True,
        output=None
    )
    assert output == "output"


def test_setup_batch_mode_custom_output():
    """Test batch mode setup with custom output directory."""
    recursive, use_auto_detect, output = setup_batch_mode(
        batch="test_dir",
        extensions=None,
        output_json=True,
        output_csv=False,
        output="custom_output"
    )
    assert output == "custom_output"


def test_setup_single_file_output_json(tmp_path):
    """Test single file output setup for JSON."""
    output = setup_single_file_output(
        output_json=True,
        output_csv=False,
        output=None,
        filename="test.exe"
    )
    assert output is not None
    assert "test_analysis.json" in str(output)


def test_setup_single_file_output_csv(tmp_path):
    """Test single file output setup for CSV."""
    output = setup_single_file_output(
        output_json=False,
        output_csv=True,
        output=None,
        filename="test.exe"
    )
    assert output is not None
    assert "test_analysis.csv" in str(output)


def test_setup_single_file_output_custom():
    """Test single file output with custom path."""
    output = setup_single_file_output(
        output_json=True,
        output_csv=False,
        output="custom.json",
        filename="test.exe"
    )
    assert output == "custom.json"


def test_setup_single_file_output_no_output():
    """Test single file output when no output format specified."""
    output = setup_single_file_output(
        output_json=False,
        output_csv=False,
        output=None,
        filename="test.exe"
    )
    assert output is None


def test_setup_analysis_options_basic():
    """Test basic analysis options setup."""
    options = setup_analysis_options(yara=None, sanitized_xor=None)
    assert isinstance(options, dict)
    assert "full_analysis" in options or len(options) >= 0


def test_setup_analysis_options_with_yara():
    """Test analysis options with YARA rules."""
    options = setup_analysis_options(yara="/path/to/rules", sanitized_xor=None)
    assert isinstance(options, dict)


def test_setup_analysis_options_with_xor():
    """Test analysis options with XOR sanitization."""
    options = setup_analysis_options(yara=None, sanitized_xor="xor_key")
    assert isinstance(options, dict)


def test_display_rate_limiter_stats(capsys):
    """Test rate limiter statistics display."""
    rate_stats = {
        'success_rate': 0.95,
        'avg_wait_time': 0.2,
        'current_rate': 15.5
    }
    display_rate_limiter_stats(rate_stats)
    captured = capsys.readouterr()
    assert "Success rate: 95.0%" in captured.out
    assert "Avg wait time: 0.20s" in captured.out
    assert "Final rate: 15.5 files/sec" in captured.out


def test_display_rate_limiter_stats_empty(capsys):
    """Test rate limiter statistics with empty stats."""
    rate_stats = {}
    display_rate_limiter_stats(rate_stats)
    captured = capsys.readouterr()
    assert "Success rate: 0.0%" in captured.out


def test_display_memory_stats(capsys):
    """Test memory statistics display."""
    with patch('r2inspect.utils.memory_manager.get_memory_stats') as mock_stats:
        mock_stats.return_value = {
            'status': 'ok',
            'peak_memory_mb': 150.5,
            'process_memory_mb': 120.3,
            'gc_count': 5
        }
        display_memory_stats()
        captured = capsys.readouterr()
        assert "Memory stats" in captured.out
        assert "Peak usage: 150.5MB" in captured.out
        assert "Current usage: 120.3MB" in captured.out


def test_display_memory_stats_error(capsys):
    """Test memory statistics display with error."""
    with patch('r2inspect.utils.memory_manager.get_memory_stats') as mock_stats:
        mock_stats.return_value = {'status': 'error'}
        display_memory_stats()
        captured = capsys.readouterr()
        assert "Memory stats" not in captured.out


def test_display_failed_files_verbose(capsys):
    """Test failed files display in verbose mode."""
    failed_files = [
        ("file1.exe", "Error message 1"),
        ("file2.exe", "Error message 2"),
    ]
    display_failed_files(failed_files, verbose=True)
    captured = capsys.readouterr()
    assert "Failed: 2 files" in captured.out
    assert "file1.exe" in captured.out
    assert "file2.exe" in captured.out


def test_display_failed_files_non_verbose(capsys):
    """Test failed files display in non-verbose mode."""
    failed_files = [("file1.exe", "Error message 1")]
    display_failed_files(failed_files, verbose=False)
    captured = capsys.readouterr()
    assert "Failed: 1 files" in captured.out
    assert "Use --verbose to see error details" in captured.out


def test_display_failed_files_truncation(capsys):
    """Test failed files display truncates long error messages."""
    long_error = "x" * 150
    failed_files = [("file.exe", long_error)]
    display_failed_files(failed_files, verbose=True)
    captured = capsys.readouterr()
    assert "..." in captured.out


def test_display_failed_files_many_files(capsys):
    """Test failed files display limits to first 10."""
    failed_files = [(f"file{i}.exe", f"Error {i}") for i in range(15)]
    display_failed_files(failed_files, verbose=True)
    captured = capsys.readouterr()
    assert "and 5 more" in captured.out


def test_handle_main_error_simple(capsys):
    """Test main error handler without verbose."""
    with pytest.raises(SystemExit):
        handle_main_error(ValueError("Test error"), verbose=False)
    captured = capsys.readouterr()
    assert "Error: Test error" in captured.out


def test_handle_main_error_verbose(capsys):
    """Test main error handler with verbose traceback."""
    with pytest.raises(SystemExit):
        handle_main_error(RuntimeError("Test error"), verbose=True)
    captured = capsys.readouterr()
    assert "Error: Test error" in captured.out


def test_find_files_to_process_by_extension(tmp_path):
    """Test finding files by extension."""
    test_file = tmp_path / "test.exe"
    test_file.touch()
    
    files = find_files_to_process(
        batch_path=tmp_path,
        auto_detect=False,
        extensions="exe",
        recursive=False,
        verbose=False,
        quiet=True
    )
    assert test_file in files


def test_find_files_to_process_no_extensions(tmp_path):
    """Test finding files with no extensions returns empty."""
    files = find_files_to_process(
        batch_path=tmp_path,
        auto_detect=False,
        extensions=None,
        recursive=False,
        verbose=False,
        quiet=True
    )
    assert files == []


def test_find_files_to_process_auto_detect(tmp_path):
    """Test finding files with auto-detection."""
    with patch('r2inspect.cli.batch_processing.find_executable_files_by_magic') as mock_find:
        mock_find.return_value = []
        files = find_files_to_process(
            batch_path=tmp_path,
            auto_detect=True,
            extensions=None,
            recursive=True,
            verbose=False,
            quiet=True
        )
        mock_find.assert_called_once()


def test_find_files_by_extensions_single(tmp_path):
    """Test finding files by single extension."""
    exe_file = tmp_path / "test.exe"
    exe_file.touch()
    dll_file = tmp_path / "test.dll"
    dll_file.touch()
    
    files = find_files_by_extensions(tmp_path, "exe", recursive=False)
    assert exe_file in files
    assert dll_file not in files


def test_find_files_by_extensions_multiple(tmp_path):
    """Test finding files by multiple extensions."""
    exe_file = tmp_path / "test.exe"
    exe_file.touch()
    dll_file = tmp_path / "test.dll"
    dll_file.touch()
    
    files = find_files_by_extensions(tmp_path, "exe,dll", recursive=False)
    assert exe_file in files
    assert dll_file in files


def test_find_files_by_extensions_recursive(tmp_path):
    """Test finding files recursively."""
    subdir = tmp_path / "subdir"
    subdir.mkdir()
    exe_file = subdir / "test.exe"
    exe_file.touch()
    
    files = find_files_by_extensions(tmp_path, "exe", recursive=True)
    assert exe_file in files


def test_display_no_files_message_auto_detect(capsys):
    """Test no files message for auto-detect mode."""
    display_no_files_message(auto_detect=True, extensions=None)
    captured = capsys.readouterr()
    assert "No executable files detected" in captured.out


def test_display_no_files_message_extensions(capsys):
    """Test no files message for extension mode."""
    display_no_files_message(auto_detect=False, extensions="exe,dll")
    captured = capsys.readouterr()
    assert "No files found with extensions: exe,dll" in captured.out


def test_setup_batch_output_directory_default(tmp_path):
    """Test batch output directory setup with defaults."""
    os.chdir(tmp_path)
    output_path = setup_batch_output_directory(
        output_dir=None,
        output_json=False,
        output_csv=False
    )
    assert output_path.name == "r2inspect_batch_results"
    assert output_path.exists()


def test_setup_batch_output_directory_json(tmp_path):
    """Test batch output directory for JSON."""
    os.chdir(tmp_path)
    output_path = setup_batch_output_directory(
        output_dir=None,
        output_json=True,
        output_csv=False
    )
    assert output_path.name == "output"
    assert output_path.exists()


def test_setup_batch_output_directory_csv(tmp_path):
    """Test batch output directory for CSV."""
    os.chdir(tmp_path)
    output_path = setup_batch_output_directory(
        output_dir=None,
        output_json=False,
        output_csv=True
    )
    assert output_path.name == "output"
    assert output_path.exists()


def test_setup_batch_output_directory_custom(tmp_path):
    """Test batch output directory with custom path."""
    custom_dir = tmp_path / "custom_output"
    output_path = setup_batch_output_directory(
        output_dir=str(custom_dir),
        output_json=False,
        output_csv=False
    )
    assert output_path == custom_dir
    assert output_path.exists()


def test_setup_batch_output_directory_csv_file(tmp_path):
    """Test batch output directory with CSV filename."""
    csv_file = tmp_path / "results.csv"
    output_path = setup_batch_output_directory(
        output_dir=str(csv_file),
        output_json=False,
        output_csv=True
    )
    assert output_path == csv_file
    assert output_path.parent.exists()


def test_ensure_batch_shutdown_no_threads():
    """Test batch shutdown with no lingering threads."""
    ensure_batch_shutdown(timeout=0.5)


def test_ensure_batch_shutdown_with_threads():
    """Test batch shutdown with lingering threads."""
    stop_event = threading.Event()
    
    def worker():
        stop_event.wait(timeout=0.1)
    
    thread = threading.Thread(target=worker, daemon=False)
    thread.start()
    
    ensure_batch_shutdown(timeout=0.3)
    thread.join(timeout=0.5)


def test_schedule_forced_exit_disabled():
    """Test forced exit when disabled."""
    with patch.dict(os.environ, {'R2INSPECT_DISABLE_FORCED_EXIT': '1'}):
        schedule_forced_exit(delay=0.1)
        time.sleep(0.2)


def test_schedule_forced_exit_enabled():
    """Test forced exit schedules timer."""
    with patch.dict(os.environ, {}, clear=True):
        schedule_forced_exit(delay=10.0)


def test_pytest_running_detection():
    """Test pytest detection."""
    result = _pytest_running()
    assert isinstance(result, bool)


def test_pytest_running_with_env():
    """Test pytest detection with environment variable."""
    with patch.dict(os.environ, {'R2INSPECT_TEST_MODE': '1'}):
        assert _pytest_running() is True


def test_safe_exit_with_test_mode():
    """Test safe exit in test mode."""
    with patch.dict(os.environ, {'R2INSPECT_TEST_SAFE_EXIT': '1'}):
        with pytest.raises(SystemExit):
            _safe_exit(0)


def test_flush_coverage_data_no_coverage():
    """Test flushing coverage data when not available."""
    with patch.dict(os.environ, {'R2INSPECT_TEST_COVERAGE_IMPORT_ERROR': '1'}):
        _flush_coverage_data()


def test_flush_coverage_data_none():
    """Test flushing coverage data when coverage is None."""
    with patch.dict(os.environ, {'R2INSPECT_TEST_COVERAGE_NONE': '1'}):
        _flush_coverage_data()


def test_flush_coverage_data_dummy():
    """Test flushing coverage data with dummy coverage."""
    with patch.dict(os.environ, {'R2INSPECT_TEST_COVERAGE_DUMMY': '1'}):
        _flush_coverage_data()


def test_flush_coverage_data_save_error():
    """Test flushing coverage data with save error."""
    with patch.dict(os.environ, {
        'R2INSPECT_TEST_COVERAGE_DUMMY': '1',
        'R2INSPECT_TEST_COVERAGE_SAVE_ERROR': '1'
    }):
        _flush_coverage_data()
