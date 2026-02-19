from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import Mock

from r2inspect.cli import batch_processing


def test_flush_coverage_data_import_error() -> None:
    """Test _flush_coverage_data when coverage import fails"""
    os.environ["R2INSPECT_TEST_COVERAGE_IMPORT_ERROR"] = "1"
    try:
        batch_processing._flush_coverage_data()
        # Should not raise
    finally:
        del os.environ["R2INSPECT_TEST_COVERAGE_IMPORT_ERROR"]


def test_flush_coverage_data_current_error() -> None:
    """Test _flush_coverage_data when Coverage.current() fails"""
    os.environ["R2INSPECT_TEST_COVERAGE_CURRENT_ERROR"] = "1"
    try:
        batch_processing._flush_coverage_data()
        # Should not raise
    finally:
        del os.environ["R2INSPECT_TEST_COVERAGE_CURRENT_ERROR"]


def test_flush_coverage_data_none() -> None:
    """Test _flush_coverage_data when cov is None"""
    os.environ["R2INSPECT_TEST_COVERAGE_NONE"] = "1"
    os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"] = "1"
    try:
        batch_processing._flush_coverage_data()
        # Should not raise
    finally:
        del os.environ["R2INSPECT_TEST_COVERAGE_NONE"]
        del os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"]


def test_flush_coverage_data_save_error() -> None:
    """Test _flush_coverage_data when save() fails"""
    os.environ["R2INSPECT_TEST_COVERAGE_SAVE_ERROR"] = "1"
    os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"] = "1"
    try:
        batch_processing._flush_coverage_data()
        # Should not raise
    finally:
        del os.environ["R2INSPECT_TEST_COVERAGE_SAVE_ERROR"]
        del os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"]


def test_flush_coverage_data_pytest_running() -> None:
    """Test _flush_coverage_data when pytest is running"""
    os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"] = "1"
    os.environ["R2INSPECT_TEST_MODE"] = "1"
    try:
        batch_processing._flush_coverage_data()
        # Should call save() but not stop()
    finally:
        del os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"]
        del os.environ["R2INSPECT_TEST_MODE"]


def test_pytest_running_test_mode() -> None:
    """Test _pytest_running detects R2INSPECT_TEST_MODE"""
    os.environ["R2INSPECT_TEST_MODE"] = "1"
    try:
        assert batch_processing._pytest_running() is True
    finally:
        del os.environ["R2INSPECT_TEST_MODE"]


def test_pytest_running_test_mode_true() -> None:
    """Test _pytest_running detects R2INSPECT_TEST_MODE=true"""
    os.environ["R2INSPECT_TEST_MODE"] = "true"
    try:
        assert batch_processing._pytest_running() is True
    finally:
        del os.environ["R2INSPECT_TEST_MODE"]


def test_pytest_running_test_mode_yes() -> None:
    """Test _pytest_running detects R2INSPECT_TEST_MODE=yes"""
    os.environ["R2INSPECT_TEST_MODE"] = "yes"
    try:
        assert batch_processing._pytest_running() is True
    finally:
        del os.environ["R2INSPECT_TEST_MODE"]


def test_pytest_running_safe_exit() -> None:
    """Test _pytest_running detects R2INSPECT_TEST_SAFE_EXIT"""
    os.environ["R2INSPECT_TEST_SAFE_EXIT"] = "1"
    try:
        assert batch_processing._pytest_running() is True
    finally:
        del os.environ["R2INSPECT_TEST_SAFE_EXIT"]


def test_pytest_running_pytest_current_test() -> None:
    """Test _pytest_running detects PYTEST_CURRENT_TEST"""
    os.environ["PYTEST_CURRENT_TEST"] = "test_file.py::test_name"
    try:
        assert batch_processing._pytest_running() is True
    finally:
        del os.environ["PYTEST_CURRENT_TEST"]


def test_pytest_running_coverage_env() -> None:
    """Test _pytest_running detects R2INSPECT_TEST_COVERAGE_* env vars"""
    os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"] = "1"
    try:
        assert batch_processing._pytest_running() is True
    finally:
        del os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"]


def test_pytest_running_pytest_in_argv() -> None:
    """Test _pytest_running detects pytest in sys.argv"""
    original_argv = sys.argv.copy()
    try:
        sys.argv = ["pytest", "tests/"]
        assert batch_processing._pytest_running() is True
    finally:
        sys.argv = original_argv


def test_pytest_running_pytest_in_modules() -> None:
    """Test _pytest_running detects pytest in sys.modules"""
    # pytest is already imported in test environment
    assert batch_processing._pytest_running() is True


def test_safe_exit_test_mode() -> None:
    """Test _safe_exit raises SystemExit in test mode"""
    os.environ["R2INSPECT_TEST_SAFE_EXIT"] = "1"
    try:
        try:
            batch_processing._safe_exit(42)
        except SystemExit as e:
            assert e.code == 42
    finally:
        del os.environ["R2INSPECT_TEST_SAFE_EXIT"]


def test_ensure_batch_shutdown_no_threads() -> None:
    """Test ensure_batch_shutdown with no non-daemon threads"""
    batch_processing.ensure_batch_shutdown(timeout=0.1)
    # Should complete without hanging


def test_schedule_forced_exit_disabled() -> None:
    """Test schedule_forced_exit when disabled"""
    os.environ["R2INSPECT_DISABLE_FORCED_EXIT"] = "1"
    try:
        batch_processing.schedule_forced_exit(delay=0.1)
        # Should return immediately without scheduling
    finally:
        del os.environ["R2INSPECT_DISABLE_FORCED_EXIT"]


def test_setup_batch_mode_with_extensions() -> None:
    """Test setup_batch_mode with extensions specified"""
    recursive, use_auto_detect, output = batch_processing.setup_batch_mode(
        batch="/tmp",
        extensions=".exe,.dll",
        output_json=False,
        output_csv=False,
        output=None,
    )
    
    assert recursive is True
    assert use_auto_detect is False  # Extensions specified
    assert output is None


def test_setup_batch_mode_no_extensions_with_output() -> None:
    """Test setup_batch_mode without extensions but with output formats"""
    recursive, use_auto_detect, output = batch_processing.setup_batch_mode(
        batch="/tmp",
        extensions=None,
        output_json=True,
        output_csv=False,
        output=None,
    )
    
    assert recursive is True
    assert use_auto_detect is True  # No extensions
    assert output == "output"  # Default output dir


def test_setup_batch_mode_with_output_specified() -> None:
    """Test setup_batch_mode with output already specified"""
    recursive, use_auto_detect, output = batch_processing.setup_batch_mode(
        batch="/tmp",
        extensions=None,
        output_json=True,
        output_csv=False,
        output="/custom/path",
    )
    
    assert output == "/custom/path"


def test_setup_single_file_output_json() -> None:
    """Test setup_single_file_output for JSON output"""
    output = batch_processing.setup_single_file_output(
        output_json=True,
        output_csv=False,
        output=None,
        filename="/tmp/test.exe",
    )
    
    assert output is not None
    assert str(output).endswith("_analysis.json")


def test_setup_single_file_output_csv() -> None:
    """Test setup_single_file_output for CSV output"""
    output = batch_processing.setup_single_file_output(
        output_json=False,
        output_csv=True,
        output=None,
        filename="/tmp/test.exe",
    )
    
    assert output is not None
    assert str(output).endswith("_analysis.csv")


def test_setup_single_file_output_no_formats() -> None:
    """Test setup_single_file_output with no output formats"""
    output = batch_processing.setup_single_file_output(
        output_json=False,
        output_csv=False,
        output=None,
        filename="/tmp/test.exe",
    )
    
    assert output is None


def test_setup_single_file_output_specified() -> None:
    """Test setup_single_file_output with output already specified"""
    output = batch_processing.setup_single_file_output(
        output_json=True,
        output_csv=False,
        output="/custom/output.json",
        filename="/tmp/test.exe",
    )
    
    assert output == "/custom/output.json"


def test_display_rate_limiter_stats() -> None:
    """Test display_rate_limiter_stats"""
    rate_stats = {
        "success_rate": 0.95,
        "avg_wait_time": 0.05,
        "current_rate": 10.5,
    }
    
    batch_processing.display_rate_limiter_stats(rate_stats)
    # Should not raise


def test_display_memory_stats() -> None:
    """Test display_memory_stats"""
    batch_processing.display_memory_stats()
    # Should not raise even if memory stats unavailable


def test_display_failed_files_verbose() -> None:
    """Test display_failed_files in verbose mode"""
    failed_files = [
        ("/tmp/file1.exe", "Error: File not found"),
        ("/tmp/file2.exe", "Error: Permission denied"),
    ]
    
    batch_processing.display_failed_files(failed_files, verbose=True)
    # Should not raise


def test_display_failed_files_not_verbose() -> None:
    """Test display_failed_files in non-verbose mode"""
    failed_files = [
        ("/tmp/file1.exe", "Error: File not found"),
    ]
    
    batch_processing.display_failed_files(failed_files, verbose=False)
    # Should not raise


def test_display_failed_files_many_errors() -> None:
    """Test display_failed_files with many errors (>10)"""
    failed_files = [(f"/tmp/file{i}.exe", f"Error {i}") for i in range(15)]
    
    batch_processing.display_failed_files(failed_files, verbose=True)
    # Should show first 10 and summary


def test_handle_main_error_verbose() -> None:
    """Test handle_main_error in verbose mode"""
    try:
        batch_processing.handle_main_error(RuntimeError("Test error"), verbose=True)
    except SystemExit as e:
        assert e.code == 1


def test_handle_main_error_not_verbose() -> None:
    """Test handle_main_error in non-verbose mode"""
    try:
        batch_processing.handle_main_error(RuntimeError("Test error"), verbose=False)
    except SystemExit as e:
        assert e.code == 1


def test_display_no_files_message_auto_detect() -> None:
    """Test display_no_files_message with auto_detect=True"""
    batch_processing.display_no_files_message(auto_detect=True, extensions=None)
    # Should not raise


def test_display_no_files_message_extensions() -> None:
    """Test display_no_files_message with extensions"""
    batch_processing.display_no_files_message(auto_detect=False, extensions=".exe,.dll")
    # Should not raise


def test_setup_batch_output_directory_with_filename() -> None:
    """Test setup_batch_output_directory when output is a filename"""
    import tempfile
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_file = Path(tmpdir) / "subdir" / "results.json"
        result = batch_processing.setup_batch_output_directory(
            output_dir=str(output_file),
            output_json=True,
            output_csv=False,
        )
        
        # Parent directory should be created
        assert output_file.parent.exists()


def test_setup_batch_output_directory_with_dir() -> None:
    """Test setup_batch_output_directory when output is a directory"""
    import tempfile
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_dir = Path(tmpdir) / "results"
        result = batch_processing.setup_batch_output_directory(
            output_dir=str(output_dir),
            output_json=True,
            output_csv=False,
        )
        
        assert result.exists()
        assert result.is_dir()


def test_setup_batch_output_directory_none_with_formats() -> None:
    """Test setup_batch_output_directory with None output but formats specified"""
    result = batch_processing.setup_batch_output_directory(
        output_dir=None,
        output_json=True,
        output_csv=False,
    )
    
    assert result.name == "output"


def test_setup_batch_output_directory_none_no_formats() -> None:
    """Test setup_batch_output_directory with None output and no formats"""
    result = batch_processing.setup_batch_output_directory(
        output_dir=None,
        output_json=False,
        output_csv=False,
    )
    
    assert result.name == "r2inspect_batch_results"


def test_display_batch_results_with_rate_stats() -> None:
    """Test display_batch_results with rate stats"""
    rate_limiter = Mock()
    rate_limiter.get_stats.return_value = {
        "success_rate": 0.95,
        "avg_wait_time": 0.05,
        "current_rate": 10.0,
    }
    
    batch_processing.display_batch_results(
        all_results={"file1.exe": {}, "file2.exe": {}},
        failed_files=[],
        elapsed_time=10.0,
        files_to_process=[Path("/tmp/file1.exe"), Path("/tmp/file2.exe")],
        rate_limiter=rate_limiter,
        verbose=True,
        output_filename="output.json",
    )
    # Should not raise


def test_display_batch_results_with_failures() -> None:
    """Test display_batch_results with failed files"""
    rate_limiter = Mock()
    rate_limiter.get_stats.return_value = {}
    
    batch_processing.display_batch_results(
        all_results={"file1.exe": {}},
        failed_files=[("/tmp/file2.exe", "Error")],
        elapsed_time=5.0,
        files_to_process=[Path("/tmp/file1.exe"), Path("/tmp/file2.exe")],
        rate_limiter=rate_limiter,
        verbose=False,
        output_filename=None,
    )
    # Should not raise


def test_find_files_to_process_auto_detect() -> None:
    """Test find_files_to_process with auto_detect"""
    import tempfile
    
    with tempfile.TemporaryDirectory() as tmpdir:
        result = batch_processing.find_files_to_process(
            batch_path=Path(tmpdir),
            auto_detect=True,
            extensions=None,
            recursive=True,
            verbose=False,
            quiet=True,
        )
        
        assert isinstance(result, list)


def test_find_files_to_process_extensions() -> None:
    """Test find_files_to_process with extensions"""
    import tempfile
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a test file
        test_file = Path(tmpdir) / "test.exe"
        test_file.write_bytes(b"\x00" * 100)
        
        result = batch_processing.find_files_to_process(
            batch_path=Path(tmpdir),
            auto_detect=False,
            extensions=".exe",
            recursive=False,
            verbose=False,
            quiet=True,
        )
        
        assert isinstance(result, list)


def test_find_files_to_process_no_extensions() -> None:
    """Test find_files_to_process with auto_detect=False and no extensions"""
    import tempfile
    
    with tempfile.TemporaryDirectory() as tmpdir:
        result = batch_processing.find_files_to_process(
            batch_path=Path(tmpdir),
            auto_detect=False,
            extensions=None,
            recursive=False,
            verbose=False,
            quiet=True,
        )
        
        assert result == []
