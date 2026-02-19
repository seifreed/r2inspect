"""
Tests for r2inspect/cli/batch_processing.py - coverage without mocks.

Covers setup helpers, rate limiter, file discovery, shutdown utilities,
output directory setup, coverage flushing, and batch analysis execution.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from io import StringIO
from pathlib import Path

import pytest

import r2inspect.cli.batch_processing as batch_processing
from r2inspect.cli.batch_processing import (
    _flush_coverage_data,
    _pytest_running,
    _safe_exit,
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


# ---------------------------------------------------------------------------
# setup_rate_limiter
# ---------------------------------------------------------------------------


def test_setup_rate_limiter_returns_limiter():
    limiter = setup_rate_limiter(threads=2, verbose=False)
    assert limiter is not None


def test_setup_rate_limiter_verbose_prints_message(capsys):
    limiter = setup_rate_limiter(threads=4, verbose=True)
    assert limiter is not None
    out = capsys.readouterr().out
    assert "rate limiting" in out.lower() or "files/sec" in out.lower()


def test_setup_rate_limiter_high_thread_count_caps_rate():
    # Very high thread count to exercise the min() cap in base_rate
    limiter = setup_rate_limiter(threads=30, verbose=False)
    assert limiter is not None


# ---------------------------------------------------------------------------
# find_executable_files_by_magic
# ---------------------------------------------------------------------------


def test_find_executable_files_by_magic_empty_directory(tmp_path):
    result = find_executable_files_by_magic(tmp_path, recursive=False, verbose=False)
    assert isinstance(result, list)


def test_find_executable_files_by_magic_verbose_output(tmp_path, capsys):
    # Create a file with ELF magic bytes so it gets reported as found
    elf = tmp_path / "test_elf"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 60)
    result = find_executable_files_by_magic(tmp_path, recursive=False, verbose=True)
    assert isinstance(result, list)


def test_find_executable_files_by_magic_with_magic_none_returns_empty(tmp_path):
    # Temporarily disable magic detection to trigger init_errors path
    original_magic = batch_processing.magic
    batch_processing.magic = None
    try:
        result = find_executable_files_by_magic(tmp_path, recursive=False, verbose=False)
        assert result == []
    finally:
        batch_processing.magic = original_magic


def test_find_executable_files_by_magic_init_error_message_non_fatal(tmp_path, capsys):
    # Passing magic=None produces an "not available" init_error message (else branch)
    original_magic = batch_processing.magic
    batch_processing.magic = None
    try:
        result = find_executable_files_by_magic(tmp_path, recursive=False, verbose=False)
        assert result == []
    finally:
        batch_processing.magic = original_magic


# ---------------------------------------------------------------------------
# find_files_to_process - quiet=False paths (lines 394, 398)
# ---------------------------------------------------------------------------


def test_find_files_to_process_auto_detect_not_quiet(tmp_path, capsys):
    result = find_files_to_process(
        batch_path=tmp_path,
        auto_detect=True,
        extensions=None,
        recursive=False,
        verbose=False,
        quiet=False,
    )
    assert isinstance(result, list)
    out = capsys.readouterr().out
    assert "auto-detecting" in out.lower() or "executable" in out.lower()


def test_find_files_to_process_extensions_not_quiet(tmp_path, capsys):
    (tmp_path / "a.exe").write_bytes(b"x" * 100)
    result = find_files_to_process(
        batch_path=tmp_path,
        auto_detect=False,
        extensions="exe",
        recursive=False,
        verbose=False,
        quiet=False,
    )
    assert isinstance(result, list)
    out = capsys.readouterr().out
    assert "extension" in out.lower() or "searching" in out.lower()


def test_find_files_to_process_no_extensions_returns_empty(tmp_path):
    result = find_files_to_process(
        batch_path=tmp_path,
        auto_detect=False,
        extensions=None,
        recursive=False,
        verbose=False,
        quiet=True,
    )
    assert result == []


def test_find_files_to_process_auto_detect_quiet(tmp_path):
    result = find_files_to_process(
        batch_path=tmp_path,
        auto_detect=True,
        extensions=None,
        recursive=False,
        verbose=False,
        quiet=True,
    )
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# setup_batch_mode
# ---------------------------------------------------------------------------


def test_setup_batch_mode_no_extensions_no_output():
    recursive, auto_detect, output = setup_batch_mode(
        batch="/tmp", extensions=None, output_json=False, output_csv=False, output=None
    )
    assert recursive is True
    assert auto_detect is True
    assert output is None


def test_setup_batch_mode_with_output_json():
    recursive, auto_detect, output = setup_batch_mode(
        batch="/tmp", extensions=None, output_json=True, output_csv=False, output=None
    )
    assert output == "output"


def test_setup_batch_mode_with_extensions_specified():
    recursive, auto_detect, output = setup_batch_mode(
        batch="/tmp", extensions=".exe,.dll", output_json=False, output_csv=False, output=None
    )
    assert auto_detect is False
    assert output is None


# ---------------------------------------------------------------------------
# setup_single_file_output
# ---------------------------------------------------------------------------


def test_setup_single_file_output_json(tmp_path):
    out = setup_single_file_output(True, False, None, str(tmp_path / "binary.exe"))
    assert str(out).endswith("binary_analysis.json")


def test_setup_single_file_output_csv(tmp_path):
    out = setup_single_file_output(False, True, None, str(tmp_path / "binary.exe"))
    assert str(out).endswith("binary_analysis.csv")


def test_setup_single_file_output_with_output_already_set(tmp_path):
    out = setup_single_file_output(True, False, "/custom/out.json", str(tmp_path / "binary.exe"))
    assert out == "/custom/out.json"


def test_setup_single_file_output_no_formats(tmp_path):
    out = setup_single_file_output(False, False, None, str(tmp_path / "binary.exe"))
    assert out is None


# ---------------------------------------------------------------------------
# setup_analysis_options
# ---------------------------------------------------------------------------


def test_setup_analysis_options_with_yara_and_xor():
    opts = setup_analysis_options(yara="rules/", sanitized_xor="key")
    assert opts.get("custom_yara") == "rules/"
    assert opts.get("xor_search") == "key"


def test_setup_analysis_options_all_none():
    opts = setup_analysis_options(yara=None, sanitized_xor=None)
    assert isinstance(opts, dict)


# ---------------------------------------------------------------------------
# display_rate_limiter_stats
# ---------------------------------------------------------------------------


def test_display_rate_limiter_stats_outputs_stats(capsys):
    stats = {"success_rate": 0.99, "avg_wait_time": 0.01, "current_rate": 12.5}
    display_rate_limiter_stats(stats)
    out = capsys.readouterr().out
    assert "rate" in out.lower() or "success" in out.lower()


def test_display_rate_limiter_stats_empty_dict(capsys):
    display_rate_limiter_stats({})
    # Should not raise even with missing keys


# ---------------------------------------------------------------------------
# display_memory_stats
# ---------------------------------------------------------------------------


def test_display_memory_stats_does_not_raise(capsys):
    display_memory_stats()


# ---------------------------------------------------------------------------
# display_failed_files
# ---------------------------------------------------------------------------


def test_display_failed_files_verbose_shows_errors(capsys):
    failed = [(f"/tmp/f{i}.exe", f"error {i}") for i in range(3)]
    display_failed_files(failed, verbose=True)
    out = capsys.readouterr().out
    assert "failed" in out.lower()


def test_display_failed_files_not_verbose_shows_hint(capsys):
    display_failed_files([("/tmp/f.exe", "err")], verbose=False)
    out = capsys.readouterr().out
    assert "verbose" in out.lower() or "failed" in out.lower()


def test_display_failed_files_more_than_ten_truncated(capsys):
    failed = [(f"/tmp/f{i}.exe", f"error {i}") for i in range(15)]
    display_failed_files(failed, verbose=True)
    out = capsys.readouterr().out
    assert "more" in out.lower() or "5" in out


def test_display_failed_files_long_error_truncated(capsys):
    long_error = "x" * 200
    display_failed_files([("/tmp/f.exe", long_error)], verbose=True)
    out = capsys.readouterr().out
    assert "..." in out or "failed" in out.lower()


# ---------------------------------------------------------------------------
# display_no_files_message
# ---------------------------------------------------------------------------


def test_display_no_files_message_auto_detect(capsys):
    display_no_files_message(auto_detect=True, extensions=None)
    out = capsys.readouterr().out
    assert "executable" in out.lower() or "auto" in out.lower()


def test_display_no_files_message_extensions(capsys):
    display_no_files_message(auto_detect=False, extensions=".exe")
    out = capsys.readouterr().out
    assert ".exe" in out or "extensions" in out.lower()


# ---------------------------------------------------------------------------
# handle_main_error
# ---------------------------------------------------------------------------


def test_handle_main_error_not_verbose_exits(capsys):
    with pytest.raises(SystemExit) as exc_info:
        handle_main_error(RuntimeError("something went wrong"), verbose=False)
    assert exc_info.value.code == 1


def test_handle_main_error_verbose_exits_with_traceback(capsys):
    with pytest.raises(SystemExit) as exc_info:
        handle_main_error(ValueError("bad value"), verbose=True)
    assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# setup_batch_output_directory
# ---------------------------------------------------------------------------


def test_setup_batch_output_directory_creates_named_directory(tmp_path):
    new_dir = tmp_path / "results"
    result = setup_batch_output_directory(str(new_dir), output_json=False, output_csv=False)
    assert result.exists()


def test_setup_batch_output_directory_csv_filename_creates_parent(tmp_path):
    csv_path = tmp_path / "subdir" / "out.csv"
    result = setup_batch_output_directory(str(csv_path), output_json=False, output_csv=True)
    assert csv_path.parent.exists()


def test_setup_batch_output_directory_json_filename_creates_parent(tmp_path):
    json_path = tmp_path / "deep" / "out.json"
    result = setup_batch_output_directory(str(json_path), output_json=True, output_csv=False)
    assert json_path.parent.exists()


def test_setup_batch_output_directory_existing_directory(tmp_path):
    result = setup_batch_output_directory(str(tmp_path), output_json=False, output_csv=False)
    assert result == tmp_path


def test_setup_batch_output_directory_none_with_json(tmp_path):
    result = setup_batch_output_directory(None, output_json=True, output_csv=False)
    assert result.name == "output"


def test_setup_batch_output_directory_none_with_csv(tmp_path):
    result = setup_batch_output_directory(None, output_json=False, output_csv=True)
    assert result.name == "output"


def test_setup_batch_output_directory_none_no_formats(tmp_path):
    result = setup_batch_output_directory(None, output_json=False, output_csv=False)
    assert result.name == "r2inspect_batch_results"


# ---------------------------------------------------------------------------
# _safe_exit
# ---------------------------------------------------------------------------


def test_safe_exit_raises_system_exit_in_test_mode():
    os.environ["R2INSPECT_TEST_SAFE_EXIT"] = "1"
    try:
        with pytest.raises(SystemExit) as exc_info:
            _safe_exit(42)
        assert exc_info.value.code == 42
    finally:
        del os.environ["R2INSPECT_TEST_SAFE_EXIT"]


# ---------------------------------------------------------------------------
# ensure_batch_shutdown
# ---------------------------------------------------------------------------


def test_ensure_batch_shutdown_no_lingering_threads():
    # With only daemon or current threads, should complete immediately
    ensure_batch_shutdown(timeout=0.05)


def test_ensure_batch_shutdown_waits_for_joinable_thread():
    completed = threading.Event()

    def short_task():
        time.sleep(0.01)
        completed.set()

    t = threading.Thread(target=short_task, daemon=False)
    t.start()
    ensure_batch_shutdown(timeout=1.0)
    assert completed.is_set()


def test_ensure_batch_shutdown_forces_exit_on_timeout():
    barrier = threading.Event()

    def stuck_task():
        barrier.wait(timeout=5.0)

    t = threading.Thread(target=stuck_task, daemon=False, name="stuck-thread")
    t.start()

    os.environ["R2INSPECT_TEST_SAFE_EXIT"] = "1"
    os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"] = "1"
    try:
        with pytest.raises(SystemExit):
            ensure_batch_shutdown(timeout=0.05)
    finally:
        barrier.set()
        t.join(timeout=1.0)
        os.environ.pop("R2INSPECT_TEST_SAFE_EXIT", None)
        os.environ.pop("R2INSPECT_TEST_COVERAGE_DUMMY", None)


# ---------------------------------------------------------------------------
# schedule_forced_exit
# ---------------------------------------------------------------------------


def test_schedule_forced_exit_disabled_by_env():
    os.environ["R2INSPECT_DISABLE_FORCED_EXIT"] = "1"
    try:
        schedule_forced_exit(delay=0.01)  # Should return without scheduling
    finally:
        del os.environ["R2INSPECT_DISABLE_FORCED_EXIT"]


def test_schedule_forced_exit_schedules_daemon_timer():
    # Let the timer fire in test-safe mode
    os.environ["R2INSPECT_TEST_SAFE_EXIT"] = "1"
    os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"] = "1"
    try:
        schedule_forced_exit(delay=0.05)
        time.sleep(0.15)  # Allow timer to fire; SystemExit in daemon thread won't kill us
    finally:
        os.environ.pop("R2INSPECT_TEST_SAFE_EXIT", None)
        os.environ.pop("R2INSPECT_TEST_COVERAGE_DUMMY", None)


# ---------------------------------------------------------------------------
# _flush_coverage_data
# ---------------------------------------------------------------------------


def test_flush_coverage_data_import_error_returns_silently():
    os.environ["R2INSPECT_TEST_COVERAGE_IMPORT_ERROR"] = "1"
    try:
        _flush_coverage_data()
    finally:
        del os.environ["R2INSPECT_TEST_COVERAGE_IMPORT_ERROR"]


def test_flush_coverage_data_current_error_returns_silently():
    os.environ["R2INSPECT_TEST_COVERAGE_CURRENT_ERROR"] = "1"
    try:
        _flush_coverage_data()
    finally:
        del os.environ["R2INSPECT_TEST_COVERAGE_CURRENT_ERROR"]


def test_flush_coverage_data_none_cov_returns_silently():
    os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"] = "1"
    os.environ["R2INSPECT_TEST_COVERAGE_NONE"] = "1"
    try:
        _flush_coverage_data()
    finally:
        del os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"]
        del os.environ["R2INSPECT_TEST_COVERAGE_NONE"]


def test_flush_coverage_data_save_error_returns_silently():
    os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"] = "1"
    os.environ["R2INSPECT_TEST_COVERAGE_SAVE_ERROR"] = "1"
    try:
        _flush_coverage_data()
    finally:
        del os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"]
        del os.environ["R2INSPECT_TEST_COVERAGE_SAVE_ERROR"]


def test_flush_coverage_data_dummy_saves_in_pytest_mode():
    os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"] = "1"
    os.environ["R2INSPECT_TEST_MODE"] = "1"
    try:
        _flush_coverage_data()
    finally:
        del os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"]
        del os.environ["R2INSPECT_TEST_MODE"]


def test_flush_coverage_data_real_coverage_current_then_discard():
    # Calls coverage.Coverage.current() (line 257) then immediately discards
    # the object before save() is reached, preventing db corruption.
    os.environ["R2INSPECT_TEST_COVERAGE_NONE"] = "1"
    try:
        _flush_coverage_data()
    finally:
        del os.environ["R2INSPECT_TEST_COVERAGE_NONE"]


# ---------------------------------------------------------------------------
# _pytest_running
# ---------------------------------------------------------------------------


def test_pytest_running_detects_test_mode_env():
    for val in ("1", "true", "yes"):
        os.environ["R2INSPECT_TEST_MODE"] = val
        try:
            assert _pytest_running() is True
        finally:
            del os.environ["R2INSPECT_TEST_MODE"]


def test_pytest_running_detects_safe_exit_env():
    os.environ["R2INSPECT_TEST_SAFE_EXIT"] = "1"
    try:
        assert _pytest_running() is True
    finally:
        del os.environ["R2INSPECT_TEST_SAFE_EXIT"]


def test_pytest_running_detects_pytest_current_test():
    os.environ["PYTEST_CURRENT_TEST"] = "test_file.py::test_name (call)"
    try:
        assert _pytest_running() is True
    finally:
        del os.environ["PYTEST_CURRENT_TEST"]


def test_pytest_running_detects_coverage_env_prefix():
    os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"] = "1"
    try:
        assert _pytest_running() is True
    finally:
        del os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"]


def test_pytest_running_detects_pytest_in_argv():
    saved = sys.argv[:]
    sys.argv = ["pytest", "tests/unit/"]
    try:
        assert _pytest_running() is True
    finally:
        sys.argv = saved


def test_pytest_running_detects_pytest_in_modules():
    # pytest is always in sys.modules when running under pytest
    assert "pytest" in sys.modules
    assert _pytest_running() is True


def test_pytest_running_falls_through_to_modules_check():
    # Clear all pytest-indicative env vars temporarily to reach the sys.argv
    # and sys.modules checks (lines 284-287)
    keys_to_clear = [
        "R2INSPECT_TEST_MODE",
        "R2INSPECT_TEST_SAFE_EXIT",
        "PYTEST_CURRENT_TEST",
    ]
    # Also clear all R2INSPECT_TEST_COVERAGE_* keys
    coverage_keys = [k for k in os.environ if k.startswith("R2INSPECT_TEST_COVERAGE_")]

    saved_env = {}
    for key in keys_to_clear + coverage_keys:
        if key in os.environ:
            saved_env[key] = os.environ.pop(key)

    saved_argv = sys.argv[:]
    # Replace argv so "pytest" doesn't appear as an argument
    sys.argv = ["/usr/bin/python3", "run_app.py"]

    try:
        # pytest IS in sys.modules, so line 287 returns True
        result = _pytest_running()
        assert result is True
    finally:
        sys.argv = saved_argv
        for key, val in saved_env.items():
            os.environ[key] = val


def test_pytest_running_coverage_env_prefix_reached():
    """Cover line 284: return True for R2INSPECT_TEST_COVERAGE_* env var.

    Must unset PYTEST_CURRENT_TEST first so execution reaches line 283-284.
    """
    keys_to_clear = [
        "R2INSPECT_TEST_MODE",
        "R2INSPECT_TEST_SAFE_EXIT",
        "PYTEST_CURRENT_TEST",
    ]
    saved_env = {}
    for key in keys_to_clear:
        if key in os.environ:
            saved_env[key] = os.environ.pop(key)

    os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"] = "1"
    try:
        result = _pytest_running()
        assert result is True
    finally:
        del os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"]
        for key, val in saved_env.items():
            os.environ[key] = val


def test_pytest_running_pytest_in_argv_reached():
    """Cover line 286: return True when pytest is in sys.argv.

    Must unset PYTEST_CURRENT_TEST and R2INSPECT_TEST_COVERAGE_* first.
    """
    keys_to_clear = [
        "R2INSPECT_TEST_MODE",
        "R2INSPECT_TEST_SAFE_EXIT",
        "PYTEST_CURRENT_TEST",
    ]
    coverage_keys = [k for k in os.environ if k.startswith("R2INSPECT_TEST_COVERAGE_")]

    saved_env = {}
    for key in keys_to_clear + coverage_keys:
        if key in os.environ:
            saved_env[key] = os.environ.pop(key)

    saved_argv = sys.argv[:]
    sys.argv = ["pytest", "tests/unit/"]

    try:
        result = _pytest_running()
        assert result is True
    finally:
        sys.argv = saved_argv
        for key, val in saved_env.items():
            os.environ[key] = val


# ---------------------------------------------------------------------------
# display_batch_results
# ---------------------------------------------------------------------------


class _FakeRateLimiter:
    def get_stats(self):
        return {"success_rate": 0.95, "avg_wait_time": 0.02, "current_rate": 8.0}


def test_display_batch_results_success_only(capsys):
    limiter = _FakeRateLimiter()
    display_batch_results(
        all_results={"f1.exe": {}, "f2.exe": {}},
        failed_files=[],
        elapsed_time=2.0,
        files_to_process=[Path("f1.exe"), Path("f2.exe")],
        rate_limiter=limiter,
        verbose=False,
        output_filename=None,
    )
    out = capsys.readouterr().out
    assert "2/2" in out or "processed" in out.lower()


def test_display_batch_results_with_output_filename(capsys):
    limiter = _FakeRateLimiter()
    display_batch_results(
        all_results={"f1.exe": {}},
        failed_files=[],
        elapsed_time=1.0,
        files_to_process=[Path("f1.exe")],
        rate_limiter=limiter,
        verbose=False,
        output_filename="results.csv",
    )
    out = capsys.readouterr().out
    assert "results.csv" in out


def test_display_batch_results_verbose_shows_rate_stats(capsys):
    limiter = _FakeRateLimiter()
    display_batch_results(
        all_results={"f1.exe": {}},
        failed_files=[],
        elapsed_time=1.0,
        files_to_process=[Path("f1.exe")],
        rate_limiter=limiter,
        verbose=True,
        output_filename=None,
    )
    out = capsys.readouterr().out
    assert "rate" in out.lower() or "success" in out.lower()


def test_display_batch_results_with_failed_files(capsys):
    class _EmptyStats:
        def get_stats(self):
            return {}

    display_batch_results(
        all_results={"f1.exe": {}},
        failed_files=[("/tmp/f2.exe", "some error")],
        elapsed_time=1.0,
        files_to_process=[Path("f1.exe"), Path("f2.exe")],
        rate_limiter=_EmptyStats(),
        verbose=False,
        output_filename=None,
    )
    out = capsys.readouterr().out
    assert "failed" in out.lower()


# ---------------------------------------------------------------------------
# run_batch_analysis
# ---------------------------------------------------------------------------


def test_run_batch_analysis_with_extensions_and_no_files(tmp_path):
    from r2inspect.config import Config

    options = {"detect_packer": False, "detect_crypto": False, "analyze_functions": False}
    config_obj = Config()

    # Extensions mode with no matching files - should exit cleanly
    run_batch_analysis(
        batch_dir=str(tmp_path),
        options=options,
        output_json=False,
        output_csv=False,
        output_dir=None,
        recursive=False,
        extensions="exe",
        verbose=False,
        config_obj=config_obj,
        auto_detect=False,
        threads=1,
        quiet=True,
    )


def test_run_batch_analysis_auto_detect_empty_directory(tmp_path):
    from r2inspect.config import Config

    options = {"detect_packer": False, "detect_crypto": False, "analyze_functions": False}
    config_obj = Config()

    run_batch_analysis(
        batch_dir=str(tmp_path),
        options=options,
        output_json=False,
        output_csv=False,
        output_dir=None,
        recursive=False,
        extensions=None,
        verbose=False,
        config_obj=config_obj,
        auto_detect=True,
        threads=1,
        quiet=True,
    )


def test_run_batch_analysis_quiet_false_no_files(tmp_path, capsys):
    from r2inspect.config import Config

    options = {}
    config_obj = Config()

    run_batch_analysis(
        batch_dir=str(tmp_path),
        options=options,
        output_json=False,
        output_csv=False,
        output_dir=None,
        recursive=False,
        extensions="exe",
        verbose=False,
        config_obj=config_obj,
        auto_detect=False,
        threads=1,
        quiet=False,
    )
    out = capsys.readouterr().out
    assert "searching" in out.lower() or "extension" in out.lower() or "no files" in out.lower()


def test_run_batch_analysis_with_files_triggers_display_and_logging(tmp_path):
    """Trigger _display_found_files, _configure_batch_logging, _configure_quiet_logging."""
    from r2inspect.config import Config

    # Copy the hello_pe.exe sample into tmp_path so the batch finds it
    sample_src = Path("samples/fixtures/hello_pe.exe")
    if not sample_src.exists():
        pytest.skip("sample binary missing")

    import shutil

    sample_dst = tmp_path / "hello_pe.exe"
    shutil.copy(str(sample_src), str(sample_dst))

    config_obj = Config()
    options = {"detect_packer": False, "detect_crypto": False, "analyze_functions": False}

    # quiet=False, verbose=False → triggers _display_found_files + _configure_batch_logging
    run_batch_analysis(
        batch_dir=str(tmp_path),
        options=options,
        output_json=False,
        output_csv=False,
        output_dir=None,
        recursive=False,
        extensions="exe",
        verbose=False,
        config_obj=config_obj,
        auto_detect=False,
        threads=1,
        quiet=False,
    )


def test_run_batch_analysis_quiet_mode_with_files(tmp_path):
    """Trigger _configure_quiet_logging with quiet=True and actual files present."""
    from r2inspect.config import Config

    sample_src = Path("samples/fixtures/hello_pe.exe")
    if not sample_src.exists():
        pytest.skip("sample binary missing")

    import shutil

    sample_dst = tmp_path / "hello_pe.exe"
    shutil.copy(str(sample_src), str(sample_dst))

    config_obj = Config()
    options = {"detect_packer": False, "detect_crypto": False, "analyze_functions": False}

    # quiet=True → triggers _configure_quiet_logging (and _display_found_files returns early)
    run_batch_analysis(
        batch_dir=str(tmp_path),
        options=options,
        output_json=False,
        output_csv=False,
        output_dir=None,
        recursive=False,
        extensions="exe",
        verbose=False,
        config_obj=config_obj,
        auto_detect=False,
        threads=1,
        quiet=True,
    )


# ---------------------------------------------------------------------------
# find_executable_files_by_magic - "Error initializing magic:" path (lines 132-133)
# ---------------------------------------------------------------------------


class _BrokenMagicModule:
    """Fake magic module whose Magic() constructor always raises."""

    class Magic:
        def __init__(self, **kwargs):
            raise RuntimeError("simulated magic init failure")


def test_find_executable_files_by_magic_init_error_branch(tmp_path, capsys):
    # Use a broken magic module to trigger "Error initializing magic:" init_error
    original_magic = batch_processing.magic
    batch_processing.magic = _BrokenMagicModule()
    try:
        result = find_executable_files_by_magic(tmp_path, recursive=False, verbose=False)
        assert result == []
    finally:
        batch_processing.magic = original_magic
    out = capsys.readouterr().out
    assert "falling back" in out.lower() or "error" in out.lower()


# ---------------------------------------------------------------------------
# find_executable_files_by_magic - verbose file_errors path (lines 142-143)
# ---------------------------------------------------------------------------


class _FileFaultMagic:
    """Fake magic module whose from_file() raises for all files."""

    class Magic:
        def __init__(self, **kwargs):
            pass

        def from_file(self, path: str) -> str:
            raise RuntimeError("simulated from_file error")


def test_find_executable_files_by_magic_file_errors_verbose(tmp_path, capsys):
    # Create a file large enough to not be skipped (>= 64 bytes)
    f = tmp_path / "test.bin"
    f.write_bytes(b"\x00" * 100)

    original_magic = batch_processing.magic
    batch_processing.magic = _FileFaultMagic()
    try:
        result = find_executable_files_by_magic(tmp_path, recursive=False, verbose=True)
    finally:
        batch_processing.magic = original_magic
    out = capsys.readouterr().out
    assert "error checking" in out.lower() or "error" in out.lower()


# ---------------------------------------------------------------------------
# ensure_batch_shutdown - remaining_time <= 0 path (line 207)
# ---------------------------------------------------------------------------


def test_ensure_batch_shutdown_deadline_already_exceeded():
    """Cover the 'remaining_time <= 0: break' branch with timeout=0."""
    barrier = threading.Event()

    def stuck_task():
        barrier.wait(timeout=5.0)

    t = threading.Thread(target=stuck_task, daemon=False, name="deadline-thread")
    t.start()

    os.environ["R2INSPECT_TEST_SAFE_EXIT"] = "1"
    os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"] = "1"
    try:
        # timeout=0.0 → deadline is now, remaining_time will be 0.0 → hits line 207
        with pytest.raises(SystemExit):
            ensure_batch_shutdown(timeout=0.0)
    finally:
        barrier.set()
        t.join(timeout=1.0)
        os.environ.pop("R2INSPECT_TEST_SAFE_EXIT", None)
        os.environ.pop("R2INSPECT_TEST_COVERAGE_DUMMY", None)
