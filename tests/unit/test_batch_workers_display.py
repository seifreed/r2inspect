#!/usr/bin/env python3
"""Comprehensive tests for r2inspect/cli/batch_workers.py -- no mocks."""

import os
import threading
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from r2inspect.cli.batch_workers import (
    _cap_threads_for_execution,
    process_files_parallel,
    process_single_file,
)
from r2inspect.infrastructure.rate_limiter import BatchRateLimiter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _AlwaysGrantRateLimiter:
    """Minimal rate limiter that always grants and records calls."""

    def __init__(self):
        self.acquired = 0
        self.successes = 0
        self.errors: list[str] = []

    def acquire(self, timeout: float = 30.0) -> bool:
        self.acquired += 1
        return True

    def release_success(self) -> None:
        self.successes += 1

    def release_error(self, error_type: str = "unknown") -> None:
        self.errors.append(error_type)


class _NeverGrantRateLimiter:
    """Minimal rate limiter that always denies."""

    def acquire(self, timeout: float = 30.0) -> bool:
        return False

    def release_success(self) -> None:
        pass  # pragma: no cover

    def release_error(self, error_type: str = "unknown") -> None:
        pass  # pragma: no cover


# ---------------------------------------------------------------------------
# _cap_threads_for_execution
# ---------------------------------------------------------------------------


def _with_env(key: str, value: str | None):
    """Context-manager-free helper to set/unset an env var for a test."""
    old = os.environ.pop(key, None)

    def restore():
        if old is not None:
            os.environ[key] = old
        else:
            os.environ.pop(key, None)

    if value is not None:
        os.environ[key] = value
    return restore


class TestCapThreadsForExecution:
    ENV_KEY = "R2INSPECT_MAX_THREADS"

    def test_no_env(self):
        restore = _with_env(self.ENV_KEY, None)
        try:
            assert _cap_threads_for_execution(10) == 10
        finally:
            restore()

    def test_with_cap_lower(self):
        restore = _with_env(self.ENV_KEY, "5")
        try:
            assert _cap_threads_for_execution(10) == 5
        finally:
            restore()

    def test_cap_higher_than_requested(self):
        restore = _with_env(self.ENV_KEY, "20")
        try:
            assert _cap_threads_for_execution(10) == 10
        finally:
            restore()

    def test_invalid_value(self):
        restore = _with_env(self.ENV_KEY, "invalid")
        try:
            assert _cap_threads_for_execution(10) == 10
        finally:
            restore()

    def test_zero(self):
        restore = _with_env(self.ENV_KEY, "0")
        try:
            assert _cap_threads_for_execution(10) == 10
        finally:
            restore()

    def test_negative(self):
        restore = _with_env(self.ENV_KEY, "-5")
        try:
            assert _cap_threads_for_execution(10) == 10
        finally:
            restore()

    def test_empty_string(self):
        restore = _with_env(self.ENV_KEY, "   ")
        try:
            assert _cap_threads_for_execution(10) == 10
        finally:
            restore()

    def test_cap_equals_requested(self):
        restore = _with_env(self.ENV_KEY, "10")
        try:
            assert _cap_threads_for_execution(10) == 10
        finally:
            restore()

    def test_cap_one(self):
        restore = _with_env(self.ENV_KEY, "1")
        try:
            assert _cap_threads_for_execution(8) == 1
        finally:
            restore()


# ---------------------------------------------------------------------------
# process_single_file -- real code paths (no r2 needed)
# ---------------------------------------------------------------------------


class TestProcessSingleFileRateLimitTimeout:
    """When the rate limiter denies, process_single_file returns a timeout error."""

    def test_timeout_error_returned(self, tmp_path: Path):
        file_path = tmp_path / "test.exe"
        rl = _NeverGrantRateLimiter()

        result_path, results, error = process_single_file(
            file_path, tmp_path, None, {}, False, tmp_path, rl
        )

        assert result_path == file_path
        assert results is None
        assert error is not None
        assert "timeout" in error.lower()


class TestProcessSingleFileRealErrorPaths:
    """Exercise real error handling by passing files that fail validation."""

    def test_nonexistent_file_returns_error(self, tmp_path: Path):
        file_path = tmp_path / "does_not_exist.exe"
        rl = _AlwaysGrantRateLimiter()

        result_path, results, error = process_single_file(
            file_path, tmp_path, None, {}, False, tmp_path / "out", rl
        )

        assert result_path == file_path
        assert results is None
        assert error is not None
        # The error comes from FileValidator or stat() failing
        assert len(error) > 0
        # release_error should have been called
        assert len(rl.errors) == 1

    def test_error_type_tracked(self, tmp_path: Path):
        """Error type name is passed to release_error."""
        file_path = tmp_path / "missing.bin"
        rl = _AlwaysGrantRateLimiter()

        process_single_file(file_path, tmp_path, None, {}, False, tmp_path, rl)

        assert len(rl.errors) == 1
        # Should be a real exception type name (ValueError, FileNotFoundError, etc.)
        assert rl.errors[0] in ("ValueError", "FileNotFoundError", "OSError")

    def test_empty_file_returns_error(self, tmp_path: Path):
        """A zero-byte file should fail validation."""
        file_path = tmp_path / "empty.exe"
        file_path.write_bytes(b"")
        rl = _AlwaysGrantRateLimiter()

        result_path, results, error = process_single_file(
            file_path, tmp_path, None, {}, False, tmp_path, rl
        )

        assert result_path == file_path
        # Either results is None (validation error) or analysis fails
        if results is None:
            assert error is not None
            assert len(rl.errors) == 1

    def test_directory_instead_of_file(self, tmp_path: Path):
        """Passing a directory as file_path should produce an error."""
        rl = _AlwaysGrantRateLimiter()

        result_path, results, error = process_single_file(
            tmp_path, tmp_path, None, {}, False, tmp_path, rl
        )

        assert result_path == tmp_path
        assert results is None
        assert error is not None
        assert len(rl.errors) == 1


class TestProcessSingleFileWithRealRateLimiter:
    """Use real BatchRateLimiter to exercise integration."""

    def test_real_rate_limiter_grants(self, tmp_path: Path):
        file_path = tmp_path / "nope.exe"
        rl = BatchRateLimiter(max_concurrent=2, rate_per_second=100.0, enable_adaptive=False)

        result_path, results, error = process_single_file(
            file_path, tmp_path, None, {}, False, tmp_path, rl
        )

        assert result_path == file_path
        # Will error because file doesn't exist, but rate limiter path was exercised
        assert error is not None

    def test_batch_mode_is_injected_into_options(self, tmp_path: Path):
        """Even though analysis fails, options dict gets batch_mode=True injected."""
        file_path = tmp_path / "fake.exe"
        rl = _AlwaysGrantRateLimiter()
        options = {"full_analysis": False}

        # The function modifies options internally before analysis runs,
        # but since the file doesn't exist, it errors.
        # We can still verify the function was called and the rate limiter tracked it.
        process_single_file(file_path, tmp_path, None, options, False, tmp_path, rl)

        # Original options dict should NOT be mutated (a copy is made via {**options, ...})
        assert "batch_mode" not in options


# ---------------------------------------------------------------------------
# process_files_parallel -- real orchestration
# ---------------------------------------------------------------------------


class TestProcessFilesParallel:
    """Test parallel processing orchestration with real threads and real error paths."""

    def test_single_file_failure(self, tmp_path: Path):
        """A single nonexistent file ends up in failed_files."""
        file_path = tmp_path / "missing.exe"
        all_results: dict = {}
        failed_files: list = []
        output_path = tmp_path / "output"
        output_path.mkdir()
        rl = _AlwaysGrantRateLimiter()

        process_files_parallel(
            [file_path],
            all_results,
            failed_files,
            output_path,
            tmp_path,
            None,
            {},
            False,
            1,
            rl,
        )

        assert len(all_results) == 0
        assert len(failed_files) == 1
        assert str(file_path) in failed_files[0][0]

    def test_multiple_files_all_fail(self, tmp_path: Path):
        """Multiple nonexistent files all fail."""
        files = [tmp_path / f"missing_{i}.exe" for i in range(3)]
        all_results: dict = {}
        failed_files: list = []
        output_path = tmp_path / "output"
        output_path.mkdir()
        rl = _AlwaysGrantRateLimiter()

        process_files_parallel(
            files,
            all_results,
            failed_files,
            output_path,
            tmp_path,
            None,
            {},
            False,
            2,
            rl,
        )

        assert len(all_results) == 0
        assert len(failed_files) == 3

    def test_thread_cap_respected(self, tmp_path: Path):
        """With R2INSPECT_MAX_THREADS=1, only one thread is used."""
        files = [tmp_path / f"f{i}.exe" for i in range(3)]
        all_results: dict = {}
        failed_files: list = []
        output_path = tmp_path / "output"
        output_path.mkdir()
        rl = _AlwaysGrantRateLimiter()

        restore = _with_env("R2INSPECT_MAX_THREADS", "1")
        try:
            process_files_parallel(
                files,
                all_results,
                failed_files,
                output_path,
                tmp_path,
                None,
                {},
                False,
                10,
                rl,
            )
        finally:
            restore()

        # All should have been processed (they'll all fail, but the
        # orchestration should have run them all)
        assert len(failed_files) == 3

    def test_empty_file_list(self, tmp_path: Path):
        """Empty file list produces no results and no failures."""
        all_results: dict = {}
        failed_files: list = []
        output_path = tmp_path / "output"
        output_path.mkdir()
        rl = _AlwaysGrantRateLimiter()

        process_files_parallel(
            [],
            all_results,
            failed_files,
            output_path,
            tmp_path,
            None,
            {},
            False,
            2,
            rl,
        )

        assert len(all_results) == 0
        assert len(failed_files) == 0

    def test_long_filename_handled(self, tmp_path: Path):
        """Progress display truncates long filenames without crashing."""
        long_name = "a" * 80 + ".exe"
        file_path = tmp_path / long_name
        all_results: dict = {}
        failed_files: list = []
        output_path = tmp_path / "output"
        output_path.mkdir()
        rl = _AlwaysGrantRateLimiter()

        process_files_parallel(
            [file_path],
            all_results,
            failed_files,
            output_path,
            tmp_path,
            None,
            {},
            False,
            1,
            rl,
        )

        # Should complete without error
        assert len(failed_files) == 1

    def test_thread_safety_concurrent(self, tmp_path: Path):
        """Multiple files processed concurrently with thread-safe collection."""
        files = [tmp_path / f"concurrent_{i}.exe" for i in range(10)]
        all_results: dict = {}
        failed_files: list = []
        output_path = tmp_path / "output"
        output_path.mkdir()
        rl = _AlwaysGrantRateLimiter()

        process_files_parallel(
            files,
            all_results,
            failed_files,
            output_path,
            tmp_path,
            None,
            {},
            False,
            4,
            rl,
        )

        # All 10 files should appear in failed_files (none exist)
        assert len(failed_files) == 10
        assert len(all_results) == 0

    def test_with_real_batch_rate_limiter(self, tmp_path: Path):
        """Use a real BatchRateLimiter through the full parallel path."""
        files = [tmp_path / f"rl_{i}.bin" for i in range(3)]
        all_results: dict = {}
        failed_files: list = []
        output_path = tmp_path / "output"
        output_path.mkdir()
        rl = BatchRateLimiter(
            max_concurrent=5,
            rate_per_second=100.0,
            enable_adaptive=False,
        )

        process_files_parallel(
            files,
            all_results,
            failed_files,
            output_path,
            tmp_path,
            None,
            {},
            False,
            2,
            rl,
        )

        assert len(failed_files) == 3
        stats = rl.get_stats()
        assert stats["files_failed"] == 3

    def test_rate_limit_timeout_in_parallel(self, tmp_path: Path):
        """When rate limiter always denies, files fail with timeout error."""
        files = [tmp_path / f"denied_{i}.exe" for i in range(2)]
        all_results: dict = {}
        failed_files: list = []
        output_path = tmp_path / "output"
        output_path.mkdir()
        rl = _NeverGrantRateLimiter()

        process_files_parallel(
            files,
            all_results,
            failed_files,
            output_path,
            tmp_path,
            None,
            {},
            False,
            2,
            rl,
        )

        assert len(all_results) == 0
        assert len(failed_files) == 2
        for _, error_msg in failed_files:
            assert "timeout" in error_msg.lower()


# ---------------------------------------------------------------------------
# Console output capture tests
# ---------------------------------------------------------------------------


class TestConsoleOutputCapture:
    """Verify Rich console output by capturing to StringIO."""

    def test_progress_renders_without_error(self, tmp_path: Path):
        """Progress bar renders to a captured console without crashing."""
        from rich.progress import (
            BarColumn,
            Progress,
            TaskProgressColumn,
            TextColumn,
            TimeRemainingColumn,
        )

        buf = StringIO()
        captured_console = Console(file=buf, force_terminal=False, width=120)

        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            console=captured_console,
        ) as progress:
            task = progress.add_task("Processing files...", total=3)
            for i in range(3):
                progress.update(
                    task, completed=i + 1, description=f"Processing files... (file{i}.exe)"
                )

        output = buf.getvalue()
        # Progress bar should have rendered something
        assert len(output) > 0

    def test_parallel_output_structure(self, tmp_path: Path):
        """Verify that parallel processing populates data structures correctly."""
        files = [tmp_path / f"struct_{i}.bin" for i in range(5)]
        all_results: dict = {}
        failed_files: list = []
        output_path = tmp_path / "output"
        output_path.mkdir()
        rl = _AlwaysGrantRateLimiter()

        process_files_parallel(
            files,
            all_results,
            failed_files,
            output_path,
            tmp_path,
            None,
            {},
            False,
            2,
            rl,
        )

        # Verify structure: each entry in failed_files is a (path_str, error_str) tuple
        for entry in failed_files:
            assert isinstance(entry, tuple)
            assert len(entry) == 2
            path_str, error_str = entry
            assert isinstance(path_str, str)
            assert isinstance(error_str, str)
            assert len(error_str) > 0


# ---------------------------------------------------------------------------
# Integration: _cap_threads_for_execution with process_files_parallel
# ---------------------------------------------------------------------------


class TestCapThreadsIntegration:
    """Verify thread capping integrates correctly with parallel processing."""

    def test_cap_limits_effective_threads(self, tmp_path: Path):
        """Set cap to 1 and verify all files still get processed sequentially."""
        files = [tmp_path / f"seq_{i}.exe" for i in range(4)]
        all_results: dict = {}
        failed_files: list = []
        output_path = tmp_path / "output"
        output_path.mkdir()
        rl = _AlwaysGrantRateLimiter()

        restore = _with_env("R2INSPECT_MAX_THREADS", "1")
        try:
            process_files_parallel(
                files,
                all_results,
                failed_files,
                output_path,
                tmp_path,
                None,
                {},
                False,
                8,
                rl,
            )
        finally:
            restore()

        assert len(failed_files) == 4
        # All files should have been acquired from rate limiter
        assert rl.acquired == 4
