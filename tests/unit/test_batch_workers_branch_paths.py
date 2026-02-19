#!/usr/bin/env python3
"""Branch-path tests for r2inspect/cli/batch_workers.py.

Uses real objects (no unittest.mock):
- BatchRateLimiter for the happy path
- Hand-written stub rate-limiter class for the timeout path
- Real sample binaries from samples/fixtures/

Missing lines targeted:
24-35 (_cap_threads_for_execution),
48-75 (process_single_file),
91-140 (process_files_parallel).
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

from r2inspect.cli.batch_workers import (
    _cap_threads_for_execution,
    process_files_parallel,
    process_single_file,
)
from r2inspect.config import Config
from r2inspect.utils.rate_limiter import BatchRateLimiter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sample_pe() -> Path:
    p = Path("samples/fixtures/hello_pe.exe")
    if not p.exists():
        pytest.skip("hello_pe.exe fixture missing")
    return p


# ---------------------------------------------------------------------------
# Stub rate-limiter that immediately denies every acquire (no mocks)
# ---------------------------------------------------------------------------


class _RejectingRateLimiter:
    """Always returns False from acquire – simulates a timeout."""

    def acquire(self, timeout=None) -> bool:
        return False

    def release_success(self) -> None:
        pass

    def release_error(self, error_type: str = "unknown") -> None:
        pass


# ---------------------------------------------------------------------------
# _cap_threads_for_execution – lines 24-35
# ---------------------------------------------------------------------------


def test_cap_threads_no_env_variable_returns_requested():
    saved = os.environ.pop("R2INSPECT_MAX_THREADS", None)
    try:
        assert _cap_threads_for_execution(8) == 8
    finally:
        if saved is not None:
            os.environ["R2INSPECT_MAX_THREADS"] = saved


def test_cap_threads_empty_env_returns_requested():
    os.environ["R2INSPECT_MAX_THREADS"] = "  "
    try:
        assert _cap_threads_for_execution(8) == 8
    finally:
        del os.environ["R2INSPECT_MAX_THREADS"]


def test_cap_threads_valid_cap_lower_than_requested():
    os.environ["R2INSPECT_MAX_THREADS"] = "3"
    try:
        assert _cap_threads_for_execution(10) == 3
    finally:
        del os.environ["R2INSPECT_MAX_THREADS"]


def test_cap_threads_valid_cap_higher_than_requested():
    os.environ["R2INSPECT_MAX_THREADS"] = "20"
    try:
        assert _cap_threads_for_execution(5) == 5
    finally:
        del os.environ["R2INSPECT_MAX_THREADS"]


def test_cap_threads_non_integer_env_returns_requested():
    os.environ["R2INSPECT_MAX_THREADS"] = "not_a_number"
    try:
        assert _cap_threads_for_execution(6) == 6
    finally:
        del os.environ["R2INSPECT_MAX_THREADS"]


def test_cap_threads_zero_cap_returns_requested():
    os.environ["R2INSPECT_MAX_THREADS"] = "0"
    try:
        assert _cap_threads_for_execution(4) == 4
    finally:
        del os.environ["R2INSPECT_MAX_THREADS"]


def test_cap_threads_negative_cap_returns_requested():
    os.environ["R2INSPECT_MAX_THREADS"] = "-2"
    try:
        assert _cap_threads_for_execution(4) == 4
    finally:
        del os.environ["R2INSPECT_MAX_THREADS"]


def test_cap_threads_cap_equals_requested():
    os.environ["R2INSPECT_MAX_THREADS"] = "4"
    try:
        assert _cap_threads_for_execution(4) == 4
    finally:
        del os.environ["R2INSPECT_MAX_THREADS"]


# ---------------------------------------------------------------------------
# process_single_file – rate-limiter timeout path (lines 48-49)
# ---------------------------------------------------------------------------


def test_process_single_file_rate_limit_timeout_returns_error(tmp_path: Path):
    dummy = tmp_path / "dummy.bin"
    dummy.write_bytes(b"\x00" * 4)
    file_path, results, error = process_single_file(
        dummy, tmp_path, Config(), {}, False, tmp_path, _RejectingRateLimiter()
    )
    assert file_path == dummy
    assert results is None
    assert error is not None
    assert "timeout" in error.lower() or "overloaded" in error.lower()


# ---------------------------------------------------------------------------
# process_single_file – success path with real binary (lines 51-75)
# ---------------------------------------------------------------------------


def test_process_single_file_success_with_real_binary(tmp_path: Path):
    sample = _sample_pe()
    local = tmp_path / sample.name
    local.write_bytes(sample.read_bytes())

    output_path = tmp_path / "out"
    output_path.mkdir()

    rate_limiter = BatchRateLimiter(max_concurrent=1, rate_per_second=100.0, enable_adaptive=False)
    file_path, results, error = process_single_file(
        local, tmp_path, Config(), {"full_analysis": False}, False, output_path, rate_limiter
    )

    assert error is None
    assert results is not None
    assert results.get("filename") == str(local)


def test_process_single_file_json_output_written(tmp_path: Path):
    sample = _sample_pe()
    local = tmp_path / sample.name
    local.write_bytes(sample.read_bytes())

    output_path = tmp_path / "out"
    output_path.mkdir()

    rate_limiter = BatchRateLimiter(max_concurrent=1, rate_per_second=100.0, enable_adaptive=False)
    file_path, results, error = process_single_file(
        local, tmp_path, Config(), {"full_analysis": False}, True, output_path, rate_limiter
    )

    assert error is None
    json_file = output_path / f"{local.stem}_analysis.json"
    assert json_file.exists()


def test_process_single_file_sets_relative_path(tmp_path: Path):
    sub = tmp_path / "sub"
    sub.mkdir()
    sample = _sample_pe()
    local = sub / sample.name
    local.write_bytes(sample.read_bytes())

    output_path = tmp_path / "out"
    output_path.mkdir()

    rate_limiter = BatchRateLimiter(max_concurrent=1, rate_per_second=100.0, enable_adaptive=False)
    _, results, error = process_single_file(
        local, tmp_path, Config(), {"full_analysis": False}, False, output_path, rate_limiter
    )

    assert error is None
    assert results is not None
    assert "relative_path" in results
    assert "sub" in results["relative_path"]


# ---------------------------------------------------------------------------
# process_files_parallel – lines 91-140
# ---------------------------------------------------------------------------


def test_process_files_parallel_success(tmp_path: Path):
    sample = _sample_pe()
    local = tmp_path / sample.name
    local.write_bytes(sample.read_bytes())

    all_results: dict = {}
    failed_files: list = []
    output_path = tmp_path / "out"
    output_path.mkdir()

    rate_limiter = BatchRateLimiter(max_concurrent=1, rate_per_second=100.0, enable_adaptive=False)
    process_files_parallel(
        [local],
        all_results,
        failed_files,
        output_path,
        tmp_path,
        Config(),
        {"full_analysis": False},
        False,
        1,
        rate_limiter,
    )

    assert local.name in all_results
    assert failed_files == []


def test_process_files_parallel_rate_limit_failure_recorded(tmp_path: Path):
    dummy = tmp_path / "dummy.bin"
    dummy.write_bytes(b"\x00" * 4)

    all_results: dict = {}
    failed_files: list = []
    output_path = tmp_path / "out"
    output_path.mkdir()

    process_files_parallel(
        [dummy],
        all_results,
        failed_files,
        output_path,
        tmp_path,
        Config(),
        {},
        False,
        1,
        _RejectingRateLimiter(),
    )

    assert dummy.name not in all_results
    assert len(failed_files) == 1


def test_process_files_parallel_multiple_files(tmp_path: Path):
    sample = _sample_pe()
    files = []
    for i in range(2):
        f = tmp_path / f"copy{i}_{sample.name}"
        f.write_bytes(sample.read_bytes())
        files.append(f)

    all_results: dict = {}
    failed_files: list = []
    output_path = tmp_path / "out"
    output_path.mkdir()

    rate_limiter = BatchRateLimiter(max_concurrent=2, rate_per_second=100.0, enable_adaptive=False)
    process_files_parallel(
        files,
        all_results,
        failed_files,
        output_path,
        tmp_path,
        Config(),
        {"full_analysis": False},
        False,
        2,
        rate_limiter,
    )

    assert len(all_results) == 2
    assert failed_files == []


def test_process_files_parallel_thread_cap_applied(tmp_path: Path):
    sample = _sample_pe()
    local = tmp_path / sample.name
    local.write_bytes(sample.read_bytes())

    all_results: dict = {}
    failed_files: list = []
    output_path = tmp_path / "out"
    output_path.mkdir()

    os.environ["R2INSPECT_MAX_THREADS"] = "1"
    try:
        rate_limiter = BatchRateLimiter(max_concurrent=1, rate_per_second=100.0, enable_adaptive=False)
        process_files_parallel(
            [local],
            all_results,
            failed_files,
            output_path,
            tmp_path,
            Config(),
            {"full_analysis": False},
            False,
            10,
            rate_limiter,
        )
        assert local.name in all_results
    finally:
        del os.environ["R2INSPECT_MAX_THREADS"]
