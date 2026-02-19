#!/usr/bin/env python3
"""Comprehensive tests for r2inspect/cli/batch_workers.py"""

import os
import threading
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from r2inspect.cli.batch_workers import _cap_threads_for_execution, process_files_parallel, process_single_file


def test_cap_threads_for_execution_no_env():
    if "R2INSPECT_MAX_THREADS" in os.environ:
        del os.environ["R2INSPECT_MAX_THREADS"]
    result = _cap_threads_for_execution(10)
    assert result == 10


def test_cap_threads_for_execution_with_cap():
    os.environ["R2INSPECT_MAX_THREADS"] = "5"
    try:
        result = _cap_threads_for_execution(10)
        assert result == 5
    finally:
        del os.environ["R2INSPECT_MAX_THREADS"]


def test_cap_threads_for_execution_cap_higher():
    os.environ["R2INSPECT_MAX_THREADS"] = "20"
    try:
        result = _cap_threads_for_execution(10)
        assert result == 10
    finally:
        del os.environ["R2INSPECT_MAX_THREADS"]


def test_cap_threads_for_execution_invalid():
    os.environ["R2INSPECT_MAX_THREADS"] = "invalid"
    try:
        result = _cap_threads_for_execution(10)
        assert result == 10
    finally:
        del os.environ["R2INSPECT_MAX_THREADS"]


def test_cap_threads_for_execution_zero():
    os.environ["R2INSPECT_MAX_THREADS"] = "0"
    try:
        result = _cap_threads_for_execution(10)
        assert result == 10
    finally:
        del os.environ["R2INSPECT_MAX_THREADS"]


def test_cap_threads_for_execution_negative():
    os.environ["R2INSPECT_MAX_THREADS"] = "-5"
    try:
        result = _cap_threads_for_execution(10)
        assert result == 10
    finally:
        del os.environ["R2INSPECT_MAX_THREADS"]


def test_cap_threads_for_execution_empty_string():
    os.environ["R2INSPECT_MAX_THREADS"] = "   "
    try:
        result = _cap_threads_for_execution(10)
        assert result == 10
    finally:
        del os.environ["R2INSPECT_MAX_THREADS"]


def test_process_single_file_success(tmp_path):
    file_path = tmp_path / "test.exe"
    file_path.write_bytes(b"MZ" + b"\x00" * 100)
    batch_path = tmp_path
    output_path = tmp_path / "output"
    output_path.mkdir()

    config_obj = MagicMock()
    options = {"full_analysis": True}
    rate_limiter = Mock()
    rate_limiter.acquire.return_value = True

    with patch("r2inspect.cli.batch_workers.create_inspector") as mock_inspector:
        mock_insp = MagicMock()
        mock_inspector.return_value.__enter__.return_value = mock_insp

        with patch("r2inspect.cli.batch_workers.AnalyzeBinaryUseCase") as mock_use_case:
            mock_instance = mock_use_case.return_value
            mock_instance.run.return_value = {"file_info": {"name": "test.exe"}}

            result_path, results, error = process_single_file(
                file_path, batch_path, config_obj, options, False, output_path, rate_limiter
            )

            assert result_path == file_path
            assert results is not None
            assert error is None
            rate_limiter.release_success.assert_called_once()


def test_process_single_file_timeout(tmp_path):
    file_path = tmp_path / "test.exe"
    batch_path = tmp_path
    output_path = tmp_path / "output"

    rate_limiter = Mock()
    rate_limiter.acquire.return_value = False

    result_path, results, error = process_single_file(
        file_path, batch_path, MagicMock(), {}, False, output_path, rate_limiter
    )

    assert result_path == file_path
    assert results is None
    assert "timeout" in error.lower()


def test_process_single_file_error(tmp_path):
    file_path = tmp_path / "test.exe"
    batch_path = tmp_path
    output_path = tmp_path / "output"

    rate_limiter = Mock()
    rate_limiter.acquire.return_value = True

    with patch("r2inspect.cli.batch_workers.create_inspector") as mock_inspector:
        mock_inspector.side_effect = Exception("Test error")

        result_path, results, error = process_single_file(
            file_path, batch_path, MagicMock(), {}, False, output_path, rate_limiter
        )

        assert result_path == file_path
        assert results is None
        assert error == "Test error"
        rate_limiter.release_error.assert_called_once()


def test_process_single_file_with_json_output(tmp_path):
    file_path = tmp_path / "test.exe"
    file_path.write_bytes(b"MZ" + b"\x00" * 100)
    batch_path = tmp_path
    output_path = tmp_path / "output"
    output_path.mkdir()

    rate_limiter = Mock()
    rate_limiter.acquire.return_value = True

    with patch("r2inspect.cli.batch_workers.create_inspector") as mock_inspector:
        mock_insp = MagicMock()
        mock_inspector.return_value.__enter__.return_value = mock_insp

        with patch("r2inspect.cli.batch_workers.AnalyzeBinaryUseCase") as mock_use_case:
            mock_instance = mock_use_case.return_value
            mock_instance.run.return_value = {"file_info": {"name": "test.exe"}}

            with patch("r2inspect.cli.batch_workers.OutputFormatter") as mock_formatter:
                mock_fmt = mock_formatter.return_value
                mock_fmt.to_json.return_value = '{"test": "data"}'

                result_path, results, error = process_single_file(
                    file_path, batch_path, MagicMock(), {}, True, output_path, rate_limiter
                )

                assert error is None
                json_file = output_path / "test_analysis.json"
                assert json_file.exists()


def test_process_single_file_relative_path(tmp_path):
    subdir = tmp_path / "subdir"
    subdir.mkdir()
    file_path = subdir / "test.exe"
    file_path.write_bytes(b"MZ" + b"\x00" * 100)
    batch_path = tmp_path
    output_path = tmp_path / "output"
    output_path.mkdir()

    rate_limiter = Mock()
    rate_limiter.acquire.return_value = True

    with patch("r2inspect.cli.batch_workers.create_inspector") as mock_inspector:
        mock_insp = MagicMock()
        mock_inspector.return_value.__enter__.return_value = mock_insp

        with patch("r2inspect.cli.batch_workers.AnalyzeBinaryUseCase") as mock_use_case:
            mock_instance = mock_use_case.return_value
            mock_instance.run.return_value = {}

            result_path, results, error = process_single_file(
                file_path, batch_path, MagicMock(), {}, False, output_path, rate_limiter
            )

            assert "relative_path" in results
            assert "subdir" in str(results["relative_path"])


def test_process_files_parallel_single(tmp_path):
    file_path = tmp_path / "test.exe"
    file_path.write_bytes(b"MZ" + b"\x00" * 100)

    all_results = {}
    failed_files = []
    output_path = tmp_path / "output"
    output_path.mkdir()
    batch_path = tmp_path
    files_to_process = [file_path]

    rate_limiter = Mock()

    with patch("r2inspect.cli.batch_workers.process_single_file") as mock_process:
        mock_process.return_value = (file_path, {"file_info": {"name": "test.exe"}}, None)

        process_files_parallel(
            files_to_process,
            all_results,
            failed_files,
            output_path,
            batch_path,
            MagicMock(),
            {},
            False,
            1,
            rate_limiter,
        )

        assert len(all_results) == 1
        assert len(failed_files) == 0


def test_process_files_parallel_multiple(tmp_path):
    files = []
    for i in range(3):
        file_path = tmp_path / f"test{i}.exe"
        file_path.write_bytes(b"MZ" + b"\x00" * 100)
        files.append(file_path)

    all_results = {}
    failed_files = []
    output_path = tmp_path / "output"
    output_path.mkdir()
    batch_path = tmp_path

    rate_limiter = Mock()

    with patch("r2inspect.cli.batch_workers.process_single_file") as mock_process:
        mock_process.side_effect = [
            (files[0], {"file_info": {}}, None),
            (files[1], {"file_info": {}}, None),
            (files[2], {"file_info": {}}, None),
        ]

        process_files_parallel(
            files, all_results, failed_files, output_path, batch_path, MagicMock(), {}, False, 2, rate_limiter
        )

        assert len(all_results) == 3
        assert len(failed_files) == 0


def test_process_files_parallel_with_failures(tmp_path):
    files = []
    for i in range(2):
        file_path = tmp_path / f"test{i}.exe"
        file_path.write_bytes(b"MZ" + b"\x00" * 100)
        files.append(file_path)

    all_results = {}
    failed_files = []
    output_path = tmp_path / "output"
    output_path.mkdir()
    batch_path = tmp_path

    rate_limiter = Mock()

    with patch("r2inspect.cli.batch_workers.process_single_file") as mock_process:
        mock_process.side_effect = [
            (files[0], {"file_info": {}}, None),
            (files[1], None, "Test error"),
        ]

        process_files_parallel(
            files, all_results, failed_files, output_path, batch_path, MagicMock(), {}, False, 2, rate_limiter
        )

        assert len(all_results) == 1
        assert len(failed_files) == 1
        assert failed_files[0][1] == "Test error"


def test_process_files_parallel_empty_results(tmp_path):
    file_path = tmp_path / "test.exe"
    file_path.write_bytes(b"MZ" + b"\x00" * 100)

    all_results = {}
    failed_files = []
    output_path = tmp_path / "output"
    output_path.mkdir()

    rate_limiter = Mock()

    with patch("r2inspect.cli.batch_workers.process_single_file") as mock_process:
        mock_process.return_value = (file_path, None, None)

        process_files_parallel(
            [file_path], all_results, failed_files, output_path, tmp_path, MagicMock(), {}, False, 1, rate_limiter
        )

        assert len(all_results) == 0
        assert len(failed_files) == 1
        assert "Empty results" in failed_files[0][1]


def test_process_files_parallel_thread_cap(tmp_path):
    files = [tmp_path / f"test{i}.exe" for i in range(5)]
    for f in files:
        f.write_bytes(b"MZ" + b"\x00" * 100)

    all_results = {}
    failed_files = []
    output_path = tmp_path / "output"
    output_path.mkdir()

    rate_limiter = Mock()

    os.environ["R2INSPECT_MAX_THREADS"] = "2"
    try:
        with patch("r2inspect.cli.batch_workers.process_single_file") as mock_process:
            mock_process.return_value = (files[0], {}, None)

            process_files_parallel(
                files, all_results, failed_files, output_path, tmp_path, MagicMock(), {}, False, 10, rate_limiter
            )

    finally:
        del os.environ["R2INSPECT_MAX_THREADS"]


def test_process_files_parallel_progress_tracking(tmp_path):
    files = [tmp_path / f"test{i}.exe" for i in range(3)]
    for f in files:
        f.write_bytes(b"MZ" + b"\x00" * 100)

    all_results = {}
    failed_files = []
    output_path = tmp_path / "output"
    output_path.mkdir()

    rate_limiter = Mock()

    with patch("r2inspect.cli.batch_workers.process_single_file") as mock_process:
        mock_process.return_value = (files[0], {"info": {}}, None)

        with patch("r2inspect.cli.batch_workers.Progress") as mock_progress:
            mock_prog_instance = MagicMock()
            mock_progress.return_value.__enter__.return_value = mock_prog_instance
            mock_task = MagicMock()
            mock_prog_instance.add_task.return_value = mock_task

            process_files_parallel(
                files, all_results, failed_files, output_path, tmp_path, MagicMock(), {}, False, 2, rate_limiter
            )

            mock_prog_instance.add_task.assert_called_once()
            assert mock_prog_instance.update.call_count >= 3


def test_process_files_parallel_long_filename(tmp_path):
    long_name = "a" * 50 + ".exe"
    file_path = tmp_path / long_name
    file_path.write_bytes(b"MZ" + b"\x00" * 100)

    all_results = {}
    failed_files = []
    output_path = tmp_path / "output"
    output_path.mkdir()

    rate_limiter = Mock()

    with patch("r2inspect.cli.batch_workers.process_single_file") as mock_process:
        mock_process.return_value = (file_path, {"info": {}}, None)

        process_files_parallel(
            [file_path], all_results, failed_files, output_path, tmp_path, MagicMock(), {}, False, 1, rate_limiter
        )

        assert len(all_results) == 1


def test_process_files_parallel_thread_safety(tmp_path):
    files = [tmp_path / f"test{i}.exe" for i in range(10)]
    for f in files:
        f.write_bytes(b"MZ" + b"\x00" * 100)

    all_results = {}
    failed_files = []
    output_path = tmp_path / "output"
    output_path.mkdir()

    rate_limiter = Mock()
    call_count = {"count": 0}
    lock = threading.Lock()

    def mock_process_file(*args):
        with lock:
            call_count["count"] += 1
        return (args[0], {"info": {}}, None)

    with patch("r2inspect.cli.batch_workers.process_single_file", side_effect=mock_process_file):
        process_files_parallel(
            files, all_results, failed_files, output_path, tmp_path, MagicMock(), {}, False, 4, rate_limiter
        )

        assert len(all_results) == 10
        assert call_count["count"] == 10


def test_process_single_file_batch_mode_option(tmp_path):
    file_path = tmp_path / "test.exe"
    file_path.write_bytes(b"MZ" + b"\x00" * 100)
    batch_path = tmp_path
    output_path = tmp_path / "output"
    output_path.mkdir()

    rate_limiter = Mock()
    rate_limiter.acquire.return_value = True
    options = {"full_analysis": False}

    with patch("r2inspect.cli.batch_workers.create_inspector") as mock_inspector:
        mock_insp = MagicMock()
        mock_inspector.return_value.__enter__.return_value = mock_insp

        with patch("r2inspect.cli.batch_workers.AnalyzeBinaryUseCase") as mock_use_case:
            mock_instance = mock_use_case.return_value
            mock_instance.run.return_value = {}

            process_single_file(file_path, batch_path, MagicMock(), options, False, output_path, rate_limiter)

            called_options = mock_instance.run.call_args[0][1]
            assert called_options["batch_mode"] is True


def test_process_single_file_error_type_tracking(tmp_path):
    file_path = tmp_path / "test.exe"
    batch_path = tmp_path
    output_path = tmp_path / "output"

    rate_limiter = Mock()
    rate_limiter.acquire.return_value = True

    class CustomError(Exception):
        pass

    with patch("r2inspect.cli.batch_workers.create_inspector") as mock_inspector:
        mock_inspector.side_effect = CustomError("Custom error")

        result_path, results, error = process_single_file(
            file_path, batch_path, MagicMock(), {}, False, output_path, rate_limiter
        )

        rate_limiter.release_error.assert_called_once_with("CustomError")


def test_process_files_parallel_console_output():
    with patch("r2inspect.cli.batch_workers.console") as mock_console:
        with patch("r2inspect.cli.batch_workers.process_single_file") as mock_process:
            mock_process.return_value = (Path("test.exe"), {}, None)

            process_files_parallel(
                [Path("test.exe")], {}, [], Path("."), Path("."), MagicMock(), {}, False, 1, Mock()
            )
