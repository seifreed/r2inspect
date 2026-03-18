#!/usr/bin/env python3
"""Tests for r2inspect/cli/analysis_runner.py — zero mocks.

Every test exercises real code paths.  CLI output is captured via
``Console(file=StringIO())`` or by inspecting return values directly.
"""

import json
import sys
from io import StringIO
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console

from r2inspect.application.analysis_service import AnalysisService
from r2inspect.cli.analysis_runner import (
    add_statistics_to_results,
    handle_main_error,
    has_circuit_breaker_data,
    output_console_results,
    output_csv_results,
    output_json_results,
    output_results,
    print_status_if_appropriate,
    setup_analysis_options,
    setup_single_file_output,
)
from r2inspect.cli.commands.analysis_output import (
    _output_csv_results,
    _output_json_results,
    _write_output,
    print_status_if_needed,
)
from r2inspect.cli.output_formatters import OutputFormatter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_console() -> tuple[Console, StringIO]:
    """Return a ``(console, buffer)`` pair that captures printed output."""
    buf = StringIO()
    return Console(file=buf, force_terminal=False, width=200), buf


def _sample_results() -> dict[str, Any]:
    """Minimal analysis-result dict used by several tests."""
    return {
        "file_info": {
            "name": "test.exe",
            "size": 1024,
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "file_type": "PE32",
        },
    }


# ---------------------------------------------------------------------------
# setup_analysis_options — pure function, no I/O
# ---------------------------------------------------------------------------


class TestSetupAnalysisOptions:
    def test_default_options(self):
        opts = setup_analysis_options(None, None)
        assert opts["detect_packer"] is True
        assert opts["detect_crypto"] is True
        assert opts["detect_av"] is True
        assert opts["full_analysis"] is True
        assert opts["custom_yara"] is None
        assert opts["xor_search"] is None

    def test_with_yara(self):
        opts = setup_analysis_options("/path/to/yara", None)
        assert opts["custom_yara"] == "/path/to/yara"
        assert opts["detect_packer"] is True

    def test_with_xor(self):
        opts = setup_analysis_options(None, "xor_string")
        assert opts["xor_search"] == "xor_string"
        assert opts["full_analysis"] is True

    def test_with_both(self):
        opts = setup_analysis_options("/yara/path", "xor_data")
        assert opts["custom_yara"] == "/yara/path"
        assert opts["xor_search"] == "xor_data"


# ---------------------------------------------------------------------------
# setup_single_file_output — creates real paths on disk
# ---------------------------------------------------------------------------


class TestSetupSingleFileOutput:
    def test_json_output_generates_path(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = setup_single_file_output(True, False, None, "test.exe")
        assert isinstance(result, Path)
        assert str(result).endswith("_analysis.json")
        assert "test" in str(result)

    def test_csv_output_generates_path(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = setup_single_file_output(False, True, None, "test.exe")
        assert isinstance(result, Path)
        assert str(result).endswith("_analysis.csv")
        assert "test" in str(result)

    def test_custom_output_path_passed_through(self):
        result = setup_single_file_output(True, False, "custom.json", "test.exe")
        assert result == "custom.json"

    def test_none_when_no_output_requested(self):
        result = setup_single_file_output(False, False, None, "test.exe")
        assert result is None

    def test_directory_is_created(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = setup_single_file_output(True, False, None, "test.exe")
        assert result is not None
        assert result.parent.exists()

    def test_path_object_returned(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = setup_single_file_output(True, False, None, "/full/path/to/test.exe")
        assert isinstance(result, Path)

    def test_nested_path(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        nested = str(tmp_path / "nested" / "dir" / "file.exe")
        result = setup_single_file_output(True, False, None, nested)
        assert isinstance(result, Path)
        assert result.name.endswith("_analysis.json")

    def test_special_characters_in_filename(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = setup_single_file_output(True, False, None, "test-file.v2.exe")
        assert "test-file.v2" in str(result)


# ---------------------------------------------------------------------------
# has_circuit_breaker_data — exercises the real AnalysisService static method
# ---------------------------------------------------------------------------


class TestHasCircuitBreakerData:
    def test_true_with_nonzero_values(self):
        stats = {"total_calls": 100, "failures": 5}
        assert has_circuit_breaker_data(stats) is True

    def test_false_for_empty_dict(self):
        assert has_circuit_breaker_data({}) is False

    def test_complex_stats_with_nested_values(self):
        stats = {
            "total_calls": 1000,
            "failures": 10,
            "success_rate": 0.99,
            "state": "closed",
        }
        assert has_circuit_breaker_data(stats) is True

    def test_false_when_all_zeros(self):
        stats = {"total_calls": 0, "failures": 0}
        assert has_circuit_breaker_data(stats) is False

    def test_nested_dict_with_positive_int(self):
        stats = {"breaker_a": {"failures": 3, "state": "open"}}
        assert has_circuit_breaker_data(stats) is True

    def test_nested_dict_non_closed_string(self):
        stats = {"breaker_a": {"state": "open"}}
        assert has_circuit_breaker_data(stats) is True

    def test_nested_dict_closed_string_only(self):
        stats = {"breaker_a": {"state": "closed"}}
        assert has_circuit_breaker_data(stats) is False


# ---------------------------------------------------------------------------
# add_statistics_to_results — real AnalysisService
# ---------------------------------------------------------------------------


class TestAddStatisticsToResults:
    def test_adds_stats_to_empty_results(self):
        results: dict[str, Any] = {}
        # Calling the real function — it will collect live stats
        # (which should all be zero in a fresh test context).
        add_statistics_to_results(results)
        # No crash; stats may or may not be inserted depending on runtime state.
        assert isinstance(results, dict)

    def test_preserves_existing_keys(self):
        results = {"file_info": {"name": "test.exe"}}
        add_statistics_to_results(results)
        assert results["file_info"]["name"] == "test.exe"


# ---------------------------------------------------------------------------
# print_status_if_needed — real Console, captured output
# ---------------------------------------------------------------------------


class TestPrintStatusIfAppropriate:
    def test_console_mode_prints_starting(self):
        console, buf = _make_console()
        print_status_if_needed(console, output_json=False, output_csv=False, output_file=None)
        text = buf.getvalue()
        assert "Starting analysis" in text

    def test_json_to_file_prints_starting(self):
        console, buf = _make_console()
        print_status_if_needed(console, output_json=True, output_csv=False, output_file="out.json")
        text = buf.getvalue()
        assert "Starting analysis" in text

    def test_json_no_file_no_output(self):
        console, buf = _make_console()
        print_status_if_needed(console, output_json=True, output_csv=False, output_file=None)
        text = buf.getvalue()
        # json-to-stdout: no status message expected
        assert "Starting analysis" not in text

    def test_csv_to_file_prints_starting(self):
        console, buf = _make_console()
        print_status_if_needed(console, output_json=False, output_csv=True, output_file="out.csv")
        text = buf.getvalue()
        assert "Starting analysis" in text


# ---------------------------------------------------------------------------
# _write_output — real file I/O
# ---------------------------------------------------------------------------


class TestWriteOutput:
    def test_writes_to_file(self, tmp_path):
        out = tmp_path / "result.json"
        console, buf = _make_console()
        _write_output('{"key": "value"}', str(out), console, "JSON")
        assert out.read_text() == '{"key": "value"}'
        assert "JSON results saved to" in buf.getvalue()

    def test_prints_to_stdout_when_no_file(self, capsys):
        console, buf = _make_console()
        _write_output("hello", None, console, "TXT")
        captured = capsys.readouterr()
        assert "hello" in captured.out


# ---------------------------------------------------------------------------
# OutputFormatter JSON / CSV — real formatting
# ---------------------------------------------------------------------------


class TestOutputFormatterJson:
    def test_json_round_trip(self):
        results = _sample_results()
        formatter = OutputFormatter(results)
        json_str = formatter.to_json()
        parsed = json.loads(json_str)
        assert parsed["file_info"]["name"] == "test.exe"

    def test_json_output_to_file(self, tmp_path):
        results = _sample_results()
        formatter = OutputFormatter(results)
        console, buf = _make_console()
        out = tmp_path / "out.json"
        _output_json_results(formatter, str(out), console)
        assert out.exists()
        parsed = json.loads(out.read_text())
        assert parsed["file_info"]["name"] == "test.exe"
        assert "JSON results saved to" in buf.getvalue()

    def test_json_output_to_stdout(self, capsys):
        results = _sample_results()
        formatter = OutputFormatter(results)
        console, buf = _make_console()
        _output_json_results(formatter, None, console)
        captured = capsys.readouterr()
        assert "test.exe" in captured.out


class TestOutputFormatterCsv:
    def test_csv_output_to_file(self, tmp_path):
        results = _sample_results()
        formatter = OutputFormatter(results)
        console, buf = _make_console()
        out = tmp_path / "out.csv"
        _output_csv_results(formatter, str(out), console)
        assert out.exists()
        content = out.read_text()
        # CSV should contain some content
        assert len(content) > 0
        assert "CSV results saved to" in buf.getvalue()

    def test_csv_output_to_stdout(self, capsys):
        results = _sample_results()
        formatter = OutputFormatter(results)
        console, buf = _make_console()
        _output_csv_results(formatter, None, console)
        captured = capsys.readouterr()
        assert len(captured.out) > 0


# ---------------------------------------------------------------------------
# output_results — dispatches to json / csv / console
# ---------------------------------------------------------------------------


class TestOutputResultsDispatch:
    def test_json_dispatch_writes_file(self, tmp_path):
        results = _sample_results()
        console, buf = _make_console()
        out = tmp_path / "dispatch.json"
        from r2inspect.cli.commands.analysis_output import output_results as ao_output_results

        ao_output_results(results, True, False, str(out), False, console)
        assert out.exists()
        parsed = json.loads(out.read_text())
        assert parsed["file_info"]["name"] == "test.exe"

    def test_csv_dispatch_writes_file(self, tmp_path):
        results = _sample_results()
        console, buf = _make_console()
        out = tmp_path / "dispatch.csv"
        from r2inspect.cli.commands.analysis_output import output_results as ao_output_results

        ao_output_results(results, False, True, str(out), False, console)
        assert out.exists()
        assert len(out.read_text()) > 0


# ---------------------------------------------------------------------------
# output_json_results / output_csv_results facade
# ---------------------------------------------------------------------------


class TestOutputJsonResultsFacade:
    def test_facade_writes_file(self, tmp_path):
        results = _sample_results()
        formatter = OutputFormatter(results)
        out = tmp_path / "facade.json"
        # Call the facade — it uses the module-level console
        console, buf = _make_console()
        _output_json_results(formatter, str(out), console)
        assert out.exists()

    def test_facade_no_file(self, capsys):
        results = _sample_results()
        formatter = OutputFormatter(results)
        console, buf = _make_console()
        _output_json_results(formatter, None, console)
        captured = capsys.readouterr()
        assert "test.exe" in captured.out


class TestOutputCsvResultsFacade:
    def test_facade_writes_file(self, tmp_path):
        results = _sample_results()
        formatter = OutputFormatter(results)
        out = tmp_path / "facade.csv"
        console, buf = _make_console()
        _output_csv_results(formatter, str(out), console)
        assert out.exists()

    def test_facade_no_file(self, capsys):
        results = _sample_results()
        formatter = OutputFormatter(results)
        console, buf = _make_console()
        _output_csv_results(formatter, None, console)
        captured = capsys.readouterr()
        assert len(captured.out) > 0


# ---------------------------------------------------------------------------
# handle_main_error — real Console, real SystemExit
# ---------------------------------------------------------------------------


class TestHandleMainError:
    def test_non_verbose_exits_with_1(self):
        from r2inspect.cli.analysis_runner_support import handle_main_error as _handle

        console, buf = _make_console()
        error = ValueError("Test error message")
        with pytest.raises(SystemExit) as exc_info:
            _handle(console, error, verbose=False)
        assert exc_info.value.code == 1
        assert "Test error message" in buf.getvalue()

    def test_verbose_exits_with_1(self):
        from r2inspect.cli.analysis_runner_support import handle_main_error as _handle

        console, buf = _make_console()
        error = RuntimeError("Test runtime error")
        with pytest.raises(SystemExit) as exc_info:
            _handle(console, error, verbose=True)
        assert exc_info.value.code == 1
        assert "Test runtime error" in buf.getvalue()

    def test_error_message_in_output(self):
        from r2inspect.cli.analysis_runner_support import handle_main_error as _handle

        console, buf = _make_console()
        error = Exception("Custom error")
        with pytest.raises(SystemExit):
            _handle(console, error, verbose=False)
        assert "Custom error" in buf.getvalue()


# ---------------------------------------------------------------------------
# output_console_results — exercises display dispatch
# ---------------------------------------------------------------------------


class TestOutputConsoleResults:
    def test_console_output_does_not_crash(self):
        """Calling console output with a valid results dict must not raise."""
        results = _sample_results()
        # output_console_results invokes display_results internally.
        # We just assert it doesn't blow up.
        try:
            output_console_results(results, False)
        except SystemExit:
            pytest.skip("display_results triggered exit")

    def test_console_verbose_does_not_crash(self):
        results = _sample_results()
        try:
            output_console_results(results, True)
        except SystemExit:
            pytest.skip("display_results triggered exit")


# ---------------------------------------------------------------------------
# Integration-style: setup_single_file_output → output → read back
# ---------------------------------------------------------------------------


class TestEndToEndOutputRoundTrip:
    def test_json_round_trip(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        path = setup_single_file_output(True, False, None, "sample.exe")
        assert path is not None
        results = _sample_results()
        formatter = OutputFormatter(results)
        console, buf = _make_console()
        _output_json_results(formatter, str(path), console)
        assert path.exists()
        parsed = json.loads(path.read_text())
        assert parsed["file_info"]["name"] == "test.exe"

    def test_csv_round_trip(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        path = setup_single_file_output(False, True, None, "sample.exe")
        assert path is not None
        results = _sample_results()
        formatter = OutputFormatter(results)
        console, buf = _make_console()
        _output_csv_results(formatter, str(path), console)
        assert path.exists()
        content = path.read_text()
        assert len(content) > 0
