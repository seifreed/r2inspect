#!/usr/bin/env python3
"""Tests for r2inspect/cli/commands/analysis_output.py - Output formatting and display.

All tests use real objects (Console, OutputFormatter, tmp_path files).
No mocks, no monkeypatch, no @patch.
"""

import io
import json
from pathlib import Path

from rich.console import Console

from r2inspect.cli.commands import analysis_output
from r2inspect.cli.output_formatters import OutputFormatter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_console() -> Console:
    """Build a real Console that captures output to a string buffer."""
    return Console(file=io.StringIO(), force_terminal=False, width=120)


def _console_text(console: Console) -> str:
    """Extract the text written to a string-backed Console."""
    f = console.file
    if hasattr(f, "getvalue"):
        return f.getvalue()
    return ""


def _sample_results() -> dict:
    """Minimal but realistic analysis results dict."""
    return {
        "file_info": {
            "name": "sample.exe",
            "size": 4096,
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "file_type": "PE32",
        },
        "analysis": {
            "strings": ["CreateFileA", "RegOpenKeyExW"],
            "imports": [{"name": "kernel32.dll", "functions": ["CreateFileA"]}],
        },
    }


# ---------------------------------------------------------------------------
# print_status_if_needed
# ---------------------------------------------------------------------------


class TestPrintStatusIfNeeded:
    """Verify the status message appears (or not) depending on output options."""

    def test_console_output_prints_status(self):
        console = _make_console()
        analysis_output.print_status_if_needed(
            console=console,
            output_json=False,
            output_csv=False,
            output_file=None,
        )
        text = _console_text(console)
        assert "Starting analysis" in text

    def test_json_file_prints_status(self, tmp_path):
        console = _make_console()
        analysis_output.print_status_if_needed(
            console=console,
            output_json=True,
            output_csv=False,
            output_file=str(tmp_path / "out.json"),
        )
        text = _console_text(console)
        assert "Starting analysis" in text

    def test_csv_file_prints_status(self, tmp_path):
        console = _make_console()
        analysis_output.print_status_if_needed(
            console=console,
            output_json=False,
            output_csv=True,
            output_file=str(tmp_path / "out.csv"),
        )
        text = _console_text(console)
        assert "Starting analysis" in text

    def test_json_no_file_suppresses_status(self):
        console = _make_console()
        analysis_output.print_status_if_needed(
            console=console,
            output_json=True,
            output_csv=False,
            output_file=None,
        )
        text = _console_text(console)
        assert text.strip() == ""

    def test_csv_no_file_suppresses_status(self):
        console = _make_console()
        analysis_output.print_status_if_needed(
            console=console,
            output_json=False,
            output_csv=True,
            output_file=None,
        )
        text = _console_text(console)
        assert text.strip() == ""


# ---------------------------------------------------------------------------
# _write_output  (file and console paths)
# ---------------------------------------------------------------------------


class TestWriteOutput:
    """Verify _write_output writes real files and prints to stdout."""

    def test_writes_to_file(self, tmp_path):
        out = tmp_path / "output.txt"
        console = _make_console()
        analysis_output._write_output(
            content="hello world",
            output_file=str(out),
            console=console,
            label="Test",
        )
        assert out.read_text(encoding="utf-8") == "hello world"
        assert "saved to" in _console_text(console)

    def test_writes_to_file_path_object(self, tmp_path):
        out = tmp_path / "output.txt"
        console = _make_console()
        analysis_output._write_output(
            content="content via Path",
            output_file=out,
            console=console,
            label="Data",
        )
        assert out.read_text(encoding="utf-8") == "content via Path"

    def test_multiline_content_preserved(self, tmp_path):
        out = tmp_path / "multi.txt"
        content = "line1\nline2\nline3"
        console = _make_console()
        analysis_output._write_output(
            content=content,
            output_file=str(out),
            console=console,
            label="Multi",
        )
        assert out.read_text(encoding="utf-8") == content

    def test_prints_to_stdout_when_no_file(self, capsys):
        console = _make_console()
        analysis_output._write_output(
            content="stdout content",
            output_file=None,
            console=console,
            label="Stdout",
        )
        captured = capsys.readouterr()
        assert "stdout content" in captured.out

    def test_label_appears_in_save_message(self, tmp_path):
        out = tmp_path / "out.json"
        console = _make_console()
        analysis_output._write_output(
            content="{}",
            output_file=str(out),
            console=console,
            label="JSON",
        )
        text = _console_text(console)
        assert "JSON" in text


# ---------------------------------------------------------------------------
# OutputFormatter integration (real formatter, real file I/O)
# ---------------------------------------------------------------------------


class TestOutputFormatterIntegration:
    """Use a real OutputFormatter and verify actual file contents."""

    def test_formatter_produces_valid_json(self):
        results = _sample_results()
        formatter = OutputFormatter(results)
        raw = formatter.to_json()
        parsed = json.loads(raw)
        assert parsed["file_info"]["name"] == "sample.exe"

    def test_formatter_produces_csv_string(self):
        results = _sample_results()
        formatter = OutputFormatter(results)
        csv_text = formatter.to_csv()
        assert isinstance(csv_text, str)
        # CSV should have at least a header line
        assert len(csv_text.strip()) > 0


# ---------------------------------------------------------------------------
# _output_json_results  (end-to-end with real formatter + real file)
# ---------------------------------------------------------------------------


class TestOutputJsonResults:
    """Verify JSON output path writes valid JSON to disk or stdout."""

    def test_json_to_file(self, tmp_path):
        out = tmp_path / "result.json"
        console = _make_console()
        formatter = OutputFormatter(_sample_results())

        analysis_output._output_json_results(
            formatter=formatter,
            output_file=str(out),
            console=console,
        )

        raw = out.read_text(encoding="utf-8")
        parsed = json.loads(raw)
        assert "file_info" in parsed
        assert "saved to" in _console_text(console)

    def test_json_to_stdout(self, capsys):
        console = _make_console()
        formatter = OutputFormatter(_sample_results())

        analysis_output._output_json_results(
            formatter=formatter,
            output_file=None,
            console=console,
        )

        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert "file_info" in parsed


# ---------------------------------------------------------------------------
# _output_csv_results  (end-to-end with real formatter + real file)
# ---------------------------------------------------------------------------


class TestOutputCsvResults:
    """Verify CSV output path writes CSV to disk or stdout."""

    def test_csv_to_file(self, tmp_path):
        out = tmp_path / "result.csv"
        console = _make_console()
        formatter = OutputFormatter(_sample_results())

        analysis_output._output_csv_results(
            formatter=formatter,
            output_file=str(out),
            console=console,
        )

        raw = out.read_text(encoding="utf-8")
        assert len(raw.strip()) > 0
        assert "saved to" in _console_text(console)

    def test_csv_to_stdout(self, capsys):
        console = _make_console()
        formatter = OutputFormatter(_sample_results())

        analysis_output._output_csv_results(
            formatter=formatter,
            output_file=None,
            console=console,
        )

        captured = capsys.readouterr()
        assert len(captured.out.strip()) > 0


# ---------------------------------------------------------------------------
# output_results  (high-level dispatcher, real objects)
# ---------------------------------------------------------------------------


class TestOutputResults:
    """Exercise the top-level output_results dispatcher with real objects."""

    def test_json_dispatch_writes_file(self, tmp_path):
        out = tmp_path / "dispatch.json"
        console = _make_console()

        analysis_output.output_results(
            results=_sample_results(),
            output_json=True,
            output_csv=False,
            output_file=str(out),
            verbose=False,
            console=console,
        )

        parsed = json.loads(out.read_text(encoding="utf-8"))
        assert "file_info" in parsed

    def test_csv_dispatch_writes_file(self, tmp_path):
        out = tmp_path / "dispatch.csv"
        console = _make_console()

        analysis_output.output_results(
            results=_sample_results(),
            output_json=False,
            output_csv=True,
            output_file=str(out),
            verbose=False,
            console=console,
        )

        raw = out.read_text(encoding="utf-8")
        assert len(raw.strip()) > 0

    def test_json_dispatch_to_stdout(self, capsys):
        console = _make_console()

        analysis_output.output_results(
            results=_sample_results(),
            output_json=True,
            output_csv=False,
            output_file=None,
            verbose=False,
            console=console,
        )

        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert "file_info" in parsed

    def test_console_dispatch_runs_display(self):
        """Console path calls display_results which renders to the global console.
        We just ensure it does not raise."""
        console = _make_console()
        analysis_output.output_results(
            results=_sample_results(),
            output_json=False,
            output_csv=False,
            output_file=None,
            verbose=False,
            console=console,
        )

    def test_console_dispatch_verbose_runs(self):
        """Verbose console path should not raise even with zero stats."""
        console = _make_console()
        analysis_output.output_results(
            results=_sample_results(),
            output_json=False,
            output_csv=False,
            output_file=None,
            verbose=True,
            console=console,
        )


# ---------------------------------------------------------------------------
# _output_console_results
# ---------------------------------------------------------------------------


class TestOutputConsoleResults:
    """Direct invocation of the console display path."""

    def test_non_verbose_does_not_raise(self):
        analysis_output._output_console_results(_sample_results(), verbose=False)

    def test_verbose_does_not_raise(self):
        analysis_output._output_console_results(_sample_results(), verbose=True)


# ---------------------------------------------------------------------------
# _collect_statistics  (real stat functions)
# ---------------------------------------------------------------------------


class TestCollectStatistics:
    """Call _collect_statistics against the real stat implementations."""

    def test_returns_three_dicts(self):
        error_stats, retry_stats, circuit_stats = analysis_output._collect_statistics()
        assert isinstance(error_stats, dict)
        assert isinstance(retry_stats, dict)
        assert isinstance(circuit_stats, dict)

    def test_error_stats_has_total_errors_key(self):
        error_stats, _, _ = analysis_output._collect_statistics()
        assert "total_errors" in error_stats


# ---------------------------------------------------------------------------
# _display_verbose_statistics  (real stat functions, real display)
# ---------------------------------------------------------------------------


class TestDisplayVerboseStatistics:
    """Ensure verbose statistics path runs without error."""

    def test_runs_without_error(self):
        # In a clean test run there are no errors/retries, so no stats rendered.
        analysis_output._display_verbose_statistics()


# ---------------------------------------------------------------------------
# add_statistics_to_results  (real AnalysisService)
# ---------------------------------------------------------------------------


class TestAddStatisticsToResults:
    """Verify add_statistics_to_results mutates the results dict via the real service."""

    def test_returns_none_and_may_add_keys(self):
        results = _sample_results()
        original_keys = set(results.keys())
        analysis_output.add_statistics_to_results(results)
        # The function should not remove existing keys
        assert original_keys.issubset(results.keys())

    def test_no_error_stats_when_clean(self):
        results = _sample_results()
        analysis_output.add_statistics_to_results(results)
        # With no actual analysis run, total_errors should be 0 => no key added
        assert "error_statistics" not in results
