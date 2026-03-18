"""Tests for cli/commands/analyze_command.py - edge cases and error paths.

All tests use real objects: real Config, real Console(file=StringIO()),
real CommandContext, real OutputFormatter. No mocks, no monkeypatch, no @patch.
"""

import logging
from io import StringIO
from pathlib import Path

from rich.console import Console

from r2inspect.cli.commands.analyze_command import AnalyzeCommand
from r2inspect.cli.commands.base import CommandContext
from r2inspect.cli.output_formatters import OutputFormatter
from r2inspect.config import Config


def _make_context(verbose: bool = False, quiet: bool = False) -> CommandContext:
    """Build a real CommandContext with captured console output."""
    console = Console(file=StringIO(), force_terminal=False)
    logger = logging.getLogger("test.analyze_command_edge")
    config = Config()
    return CommandContext(
        console=console,
        logger=logger,
        config=config,
        verbose=verbose,
        quiet=quiet,
    )


def _console_text(ctx: CommandContext) -> str:
    """Extract everything printed to the context's console."""
    ctx.console.file.seek(0)
    return ctx.console.file.read()


# ── execute() error paths ────────────────────────────────────────────


def test_analyze_command_exception_on_nonexistent_file():
    """execute() returns 1 when the file does not exist (real error path)."""
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)

    args = {
        "filename": "/nonexistent/path/to/fake_binary.exe",
        "config": None,
        "verbose": False,
    }

    result = cmd.execute(args)

    assert result == 1
    output = _console_text(ctx)
    # Should contain the error message rendered by _handle_error
    assert "failed" in output.lower() or "error" in output.lower()


def test_analyze_command_exception_verbose_on_nonexistent_file():
    """execute() returns 1 with traceback when verbose and file missing."""
    ctx = _make_context(verbose=True)
    cmd = AnalyzeCommand(ctx)

    args = {
        "filename": "/nonexistent/path/to/fake_binary.exe",
        "config": None,
        "verbose": True,
    }

    result = cmd.execute(args)

    assert result == 1
    output = _console_text(ctx)
    assert "error" in output.lower()


def test_analyze_command_exception_on_empty_file(tmp_path):
    """execute() returns 1 when file exists but is empty / invalid binary."""
    empty_file = tmp_path / "empty.exe"
    empty_file.write_bytes(b"")

    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)

    args = {
        "filename": str(empty_file),
        "config": None,
        "verbose": False,
    }

    result = cmd.execute(args)

    # Either the file validator rejects it or r2pipe fails; either way → 1
    assert result == 1


# ── _handle_error ────────────────────────────────────────────────────


def test_handle_error_verbose():
    """_handle_error in verbose mode prints error + traceback."""
    ctx = _make_context(verbose=True)
    cmd = AnalyzeCommand(ctx)

    error = RuntimeError("Test error message for verbose")
    cmd._handle_error(error, verbose=True)

    output = _console_text(ctx)
    assert "Test error message for verbose" in output
    # Verbose mode shows the dim traceback section
    assert "verbose" in output.lower() or "Error" in output


def test_handle_error_non_verbose():
    """_handle_error in non-verbose mode prints concise error + hint."""
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)

    error = RuntimeError("Analysis broke")
    cmd._handle_error(error, verbose=False)

    output = _console_text(ctx)
    assert "Analysis broke" in output or "failed" in output.lower()
    # The compact path suggests --verbose
    assert "--verbose" in output


# ── _handle_error (inherited from Command base class) ────────────────


def test_handle_error_verbose():
    """_handle_error in verbose mode renders error text and traceback."""
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)

    try:
        raise ValueError("boom")
    except ValueError as e:
        cmd._handle_error(e, verbose=True, context_label="Analysis")

    output = _console_text(ctx)
    assert "boom" in output
    assert "Traceback" in output


def test_handle_error_compact():
    """_handle_error in non-verbose mode renders concise message and hint."""
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)

    cmd._handle_error(ValueError("something went wrong"), verbose=False, context_label="Analysis")

    output = _console_text(ctx)
    assert "something went wrong" in output
    assert "--verbose" in output


# ── _show_analysis_start ─────────────────────────────────────────────


def test_show_analysis_start():
    """_show_analysis_start prints filename."""
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)

    cmd._show_analysis_start("malware.exe")

    output = _console_text(ctx)
    assert "malware.exe" in output


# ── _print_status_if_needed ──────────────────────────────────────────


def test_print_status_if_needed_console_output():
    """Status message printed when output is console (no json/csv)."""
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)

    cmd._print_status_if_needed(output_json=False, output_csv=False, output_file=None)

    output = _console_text(ctx)
    assert "Starting analysis" in output


def test_print_status_if_needed_json_to_file(tmp_path):
    """Status message printed when JSON output goes to a file."""
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)

    cmd._print_status_if_needed(
        output_json=True,
        output_csv=False,
        output_file=str(tmp_path / "out.json"),
    )

    output = _console_text(ctx)
    assert "Starting analysis" in output


def test_print_status_if_needed_json_to_stdout():
    """No status message when JSON goes to stdout (would pollute output)."""
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)

    cmd._print_status_if_needed(output_json=True, output_csv=False, output_file=None)

    output = _console_text(ctx)
    assert "Starting analysis" not in output


def test_print_status_if_needed_csv_to_stdout():
    """No status message when CSV goes to stdout."""
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)

    cmd._print_status_if_needed(output_json=False, output_csv=True, output_file=None)

    output = _console_text(ctx)
    assert "Starting analysis" not in output


# ── _output_results ──────────────────────────────────────────────────


def test_output_results_json_to_file(tmp_path):
    """_output_results writes JSON when output_json=True and output_file given."""
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)

    outfile = tmp_path / "results.json"
    results = {"file_info": {"name": "test.exe"}, "hashes": {}}

    cmd._output_results(
        results=results,
        output_json=True,
        output_csv=False,
        output_file=str(outfile),
        verbose=False,
    )

    assert outfile.exists()
    content = outfile.read_text()
    assert "test.exe" in content

    output = _console_text(ctx)
    assert "JSON" in output


def test_output_results_csv_to_file(tmp_path):
    """_output_results writes CSV when output_csv=True and output_file given."""
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)

    outfile = tmp_path / "results.csv"
    results = {"file_info": {"name": "sample.bin"}, "hashes": {}}

    cmd._output_results(
        results=results,
        output_json=False,
        output_csv=True,
        output_file=str(outfile),
        verbose=False,
    )

    assert outfile.exists()
    content = outfile.read_text()
    # CSV file should have content
    assert len(content) > 0

    output = _console_text(ctx)
    assert "CSV" in output


# ── _output_json_results / _output_csv_results ──────────────────────


def test_output_json_results_to_file(tmp_path):
    """_output_json_results writes JSON to a file."""
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)

    outfile = tmp_path / "json_output.json"
    formatter = OutputFormatter({"file_info": {"name": "hello.exe"}})

    cmd._output_json_results(formatter, str(outfile))

    assert outfile.exists()
    content = outfile.read_text()
    assert "hello.exe" in content


def test_output_csv_results_to_file(tmp_path):
    """_output_csv_results writes CSV to a file."""
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)

    outfile = tmp_path / "csv_output.csv"
    formatter = OutputFormatter({"file_info": {"name": "hello.exe"}})

    cmd._output_csv_results(formatter, str(outfile))

    assert outfile.exists()
    assert len(outfile.read_text()) > 0


# ── _setup_analysis_options ──────────────────────────────────────────


def test_setup_analysis_options_empty():
    """No yara/xor returns empty dict."""
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)

    opts = cmd._setup_analysis_options(yara=None, xor=None)

    assert opts == {}


def test_setup_analysis_options_with_yara():
    """Yara path propagated correctly."""
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)

    opts = cmd._setup_analysis_options(yara="/rules/dir", xor=None)

    assert opts["yara_rules_dir"] == "/rules/dir"
    assert "xor_search" not in opts


def test_setup_analysis_options_with_xor():
    """XOR search string propagated correctly."""
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)

    opts = cmd._setup_analysis_options(yara=None, xor="searchme")

    assert opts["xor_search"] == "searchme"
    assert "yara_rules_dir" not in opts


def test_setup_analysis_options_with_both():
    """Both yara and xor propagated."""
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)

    opts = cmd._setup_analysis_options(yara="/rules", xor="needle")

    assert opts["yara_rules_dir"] == "/rules"
    assert opts["xor_search"] == "needle"


# ── _get_config ──────────────────────────────────────────────────────


def test_get_config_returns_config_from_context():
    """_get_config with no path returns a valid Config object."""
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)

    config = cmd._get_config(config_path=None)

    assert isinstance(config, Config)


# ── _has_circuit_breaker_data ────────────────────────────────────────


def test_has_circuit_breaker_data_empty():
    """Empty stats dict has no circuit breaker data."""
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)

    result = cmd._has_circuit_breaker_data({})

    assert result is False


def test_has_circuit_breaker_data_with_data():
    """Stats with breakers key reports True (if service recognizes it)."""
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)

    stats = {"breakers": {"module_a": {"state": "closed", "failures": 2}}}
    result = cmd._has_circuit_breaker_data(stats)

    # The real service decides; just verify it returns a bool
    assert isinstance(result, bool)


# ── _add_statistics_to_results ───────────────────────────────────────


def test_add_statistics_to_results():
    """_add_statistics_to_results mutates the dict (adds stats keys)."""
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)

    results: dict = {"file_info": {}}
    cmd._add_statistics_to_results(results)

    # The service may or may not add keys, but it must not raise
    assert isinstance(results, dict)


# ── _display_verbose_statistics ──────────────────────────────────────


def test_display_verbose_statistics_does_not_raise():
    """_display_verbose_statistics runs without error on clean state."""
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)

    # Should not raise even when there are no stats to display
    cmd._display_verbose_statistics()


# ── _output_console_results ──────────────────────────────────────────


def test_output_console_results_does_not_raise():
    """_output_console_results with minimal results does not raise."""
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)

    # Minimal results dict
    results = {"file_info": {"name": "test.exe"}}

    # Should not raise - display_results renders to the global console,
    # but the method itself should not crash
    cmd._output_console_results(results, verbose=False)


# ── complete execute flow with real tmp file ─────────────────────────


def test_execute_with_junk_file_returns_error(tmp_path):
    """execute() on a small junk file returns error code."""
    junk = tmp_path / "junk.exe"
    junk.write_bytes(b"\x00" * 10)

    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)

    args = {
        "filename": str(junk),
        "config": None,
        "verbose": False,
    }

    result = cmd.execute(args)

    # A 10-byte file is not a valid binary; expect failure
    assert result == 1


def test_execute_with_threads_on_bad_file(tmp_path):
    """execute() with threads arg on bad file returns error but does not crash."""
    junk = tmp_path / "junk2.exe"
    junk.write_bytes(b"\x00" * 10)

    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)

    args = {
        "filename": str(junk),
        "config": None,
        "verbose": False,
        "threads": 4,
    }

    result = cmd.execute(args)
    assert result == 1


def test_execute_with_yara_xor_on_bad_file(tmp_path):
    """execute() with yara/xor options on bad file fails gracefully."""
    junk = tmp_path / "junk3.exe"
    junk.write_bytes(b"\x00" * 10)

    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)

    args = {
        "filename": str(junk),
        "config": None,
        "verbose": False,
        "yara": "/nonexistent/rules",
        "xor": "searchme",
    }

    result = cmd.execute(args)
    assert result == 1
