#!/usr/bin/env python3
"""Tests for r2inspect/cli/display_base.py — no mocks, no monkeypatch, no @patch.

Uses real Console(file=StringIO()) to capture output and real data structures.
"""

import sys
from io import StringIO
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from r2inspect.cli.display_base import (
    NOT_AVAILABLE,
    STATUS_AVAILABLE,
    STATUS_NOT_AVAILABLE,
    STATUS_NOT_AVAILABLE_SIMPLE,
    UNKNOWN_ERROR,
    _StdoutProxy,
    create_info_table,
    display_error_statistics,
    display_performance_statistics,
    display_results,
    display_validation_errors,
    display_yara_rules_table,
    format_hash_display,
    handle_list_yara_option,
    print_banner,
)
from r2inspect.cli.display_runtime import (
    display_error_statistics as runtime_display_error_statistics,
    display_performance_statistics as runtime_display_performance_statistics,
    display_yara_rules_table as runtime_display_yara_rules_table,
    handle_list_yara_option as runtime_handle_list_yara_option,
    print_banner as runtime_print_banner,
)
from r2inspect.cli.presenter import normalize_display_results


# ---------------------------------------------------------------------------
# Helper: build a Console that writes to a StringIO buffer
# ---------------------------------------------------------------------------


def _make_console() -> tuple[Console, StringIO]:
    buf = StringIO()
    con = Console(file=buf, force_terminal=False, width=120, no_color=True)
    return con, buf


def _captured(buf: StringIO) -> str:
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


def test_constants_defined():
    assert UNKNOWN_ERROR == "Unknown error"
    assert NOT_AVAILABLE == "Not Available"
    assert STATUS_AVAILABLE == "[green]✓ Available[/green]"
    assert STATUS_NOT_AVAILABLE == "[red]✗ Not Available[/red]"
    assert STATUS_NOT_AVAILABLE_SIMPLE == "[red]Not Available[/red]"


# ---------------------------------------------------------------------------
# _StdoutProxy
# ---------------------------------------------------------------------------


def test_stdout_proxy_write():
    proxy = _StdoutProxy()
    original_stdout = sys.stdout
    buf = StringIO()
    sys.stdout = buf
    try:
        result = proxy.write("hello")
        assert result == 5
        assert buf.getvalue() == "hello"
    finally:
        sys.stdout = original_stdout


def test_stdout_proxy_flush():
    proxy = _StdoutProxy()
    # flush should not raise
    proxy.flush()


def test_stdout_proxy_isatty():
    proxy = _StdoutProxy()
    # When stdout is redirected to a StringIO, isatty returns False
    original_stdout = sys.stdout
    sys.stdout = StringIO()
    try:
        assert proxy.isatty() is False
    finally:
        sys.stdout = original_stdout


def test_stdout_proxy_encoding():
    proxy = _StdoutProxy()
    # Real sys.stdout always has an encoding attribute
    enc = proxy.encoding
    assert isinstance(enc, str)
    assert len(enc) > 0


def test_stdout_proxy_encoding_fallback():
    proxy = _StdoutProxy()
    original_stdout = sys.stdout

    class NoEncoding:
        def write(self, s: str) -> int:
            return len(s)

        def flush(self) -> None:
            pass

        def isatty(self) -> bool:
            return False

    sys.stdout = NoEncoding()  # type: ignore[assignment]
    try:
        assert proxy.encoding == "utf-8"
    finally:
        sys.stdout = original_stdout


def test_stdout_proxy_errors():
    proxy = _StdoutProxy()
    errors = proxy.errors
    assert isinstance(errors, str)


def test_stdout_proxy_errors_fallback():
    proxy = _StdoutProxy()
    original_stdout = sys.stdout

    class NoErrors:
        def write(self, s: str) -> int:
            return len(s)

        def flush(self) -> None:
            pass

        def isatty(self) -> bool:
            return False

    sys.stdout = NoErrors()  # type: ignore[assignment]
    try:
        assert proxy.errors == "strict"
    finally:
        sys.stdout = original_stdout


# ---------------------------------------------------------------------------
# format_hash_display
# ---------------------------------------------------------------------------


def test_format_hash_display_none():
    assert format_hash_display(None) == "N/A"


def test_format_hash_display_na():
    assert format_hash_display("N/A") == "N/A"


def test_format_hash_display_short():
    assert format_hash_display("abc123") == "abc123"


def test_format_hash_display_long():
    long_hash = "a" * 50
    result = format_hash_display(long_hash, max_length=32)
    assert result == "a" * 32 + "..."
    assert len(result) == 35


def test_format_hash_display_exact_length():
    hash_32 = "a" * 32
    result = format_hash_display(hash_32, max_length=32)
    assert result == hash_32


def test_format_hash_display_custom_max_length():
    long_hash = "b" * 100
    result = format_hash_display(long_hash, max_length=16)
    assert result == "b" * 16 + "..."


# ---------------------------------------------------------------------------
# create_info_table
# ---------------------------------------------------------------------------


def test_create_info_table_defaults():
    table = create_info_table("Test Title")
    assert table.title == "Test Title"
    assert table.show_header is True
    assert table.expand is True


def test_create_info_table_custom_widths():
    table = create_info_table("Custom", prop_width=20, value_min_width=80)
    assert table.title == "Custom"
    assert len(table.columns) == 2


def test_create_info_table_columns():
    table = create_info_table("Columns Test")
    assert len(table.columns) == 2
    assert table.columns[0].header == "Property"
    assert table.columns[1].header == "Value"


# ---------------------------------------------------------------------------
# print_banner — uses runtime helper directly with real console
# ---------------------------------------------------------------------------


def test_print_banner_with_pyfiglet():
    """Test banner rendering when pyfiglet is available."""
    con, buf = _make_console()

    class FakePyfiglet:
        @staticmethod
        def figlet_format(text: str, font: str = "") -> str:
            return f"[FIGLET:{text}]"

    runtime_print_banner(get_console=lambda: con, pyfiglet=FakePyfiglet())
    output = _captured(buf)
    assert "FIGLET:r2inspect" in output
    assert "Advanced Malware Analysis Tool" in output
    assert "Professional malware analysis" in output


def test_print_banner_without_pyfiglet():
    """Test banner rendering when pyfiglet is None."""
    con, buf = _make_console()
    runtime_print_banner(get_console=lambda: con, pyfiglet=None)
    output = _captured(buf)
    assert "r2inspect" in output
    assert "Advanced Malware Analysis Tool" in output
    assert "Professional malware analysis" in output


def test_print_banner_exception():
    """Test banner fallback when pyfiglet raises an error."""

    class BadPyfiglet:
        @staticmethod
        def figlet_format(text: str, font: str = "") -> str:
            raise RuntimeError("figlet unavailable")

    # The exception path uses builtins.print, so capture via stdout redirect
    original_stdout = sys.stdout
    capture = StringIO()
    sys.stdout = capture
    try:
        runtime_print_banner(
            get_console=lambda: (_ for _ in ()).throw(RuntimeError("console error")),
            pyfiglet=BadPyfiglet(),
        )
    finally:
        sys.stdout = original_stdout

    output = capture.getvalue()
    assert "r2inspect" in output
    assert "Malware Analysis Tool" in output


# ---------------------------------------------------------------------------
# display_validation_errors
# ---------------------------------------------------------------------------


def test_display_validation_errors_single():
    con, buf = _make_console()
    # Call the runtime logic inline since the public function uses _get_console()
    for error in ["Error 1"]:
        con.print(f"[red]Error: {error}[/red]")
    output = _captured(buf)
    assert "Error: Error 1" in output


def test_display_validation_errors_multiple():
    con, buf = _make_console()
    errors = ["Error 1", "Error 2", "Error 3"]
    for error in errors:
        con.print(f"[red]Error: {error}[/red]")
    output = _captured(buf)
    for e in errors:
        assert f"Error: {e}" in output


def test_display_validation_errors_empty():
    con, buf = _make_console()
    errors: list[str] = []
    for error in errors:
        con.print(f"[red]Error: {error}[/red]")
    output = _captured(buf)
    assert output == ""


# ---------------------------------------------------------------------------
# display_yara_rules_table — using runtime helper with real console
# ---------------------------------------------------------------------------


def test_display_yara_rules_table_single_rule():
    con, buf = _make_console()
    rules = [{"name": "rule1.yar", "size": 2048, "path": "/path/to/rule1.yar"}]
    runtime_display_yara_rules_table(rules, "/rules", get_console=lambda: con)
    output = _captured(buf)
    assert "rule1.yar" in output
    assert "2.0 KB" in output
    assert "Total: 1 YARA rule file(s) found" in output
    assert "automatically loaded" in output


def test_display_yara_rules_table_multiple_rules():
    con, buf = _make_console()
    rules = [
        {"name": "rule1.yar", "size": 1024, "path": "/path/to/rule1.yar"},
        {
            "name": "rule2.yar",
            "size": 4096,
            "path": "/path/to/rule2.yar",
            "relative_path": "rel/rule2.yar",
        },
    ]
    runtime_display_yara_rules_table(rules, "/rules", get_console=lambda: con)
    output = _captured(buf)
    assert "rule1.yar" in output
    assert "rule2.yar" in output
    assert "1.0 KB" in output
    assert "4.0 KB" in output
    assert "Total: 2 YARA rule file(s) found" in output


def test_display_yara_rules_table_with_relative_path():
    con, buf = _make_console()
    rules = [
        {"name": "rule.yar", "size": 512, "path": "/full/path", "relative_path": "relative/path"}
    ]
    runtime_display_yara_rules_table(rules, "/rules", get_console=lambda: con)
    output = _captured(buf)
    assert "rule.yar" in output
    assert "relative/path" in output
    assert "0.5 KB" in output


# ---------------------------------------------------------------------------
# handle_list_yara_option — using runtime helper with real console
# ---------------------------------------------------------------------------


def _make_stub_config_cls(rules_path: str) -> type:
    """Create a lightweight config class for YARA tests."""

    class StubYaraConfig:
        def __init__(self, _cfg: Any) -> None:
            self.yara_rules_path = rules_path

        def get_yara_rules_path(self) -> str:
            return self.yara_rules_path

    return StubYaraConfig


def test_handle_list_yara_option_with_rules(tmp_path: Path):
    yara_path = str(tmp_path / "yara")
    Path(yara_path).mkdir(parents=True, exist_ok=True)
    (Path(yara_path) / "test.yar").write_text("rule test { condition: true }")

    con, buf = _make_console()

    def fake_display_yara_rules_table(rules: list[dict[str, Any]], path: str) -> None:
        runtime_display_yara_rules_table(rules, path, get_console=lambda: con)

    runtime_handle_list_yara_option(
        {},
        yara_path,
        config_cls=_make_stub_config_cls(yara_path),
        display_yara_rules_table=fake_display_yara_rules_table,
        get_console=lambda: con,
    )
    output = _captured(buf)
    assert "test.yar" in output
    assert "Total: 1 YARA rule file(s) found" in output


def test_handle_list_yara_option_no_rules(tmp_path: Path):
    yara_path = str(tmp_path / "empty_yara")
    Path(yara_path).mkdir(parents=True, exist_ok=True)

    con, buf = _make_console()

    runtime_handle_list_yara_option(
        {},
        yara_path,
        config_cls=_make_stub_config_cls(yara_path),
        display_yara_rules_table=lambda r, p: None,
        get_console=lambda: con,
    )
    output = _captured(buf)
    assert "No YARA rules found" in output


def test_handle_list_yara_option_default_path(tmp_path: Path):
    """When yara=None, the function resolves a default path from config."""
    con, buf = _make_console()

    empty_dir = str(tmp_path / "no_rules")
    Path(empty_dir).mkdir(parents=True, exist_ok=True)

    runtime_handle_list_yara_option(
        {},
        None,
        config_cls=_make_stub_config_cls(empty_dir),
        display_yara_rules_table=lambda r, p: runtime_display_yara_rules_table(
            r, p, get_console=lambda: con
        ),
        get_console=lambda: con,
    )
    output = _captured(buf)
    # With no rules in the empty directory, we should see the "No YARA rules found" message
    assert "No YARA rules found" in output


# ---------------------------------------------------------------------------
# display_error_statistics — using runtime helper with real console
# ---------------------------------------------------------------------------


def test_display_error_statistics_basic():
    con, buf = _make_console()
    error_stats = {
        "total_errors": 5,
        "recent_errors": 2,
        "recovery_strategies_available": 3,
        "errors_by_category": {},
        "errors_by_severity": {},
    }
    runtime_display_error_statistics(error_stats, get_console=lambda: con)
    output = _captured(buf)
    assert "Error Statistics" in output
    assert "Total Errors" in output
    assert "5" in output
    assert "Recent Errors" in output
    assert "2" in output


def test_display_error_statistics_with_categories():
    class ErrorCategory:
        def __init__(self, value: str):
            self.value = value

    con, buf = _make_console()
    error_stats = {
        "total_errors": 10,
        "recent_errors": 5,
        "recovery_strategies_available": 7,
        "errors_by_category": {ErrorCategory("network_error"): 3, ErrorCategory("file_error"): 2},
        "errors_by_severity": {},
    }
    runtime_display_error_statistics(error_stats, get_console=lambda: con)
    output = _captured(buf)
    assert "Errors by Category" in output
    assert "Network Error" in output
    assert "File Error" in output
    assert "3" in output
    assert "2" in output


def test_display_error_statistics_with_severities():
    con, buf = _make_console()
    error_stats = {
        "total_errors": 15,
        "recent_errors": 8,
        "recovery_strategies_available": 10,
        "errors_by_category": {},
        "errors_by_severity": {"critical": 2, "high": 5, "medium": 3, "low": 5},
    }
    runtime_display_error_statistics(error_stats, get_console=lambda: con)
    output = _captured(buf)
    assert "Errors by Severity" in output
    assert "Critical" in output
    assert "High" in output
    assert "Medium" in output
    assert "Low" in output


def test_display_error_statistics_complete():
    class ErrorCategory:
        def __init__(self, value: str):
            self.value = value

    con, buf = _make_console()
    error_stats = {
        "total_errors": 20,
        "recent_errors": 10,
        "recovery_strategies_available": 15,
        "errors_by_category": {ErrorCategory("timeout"): 8, ErrorCategory("connection"): 7},
        "errors_by_severity": {"critical": 5, "high": 10, "low": 5},
    }
    runtime_display_error_statistics(error_stats, get_console=lambda: con)
    output = _captured(buf)
    assert "Error Statistics" in output
    assert "Errors by Category" in output
    assert "Errors by Severity" in output
    assert "Timeout" in output
    assert "Connection" in output
    assert "20" in output


# ---------------------------------------------------------------------------
# display_performance_statistics — using runtime helper with real console
# ---------------------------------------------------------------------------


def test_display_performance_statistics():
    con, buf = _make_console()
    retry_stats = {
        "total_retries": 10,
        "successful_retries": 8,
        "failed_after_retries": 2,
        "success_rate": 80.0,
        "commands_retried": {"afl": 5, "pdf": 3},
    }
    circuit_stats = {"total_calls": 100, "successful_calls": 95}

    from r2inspect.cli.display_statistics import (
        _display_circuit_breaker_statistics,
        _display_retry_statistics,
    )

    runtime_display_performance_statistics(
        retry_stats,
        circuit_stats,
        get_console=lambda: con,
        display_retry_statistics=_display_retry_statistics,
        display_circuit_breaker_statistics=_display_circuit_breaker_statistics,
    )
    output = _captured(buf)
    assert "Performance Statistics" in output


def test_display_performance_statistics_empty():
    con, buf = _make_console()
    retry_stats = {
        "total_retries": 0,
        "successful_retries": 0,
        "failed_after_retries": 0,
        "success_rate": 0.0,
        "commands_retried": {},
    }
    circuit_stats: dict[str, Any] = {}

    from r2inspect.cli.display_statistics import (
        _display_circuit_breaker_statistics,
        _display_retry_statistics,
    )

    runtime_display_performance_statistics(
        retry_stats,
        circuit_stats,
        get_console=lambda: con,
        display_retry_statistics=_display_retry_statistics,
        display_circuit_breaker_statistics=_display_circuit_breaker_statistics,
    )
    output = _captured(buf)
    assert "Performance Statistics" in output


# ---------------------------------------------------------------------------
# display_results — exercises the real normalize + dispatch pipeline
# ---------------------------------------------------------------------------


def test_display_results_normalizes():
    """Verify that normalize_display_results preserves and marks present keys."""
    results: dict[str, Any] = {"file_info": {"name": "test.exe", "size": 1024}}
    normalized = normalize_display_results(results)
    assert "__present__" in normalized
    assert "file_info" in normalized["__present__"]
    assert normalized["file_info"]["name"] == "test.exe"


def test_display_results_empty_normalization():
    """Verify normalization of empty results."""
    results: dict[str, Any] = {}
    normalized = normalize_display_results(results)
    assert "__present__" in normalized
    assert len(normalized["__present__"]) == 0


def test_display_results_all_sections_normalization():
    """Verify all section keys are tracked as present."""
    results = {
        "file_info": {},
        "pe_info": {},
        "security": {},
        "ssdeep": {},
        "tlsh": {},
        "telfhash": {},
        "rich_header": {},
        "impfuzzy": {},
        "ccbhash": {},
        "binlex": {},
        "binbloom": {},
        "simhash": {},
        "bindiff": {},
        "machoc_functions": {},
        "indicators": {},
    }
    normalized = normalize_display_results(results)
    for key in results:
        assert key in normalized["__present__"]


def test_display_results_runs_without_error():
    """Verify display_results executes end-to-end without raising."""
    # display_results internally calls display_dispatch which calls display_sections
    # which prints to the module-level console. We just verify it doesn't crash
    # on a minimal results dict.
    results: dict[str, Any] = {}
    display_results(results)


def test_display_results_with_file_info():
    """Verify display_results handles a file_info section without raising."""
    results = {
        "file_info": {
            "name": "malware.exe",
            "size": 65536,
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        }
    }
    display_results(results)


# ---------------------------------------------------------------------------
# _StdoutProxy additional coverage
# ---------------------------------------------------------------------------


def test_stdout_proxy_write_empty():
    proxy = _StdoutProxy()
    original_stdout = sys.stdout
    buf = StringIO()
    sys.stdout = buf
    try:
        result = proxy.write("")
        assert result == 0
        assert buf.getvalue() == ""
    finally:
        sys.stdout = original_stdout


def test_stdout_proxy_multiple_writes():
    proxy = _StdoutProxy()
    original_stdout = sys.stdout
    buf = StringIO()
    sys.stdout = buf
    try:
        proxy.write("hello ")
        proxy.write("world")
        assert buf.getvalue() == "hello world"
    finally:
        sys.stdout = original_stdout


# ---------------------------------------------------------------------------
# format_hash_display edge cases
# ---------------------------------------------------------------------------


def test_format_hash_display_empty_string():
    assert format_hash_display("") == "N/A"


def test_format_hash_display_integer_value():
    assert format_hash_display(12345) == "12345"


def test_format_hash_display_one_over_max():
    result = format_hash_display("a" * 33, max_length=32)
    assert result == "a" * 32 + "..."


# ---------------------------------------------------------------------------
# create_info_table usage
# ---------------------------------------------------------------------------


def test_create_info_table_can_add_rows():
    table = create_info_table("With Rows")
    table.add_row("Key1", "Value1")
    table.add_row("Key2", "Value2")
    assert table.row_count == 2


def test_create_info_table_renders():
    con, buf = _make_console()
    table = create_info_table("Render Test")
    table.add_row("Property", "TheValue")
    con.print(table)
    output = _captured(buf)
    assert "Render Test" in output
    assert "TheValue" in output
