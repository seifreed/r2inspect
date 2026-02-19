#!/usr/bin/env python3
"""Comprehensive tests for r2inspect/cli/display_base.py"""

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

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


def test_constants_defined():
    assert UNKNOWN_ERROR == "Unknown error"
    assert NOT_AVAILABLE == "Not Available"
    assert STATUS_AVAILABLE == "[green]✓ Available[/green]"
    assert STATUS_NOT_AVAILABLE == "[red]✗ Not Available[/red]"
    assert STATUS_NOT_AVAILABLE_SIMPLE == "[red]Not Available[/red]"


def test_stdout_proxy_write():
    proxy = _StdoutProxy()
    with patch("sys.stdout.write") as mock_write:
        mock_write.return_value = 5
        result = proxy.write("test")
        assert result == 5
        mock_write.assert_called_once_with("test")


def test_stdout_proxy_flush():
    proxy = _StdoutProxy()
    with patch("sys.stdout.flush") as mock_flush:
        proxy.flush()
        mock_flush.assert_called_once()


def test_stdout_proxy_isatty():
    proxy = _StdoutProxy()
    with patch("sys.stdout.isatty", return_value=True):
        assert proxy.isatty() is True
    with patch("sys.stdout.isatty", return_value=False):
        assert proxy.isatty() is False


def test_stdout_proxy_encoding():
    proxy = _StdoutProxy()
    with patch("sys.stdout", encoding="utf-8"):
        assert proxy.encoding == "utf-8"


def test_stdout_proxy_encoding_fallback():
    proxy = _StdoutProxy()

    class NoEncoding:
        pass

    with patch("sys.stdout", NoEncoding()):
        assert proxy.encoding == "utf-8"


def test_stdout_proxy_errors():
    proxy = _StdoutProxy()
    with patch("sys.stdout", errors="strict"):
        assert proxy.errors == "strict"


def test_stdout_proxy_errors_fallback():
    proxy = _StdoutProxy()

    class NoErrors:
        pass

    with patch("sys.stdout", NoErrors()):
        assert proxy.errors == "strict"


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


def test_create_info_table_defaults():
    table = create_info_table("Test Title")
    assert table.title == "Test Title"
    assert table.show_header is True
    assert table.expand is True


def test_create_info_table_custom_widths():
    table = create_info_table("Custom", prop_width=20, value_min_width=80)
    assert table.title == "Custom"


def test_create_info_table_columns():
    table = create_info_table("Columns Test")
    assert len(table.columns) == 2
    assert table.columns[0].header == "Property"
    assert table.columns[1].header == "Value"


def test_print_banner_with_pyfiglet():
    with patch("r2inspect.cli.display_base.pyfiglet") as mock_pyfiglet:
        mock_pyfiglet.figlet_format.return_value = "ASCII Art"
        with patch("r2inspect.cli.display_base._get_console") as mock_console:
            mock_console_obj = MagicMock()
            mock_console.return_value = mock_console_obj
            print_banner()
            assert mock_console_obj.print.call_count == 3
            mock_pyfiglet.figlet_format.assert_called_once_with("r2inspect", font="slant")


def test_print_banner_without_pyfiglet():
    with patch("r2inspect.cli.display_base.pyfiglet", None):
        with patch("r2inspect.cli.display_base._get_console") as mock_console:
            mock_console_obj = MagicMock()
            mock_console.return_value = mock_console_obj
            print_banner()
            assert mock_console_obj.print.call_count == 3


def test_print_banner_exception():
    with patch("r2inspect.cli.display_base.pyfiglet") as mock_pyfiglet:
        mock_pyfiglet.figlet_format.side_effect = Exception("Error")
        with patch("builtins.print") as mock_print:
            print_banner()
            assert mock_print.call_count == 3


def test_display_validation_errors_single():
    with patch("r2inspect.cli.display_base._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        display_validation_errors(["Error 1"])
        mock_console_obj.print.assert_called_once()


def test_display_validation_errors_multiple():
    with patch("r2inspect.cli.display_base._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        display_validation_errors(["Error 1", "Error 2", "Error 3"])
        assert mock_console_obj.print.call_count == 3


def test_display_validation_errors_empty():
    with patch("r2inspect.cli.display_base._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        display_validation_errors([])
        mock_console_obj.print.assert_not_called()


def test_display_yara_rules_table_single_rule():
    rules = [{"name": "rule1.yar", "size": 2048, "path": "/path/to/rule1.yar"}]
    with patch("r2inspect.cli.display_base._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        display_yara_rules_table(rules, "/rules")
        assert mock_console_obj.print.call_count == 3


def test_display_yara_rules_table_multiple_rules():
    rules = [
        {"name": "rule1.yar", "size": 1024, "path": "/path/to/rule1.yar"},
        {"name": "rule2.yar", "size": 4096, "path": "/path/to/rule2.yar", "relative_path": "rel/rule2.yar"},
    ]
    with patch("r2inspect.cli.display_base._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        display_yara_rules_table(rules, "/rules")
        assert mock_console_obj.print.call_count == 3


def test_display_yara_rules_table_with_relative_path():
    rules = [{"name": "rule.yar", "size": 512, "path": "/full/path", "relative_path": "relative/path"}]
    with patch("r2inspect.cli.display_base._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        display_yara_rules_table(rules, "/rules")
        mock_console_obj.print.assert_called()


def test_handle_list_yara_option_with_rules(tmp_path):
    config = {}
    yara_path = str(tmp_path / "yara")
    Path(yara_path).mkdir(parents=True, exist_ok=True)
    (Path(yara_path) / "test.yar").write_text("rule test { condition: true }")

    with patch("r2inspect.cli.display_base._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        handle_list_yara_option(config, yara_path)
        assert mock_console_obj.print.call_count >= 3


def test_handle_list_yara_option_no_rules(tmp_path):
    config = {}
    yara_path = str(tmp_path / "empty_yara")
    Path(yara_path).mkdir(parents=True, exist_ok=True)

    with patch("r2inspect.cli.display_base._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        handle_list_yara_option(config, yara_path)
        assert mock_console_obj.print.call_count == 2


def test_handle_list_yara_option_default_path():
    config = {}
    with patch("r2inspect.cli.display_base._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        handle_list_yara_option(config, None)
        mock_console_obj.print.assert_called()


def test_display_error_statistics_basic():
    error_stats = {
        "total_errors": 5,
        "recent_errors": 2,
        "recovery_strategies_available": 3,
        "errors_by_category": {},
        "errors_by_severity": {},
    }
    with patch("r2inspect.cli.display_base._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        display_error_statistics(error_stats)
        assert mock_console_obj.print.call_count >= 2


def test_display_error_statistics_with_categories():
    class ErrorCategory:
        def __init__(self, value):
            self.value = value

    error_stats = {
        "total_errors": 10,
        "recent_errors": 5,
        "recovery_strategies_available": 7,
        "errors_by_category": {ErrorCategory("network_error"): 3, ErrorCategory("file_error"): 2},
        "errors_by_severity": {},
    }
    with patch("r2inspect.cli.display_base._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        display_error_statistics(error_stats)
        assert mock_console_obj.print.call_count >= 3


def test_display_error_statistics_with_severities():
    error_stats = {
        "total_errors": 15,
        "recent_errors": 8,
        "recovery_strategies_available": 10,
        "errors_by_category": {},
        "errors_by_severity": {"critical": 2, "high": 5, "medium": 3, "low": 5},
    }
    with patch("r2inspect.cli.display_base._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        display_error_statistics(error_stats)
        assert mock_console_obj.print.call_count >= 3


def test_display_error_statistics_complete():
    class ErrorCategory:
        def __init__(self, value):
            self.value = value

    error_stats = {
        "total_errors": 20,
        "recent_errors": 10,
        "recovery_strategies_available": 15,
        "errors_by_category": {ErrorCategory("timeout"): 8, ErrorCategory("connection"): 7},
        "errors_by_severity": {"critical": 5, "high": 10, "low": 5},
    }
    with patch("r2inspect.cli.display_base._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        display_error_statistics(error_stats)
        assert mock_console_obj.print.call_count >= 4


def test_display_performance_statistics():
    retry_stats = {"total_retries": 10, "successful_retries": 8}
    circuit_stats = {"total_calls": 100, "successful_calls": 95}

    with patch("r2inspect.cli.display_base._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        with patch("r2inspect.cli.display_statistics._display_retry_statistics") as mock_retry:
            with patch("r2inspect.cli.display_statistics._display_circuit_breaker_statistics") as mock_circuit:
                display_performance_statistics(retry_stats, circuit_stats)
                mock_retry.assert_called_once_with(retry_stats)
                mock_circuit.assert_called_once_with(circuit_stats)
                assert mock_console_obj.print.call_count == 2


def test_display_results_complete():
    results = {
        "file_info": {"name": "test.exe", "size": 1024},
        "pe_info": {"machine": "x86"},
        "security": {"nx": True},
    }
    with patch("r2inspect.cli.display_sections._display_file_info") as mock_file:
        with patch("r2inspect.cli.display_sections._display_pe_info") as mock_pe:
            with patch("r2inspect.cli.display_sections._display_security") as mock_security:
                display_results(results)
                mock_file.assert_called_once()
                mock_pe.assert_called_once()
                mock_security.assert_called_once()


def test_display_results_normalized():
    results = {"file_info": {"name": "test.exe"}}
    with patch("r2inspect.cli.display_base.normalize_display_results") as mock_normalize:
        mock_normalize.return_value = results
        with patch("r2inspect.cli.display_sections._display_file_info"):
            display_results(results)
            mock_normalize.assert_called_once()


def test_display_results_all_sections():
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
    with patch("r2inspect.cli.display_sections._display_file_info"):
        with patch("r2inspect.cli.display_sections._display_pe_info"):
            with patch("r2inspect.cli.display_sections._display_security"):
                with patch("r2inspect.cli.display_sections._display_ssdeep"):
                    with patch("r2inspect.cli.display_sections._display_tlsh"):
                        with patch("r2inspect.cli.display_sections._display_telfhash"):
                            with patch("r2inspect.cli.display_sections._display_rich_header"):
                                with patch("r2inspect.cli.display_sections._display_impfuzzy"):
                                    with patch("r2inspect.cli.display_sections._display_ccbhash"):
                                        with patch("r2inspect.cli.display_sections._display_binlex"):
                                            with patch("r2inspect.cli.display_sections._display_binbloom"):
                                                with patch("r2inspect.cli.display_sections._display_simhash"):
                                                    with patch("r2inspect.cli.display_sections._display_bindiff"):
                                                        with patch("r2inspect.cli.display_sections._display_machoc_functions"):
                                                            with patch(
                                                                "r2inspect.cli.display_sections._display_indicators"
                                                            ):
                                                                display_results(results)


def test_display_results_empty():
    results = {}
    with patch("r2inspect.cli.display_sections._display_file_info") as mock_display:
        display_results(results)
        mock_display.assert_called_once()
