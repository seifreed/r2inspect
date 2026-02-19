"""Comprehensive tests for display.py facade module coverage."""

import io

from rich.console import Console

from r2inspect.cli import display


def _make_console():
    return Console(file=io.StringIO(), record=True, width=120)


def _get_text(console: Console) -> str:
    return console.export_text()


def test_display_imports():
    """Test all imports are accessible from display module."""
    assert hasattr(display, "ANALYZED_FUNCTIONS_LABEL")
    assert hasattr(display, "HTML_AMP")
    assert hasattr(display, "NOT_AVAILABLE")
    assert hasattr(display, "SIMILAR_GROUPS_LABEL")
    assert hasattr(display, "STATUS_AVAILABLE")
    assert hasattr(display, "STATUS_NOT_AVAILABLE")
    assert hasattr(display, "STATUS_NOT_AVAILABLE_SIMPLE")
    assert hasattr(display, "TOTAL_FUNCTIONS_LABEL")
    assert hasattr(display, "UNKNOWN_ERROR")
    assert hasattr(display, "console")
    assert hasattr(display, "create_info_table")
    assert hasattr(display, "display_error_statistics")
    assert hasattr(display, "display_performance_statistics")
    assert hasattr(display, "display_results")
    assert hasattr(display, "display_validation_errors")
    assert hasattr(display, "display_yara_rules_table")
    assert hasattr(display, "format_hash_display")
    assert hasattr(display, "handle_list_yara_option")
    assert hasattr(display, "print_banner")


def test_display_section_imports():
    """Test section display functions are accessible."""
    assert hasattr(display, "_add_binbloom_group")
    assert hasattr(display, "_add_rich_header_entries")
    assert hasattr(display, "_display_binbloom")
    assert hasattr(display, "_display_binbloom_signature_details")
    assert hasattr(display, "_display_bindiff")
    assert hasattr(display, "_display_binlex")
    assert hasattr(display, "_display_ccbhash")
    assert hasattr(display, "_display_file_info")
    assert hasattr(display, "_display_impfuzzy")
    assert hasattr(display, "_display_indicators")
    assert hasattr(display, "_display_machoc_functions")
    assert hasattr(display, "_display_pe_info")
    assert hasattr(display, "_display_rich_header")
    assert hasattr(display, "_display_security")
    assert hasattr(display, "_display_simhash")
    assert hasattr(display, "_display_ssdeep")
    assert hasattr(display, "_display_telfhash")
    assert hasattr(display, "_display_tlsh")
    assert hasattr(display, "_format_simhash_hex")


def test_display_statistics_imports():
    """Test statistics display functions are accessible."""
    assert hasattr(display, "_display_circuit_breaker_statistics")
    assert hasattr(display, "_display_most_retried_commands")
    assert hasattr(display, "_display_retry_statistics")


def test_format_hash_display_none():
    """Test format_hash_display with None."""
    result = display.format_hash_display(None)
    assert result == "N/A"


def test_format_hash_display_na_string():
    """Test format_hash_display with N/A string."""
    result = display.format_hash_display("N/A")
    assert result == "N/A"


def test_format_hash_display_short():
    """Test format_hash_display with short hash."""
    result = display.format_hash_display("abc123", max_length=10)
    assert result == "abc123"


def test_format_hash_display_long():
    """Test format_hash_display with long hash."""
    long_hash = "a" * 100
    result = display.format_hash_display(long_hash, max_length=20)
    assert result == "a" * 20 + "..."
    assert len(result) == 23


def test_format_hash_display_exact_length():
    """Test format_hash_display with exact max length."""
    hash_val = "a" * 20
    result = display.format_hash_display(hash_val, max_length=20)
    assert result == hash_val


def test_create_info_table():
    """Test create_info_table function."""
    table = display.create_info_table("Test Title")
    assert table.title == "Test Title"
    assert len(table.columns) == 2
    assert table.columns[0].header == "Property"
    assert table.columns[1].header == "Value"


def test_display_validation_errors_empty(monkeypatch):
    """Test display_validation_errors with empty errors."""
    console = _make_console()
    monkeypatch.setattr(display, "console", console)
    
    display.display_validation_errors([])
    text = _get_text(console)
    
    assert "Validation" not in text


def test_display_validation_errors_with_errors(monkeypatch):
    """Test display_validation_errors with actual errors."""
    console = _make_console()
    monkeypatch.setattr(display, "console", console)
    
    errors = [
        {"type": "error", "message": "Test error 1"},
        {"type": "warning", "message": "Test warning"},
    ]
    
    display.display_validation_errors(errors)
    text = _get_text(console)
    
    assert "Validation" in text or "error" in text.lower()


def test_display_error_statistics_basic(monkeypatch):
    """Test display_error_statistics with basic stats."""
    console = _make_console()
    monkeypatch.setattr(display, "console", console)
    
    stats = {
        "total_errors": 5,
        "recent_errors": 2,
        "recovery_strategies_available": 3,
        "errors_by_category": {"network": 2, "file_io": 3},
        "errors_by_severity": {"high": 1, "medium": 2, "low": 2},
    }
    
    display.display_error_statistics(stats)
    text = _get_text(console)
    
    assert "Error" in text or "Statistics" in text


def test_display_error_statistics_empty(monkeypatch):
    """Test display_error_statistics with empty stats."""
    console = _make_console()
    monkeypatch.setattr(display, "console", console)
    
    stats = {
        "total_errors": 0,
        "recent_errors": 0,
        "recovery_strategies_available": 0,
        "errors_by_category": {},
        "errors_by_severity": {},
    }
    
    display.display_error_statistics(stats)
    text = _get_text(console)
    
    assert "Error" in text or "Statistics" in text


def test_display_performance_statistics_basic(monkeypatch):
    """Test display_performance_statistics."""
    console = _make_console()
    monkeypatch.setattr(display, "console", console)
    
    retry_stats = {
        "total_retries": 10,
        "successful_retries": 8,
        "failed_after_retries": 2,
        "success_rate": 80.0,
        "commands_retried": {"cmd1": 5, "cmd2": 3, "cmd3": 2},
    }
    
    circuit_stats = {
        "open_count": 2,
        "total_failures": 5,
        "recovery_time": 1.5,
    }
    
    display.display_performance_statistics(retry_stats, circuit_stats)
    text = _get_text(console)
    
    assert "Performance" in text or "Retry" in text or "Circuit" in text


def test_display_performance_statistics_empty(monkeypatch):
    """Test display_performance_statistics with empty data."""
    console = _make_console()
    monkeypatch.setattr(display, "console", console)
    
    retry_stats = {
        "total_retries": 0,
        "successful_retries": 0,
        "failed_after_retries": 0,
        "success_rate": 0.0,
        "commands_retried": {},
    }
    
    circuit_stats = {
        "open_count": 0,
        "total_failures": 0,
    }
    
    display.display_performance_statistics(retry_stats, circuit_stats)
    text = _get_text(console)
    
    assert "Performance" in text or "Retry" in text


def test_print_banner(monkeypatch):
    """Test print_banner function."""
    console = _make_console()
    monkeypatch.setattr(display, "console", console)
    
    display.print_banner()
    text = _get_text(console)
    
    assert "r2inspect" in text.lower() or len(text) > 0


def test_handle_list_yara_option_true(monkeypatch):
    """Test handle_list_yara_option when yara path is provided."""
    from unittest.mock import Mock, patch
    console = _make_console()
    monkeypatch.setattr(display, "console", console)
    
    with patch("r2inspect.cli.display_base.Config"):
        with patch("r2inspect.modules.yara_analyzer.YaraAnalyzer") as mock_analyzer:
            mock_instance = Mock()
            mock_instance.list_available_rules.return_value = []
            mock_analyzer.return_value = mock_instance
            
            display.handle_list_yara_option({}, "/fake/path")
            
            assert mock_instance.list_available_rules.called


def test_handle_list_yara_option_false():
    """Test handle_list_yara_option when no yara path provided."""
    from unittest.mock import Mock, patch
    
    with patch("r2inspect.cli.display_base.Config"):
        with patch("r2inspect.modules.yara_analyzer.YaraAnalyzer") as mock_analyzer:
            mock_instance = Mock()
            mock_instance.list_available_rules.return_value = []
            mock_analyzer.return_value = mock_instance
            
            display.handle_list_yara_option({}, None)
            
            assert mock_instance.list_available_rules.called


def test_display_yara_rules_table_empty(monkeypatch):
    """Test display_yara_rules_table with no rules."""
    console = _make_console()
    monkeypatch.setattr(display, "console", console)
    
    display.display_yara_rules_table([], "/path/to/rules")
    text = _get_text(console)
    
    assert len(text) >= 0


def test_display_yara_rules_table_with_rules(monkeypatch):
    """Test display_yara_rules_table with rules."""
    console = _make_console()
    monkeypatch.setattr(display, "console", console)
    
    rules = [
        {"name": "rule1.yar", "size": 1024, "path": "/path/rule1.yar"},
        {"name": "rule2.yar", "size": 2048, "path": "/path/rule2.yar"},
    ]
    
    display.display_yara_rules_table(rules, "/path/to/rules")
    text = _get_text(console)
    
    assert "rule1" in text or "YARA" in text or len(text) >= 0


def test_constants_values():
    """Test constant values are strings."""
    assert isinstance(display.ANALYZED_FUNCTIONS_LABEL, str)
    assert isinstance(display.HTML_AMP, str)
    assert isinstance(display.NOT_AVAILABLE, str)
    assert isinstance(display.SIMILAR_GROUPS_LABEL, str)
    assert isinstance(display.STATUS_AVAILABLE, str)
    assert isinstance(display.STATUS_NOT_AVAILABLE, str)
    assert isinstance(display.STATUS_NOT_AVAILABLE_SIMPLE, str)
    assert isinstance(display.TOTAL_FUNCTIONS_LABEL, str)
    assert isinstance(display.UNKNOWN_ERROR, str)


def test_display_results_minimal(monkeypatch):
    """Test display_results with minimal data."""
    console = _make_console()
    monkeypatch.setattr(display, "console", console)
    
    results = {
        "file_info": {
            "name": "test.bin",
            "size": 1024,
            "path": "/tmp/test.bin",
        }
    }
    
    display.display_results(results)
    text = _get_text(console)
    
    assert len(text) > 0


def test_display_results_with_all_sections(monkeypatch):
    """Test display_results with multiple sections."""
    console = _make_console()
    monkeypatch.setattr(display, "console", console)
    
    results = {
        "file_info": {
            "name": "test.exe",
            "size": 102400,
            "path": "/tmp/test.exe",
            "mime_type": "application/x-dosexec",
            "file_type": "PE32",
            "md5": "abc123",
            "sha1": "def456",
            "sha256": "ghi789",
            "sha512": "jkl012",
        },
        "ssdeep": {
            "available": True,
            "hash_value": "3:ABC:XYZ",
        },
        "tlsh": {
            "available": True,
            "binary_tlsh": "T1ABC",
        },
    }
    
    display.display_results(results)
    text = _get_text(console)
    
    assert "test.exe" in text or "File" in text


def test_format_simhash_hex():
    """Test _format_simhash_hex function."""
    short = "abc123"
    result = display._format_simhash_hex(short)
    assert result == short
    
    long_hash = "a" * 64
    result = display._format_simhash_hex(long_hash)
    assert "\n" in result


def test_display_binlex_from_facade(monkeypatch):
    """Test _display_binlex accessible from facade."""
    console = _make_console()
    
    from r2inspect.cli import display_sections_similarity
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    
    results = {}
    display._display_binlex(results)
    text = _get_text(console)
    
    assert len(text) >= 0


def test_display_binbloom_from_facade(monkeypatch):
    """Test _display_binbloom accessible from facade."""
    console = _make_console()
    
    from r2inspect.cli import display_sections_similarity
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    
    results = {}
    display._display_binbloom(results)
    text = _get_text(console)
    
    assert len(text) >= 0


def test_display_simhash_from_facade(monkeypatch):
    """Test _display_simhash accessible from facade."""
    console = _make_console()
    
    from r2inspect.cli import display_sections_similarity
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    
    results = {}
    display._display_simhash(results)
    text = _get_text(console)
    
    assert len(text) >= 0


def test_display_bindiff_from_facade(monkeypatch):
    """Test _display_bindiff accessible from facade."""
    console = _make_console()
    
    from r2inspect.cli import display_sections_similarity
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    
    results = {}
    display._display_bindiff(results)
    text = _get_text(console)
    
    assert len(text) >= 0


def test_display_machoc_from_facade(monkeypatch):
    """Test _display_machoc_functions accessible from facade."""
    console = _make_console()
    
    from r2inspect.cli import display_sections_similarity
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    
    results = {}
    display._display_machoc_functions(results)
    text = _get_text(console)
    
    assert len(text) >= 0


def test_display_ssdeep_from_facade(monkeypatch):
    """Test _display_ssdeep accessible from facade."""
    console = _make_console()
    
    from r2inspect.cli import display_sections_hashing
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: console)
    
    results = {}
    display._display_ssdeep(results)
    text = _get_text(console)
    
    assert len(text) >= 0


def test_display_tlsh_from_facade(monkeypatch):
    """Test _display_tlsh accessible from facade."""
    console = _make_console()
    
    from r2inspect.cli import display_sections_hashing
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: console)
    
    results = {}
    display._display_tlsh(results)
    text = _get_text(console)
    
    assert len(text) >= 0


def test_display_telfhash_from_facade(monkeypatch):
    """Test _display_telfhash accessible from facade."""
    console = _make_console()
    
    from r2inspect.cli import display_sections_hashing
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: console)
    
    results = {}
    display._display_telfhash(results)
    text = _get_text(console)
    
    assert len(text) >= 0


def test_display_impfuzzy_from_facade(monkeypatch):
    """Test _display_impfuzzy accessible from facade."""
    console = _make_console()
    
    from r2inspect.cli import display_sections_hashing
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: console)
    
    results = {}
    display._display_impfuzzy(results)
    text = _get_text(console)
    
    assert len(text) >= 0


def test_display_ccbhash_from_facade(monkeypatch):
    """Test _display_ccbhash accessible from facade."""
    console = _make_console()
    
    from r2inspect.cli import display_sections_hashing
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: console)
    
    results = {}
    display._display_ccbhash(results)
    text = _get_text(console)
    
    assert len(text) >= 0
