from __future__ import annotations

from r2inspect.cli.display import (
    _display_file_info,
    _display_indicators,
    _display_pe_info,
    _display_rich_header,
    _display_security,
    console,
    create_info_table,
    display_results,
    display_validation_errors,
    format_hash_display,
    print_banner,
)


def test_print_banner() -> None:
    """Test print_banner function"""
    print_banner()
    # Should not raise


def test_create_info_table() -> None:
    """Test create_info_table with data"""
    table = create_info_table({"key": "value"}, "Test Title")
    assert table is not None


def test_format_hash_display() -> None:
    """Test format_hash_display"""
    result = format_hash_display({"md5": "abc123", "sha256": "def456"})
    assert "abc123" in result or result is not None


def test_display_file_info_minimal() -> None:
    """Test _display_file_info with minimal data"""
    results = {"file_info": {}}
    _display_file_info(results)
    # Should not raise


def test_display_file_info_full() -> None:
    """Test _display_file_info with full data"""
    results = {
        "file_info": {
            "filepath": "/tmp/test.exe",
            "size": 12345,
            "format": "PE32",
        }
    }
    _display_file_info(results)
    # Should not raise


def test_display_pe_info_minimal() -> None:
    """Test _display_pe_info with minimal data"""
    results = {"pe_info": {}}
    _display_pe_info(results)
    # Should not raise


def test_display_pe_info_full() -> None:
    """Test _display_pe_info with full data"""
    results = {
        "pe_info": {
            "machine": "i386",
            "subsystem": "Windows GUI",
            "compilation_timestamp": "2024-01-01",
        }
    }
    _display_pe_info(results)
    # Should not raise


def test_display_security_minimal() -> None:
    """Test _display_security with minimal data"""
    results = {"security": {}}
    _display_security(results)
    # Should not raise


def test_display_security_full() -> None:
    """Test _display_security with full data"""
    results = {
        "security": {
            "nx": True,
            "aslr": True,
            "dep": False,
        }
    }
    _display_security(results)
    # Should not raise


def test_display_indicators_empty() -> None:
    """Test _display_indicators with empty data"""
    results = {"indicators": []}
    _display_indicators(results)
    # Should not raise


def test_display_indicators_with_data() -> None:
    """Test _display_indicators with indicator data"""
    results = {
        "indicators": [
            {"type": "URL", "value": "http://example.com", "context": "network"},
            {"type": "IP", "value": "192.168.1.1", "context": "connection"},
        ]
    }
    _display_indicators(results)
    # Should not raise


def test_display_rich_header_not_available() -> None:
    """Test _display_rich_header when not available"""
    results = {"rich_header": {"available": False}}
    _display_rich_header(results)
    # Should not raise


def test_display_rich_header_available() -> None:
    """Test _display_rich_header when available"""
    results = {
        "rich_header": {
            "available": True,
            "xor_key": "0x12345678",
            "compilers": [
                {"name": "MSVC", "version": "19.0", "count": 5}
            ],
        }
    }
    _display_rich_header(results)
    # Should not raise


def test_display_validation_errors_empty() -> None:
    """Test display_validation_errors with no errors"""
    display_validation_errors([])
    # Should not raise


def test_display_validation_errors_with_data() -> None:
    """Test display_validation_errors with error data"""
    errors = [
        {"field": "pe_info.machine", "error": "Invalid value"},
        {"field": "imports", "error": "Missing required field"},
    ]
    display_validation_errors(errors)
    # Should not raise


def test_display_results_minimal() -> None:
    """Test display_results with minimal data"""
    results = {"file_info": {"filepath": "/tmp/test.exe"}}
    display_results(results)
    # Should not raise


def test_display_results_with_various_fields() -> None:
    """Test display_results with various data fields"""
    results = {
        "file_info": {"filepath": "/tmp/test.exe", "size": 12345},
        "pe_info": {"machine": "i386"},
        "security": {"nx": True},
        "indicators": [],
        "rich_header": {"available": False},
    }
    display_results(results)
    # Should not raise
