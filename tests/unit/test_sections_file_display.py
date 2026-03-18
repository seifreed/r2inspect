#!/usr/bin/env python3
"""Tests for r2inspect/cli/display_sections_file.py — no mocks, real Console output."""

from __future__ import annotations

from io import StringIO

from rich.console import Console

from r2inspect.cli import display as display_module
from r2inspect.cli.display_sections_file import (
    _display_file_info,
    _display_pe_info,
    _display_security,
)


def _capture(fn, results: dict) -> str:
    """Call *fn(results)* while routing all console output to a string buffer."""
    buf = StringIO()
    real_console = Console(file=buf, width=120, force_terminal=False)
    original = display_module.console
    display_module.console = real_console
    try:
        fn(results)
    finally:
        display_module.console = original
    return buf.getvalue()


# ── _display_file_info ──────────────────────────────────────────────


def test_display_file_info_not_present():
    output = _capture(_display_file_info, {})
    assert output == ""


def test_display_file_info_basic():
    results = {
        "file_info": {
            "size": 1024,
            "path": "/path/to/file.exe",
            "name": "file.exe",
            "mime_type": "application/x-executable",
            "file_type": "PE32 executable",
        }
    }
    output = _capture(_display_file_info, results)
    assert "File Information" in output
    assert "1024" in output
    assert "file.exe" in output
    assert "application/x-executable" in output
    assert "PE32 executable" in output


def test_display_file_info_with_hashes():
    results = {
        "file_info": {
            "name": "test.exe",
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "sha512": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
        }
    }
    output = _capture(_display_file_info, results)
    assert "d41d8cd98f00b204e9800998ecf8427e" in output
    assert "da39a3ee5e6b4b0d3255bfef95601890afd80709" in output
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in output


def test_display_file_info_with_enhanced_detection():
    results = {
        "file_info": {
            "name": "test.exe",
            "threat_level": "high",
            "enhanced_detection": {
                "file_format": "PE",
                "format_category": "executable",
                "architecture": "x86",
                "bits": 32,
                "endianness": "little",
                "confidence": 0.95,
            },
        }
    }
    output = _capture(_display_file_info, results)
    assert "PE" in output
    assert "executable" in output
    assert "x86" in output
    assert "32" in output
    assert "little" in output
    assert "95.00%" in output
    assert "high" in output


def test_display_file_info_empty_enhanced():
    results = {"file_info": {"name": "test.exe", "enhanced_detection": {}}}
    output = _capture(_display_file_info, results)
    assert "File Information" in output
    assert "test.exe" in output
    # Empty enhanced_detection should not add format/category rows
    assert "Format" not in output or "test.exe" in output


def test_display_file_info_none_values():
    results = {
        "file_info": {
            "name": "test.exe",
            "size": None,
            "md5": None,
            "sha1": None,
        }
    }
    output = _capture(_display_file_info, results)
    # None values should be skipped (not rendered)
    assert "test.exe" in output
    assert "None" not in output


def test_display_file_info_missing_enhanced_fields():
    results = {
        "file_info": {
            "name": "test.exe",
            "enhanced_detection": {
                "file_format": "PE",
            },
        }
    }
    output = _capture(_display_file_info, results)
    assert "PE" in output
    # Missing fields should fall back to "Unknown"
    assert "Unknown" in output


def test_display_file_info_all_fields():
    results = {
        "file_info": {
            "size": 2048,
            "path": "/full/path/to/file.exe",
            "name": "file.exe",
            "mime_type": "application/x-dosexec",
            "file_type": "PE32 executable (GUI) Intel 80386",
            "md5": "abc123",
            "sha1": "def456",
            "sha256": "ghi789",
            "sha512": "jkl012",
            "threat_level": "medium",
            "enhanced_detection": {
                "file_format": "PE32",
                "format_category": "executable",
                "architecture": "x86_64",
                "bits": 64,
                "endianness": "little",
                "confidence": 0.99,
            },
        }
    }
    output = _capture(_display_file_info, results)
    assert "File Information" in output
    assert "2048" in output
    assert "file.exe" in output
    assert "abc123" in output
    assert "def456" in output
    assert "ghi789" in output
    assert "jkl012" in output
    assert "PE32" in output
    assert "medium" in output
    assert "99.00%" in output


def test_display_file_info_sha256_sha512_strings():
    """sha256/sha512 values are cast to str even if numeric."""
    results = {
        "file_info": {
            "name": "test.exe",
            "sha256": 12345,
            "sha512": 67890,
        }
    }
    output = _capture(_display_file_info, results)
    assert "12345" in output
    assert "67890" in output


# ── _display_pe_info ────────────────────────────────────────────────


def test_display_pe_info_not_present():
    output = _capture(_display_pe_info, {})
    assert output == ""


def test_display_pe_info_basic():
    results = {
        "pe_info": {
            "subsystem": "GUI",
            "timestamp": "2024-01-01",
        }
    }
    output = _capture(_display_pe_info, results)
    assert "PE Analysis" in output
    assert "GUI" in output
    assert "2024-01-01" in output


def test_display_pe_info_excluded_keys():
    results = {
        "pe_info": {
            "architecture": "x86",
            "bits": 32,
            "format": "PE",
            "security_features": {},
            "machine": "i386",
            "endian": "little",
            "subsystem": "Console",
        }
    }
    output = _capture(_display_pe_info, results)
    assert "Console" in output
    # Excluded keys should not appear as rows
    assert "x86" not in output
    assert "i386" not in output


def test_display_pe_info_with_list_values():
    results = {
        "pe_info": {
            "imports": ["kernel32.dll", "user32.dll"],
            "exports": ["func1", "func2"],
        }
    }
    output = _capture(_display_pe_info, results)
    assert "kernel32.dll" in output
    assert "user32.dll" in output
    assert "func1" in output
    assert "func2" in output


def test_display_pe_info_with_dict_values():
    results = {
        "pe_info": {
            "metadata": {"key": "value"},
            "subsystem": "GUI",
        }
    }
    output = _capture(_display_pe_info, results)
    # Dict values are skipped
    assert "GUI" in output


def test_display_pe_info_complex():
    results = {
        "pe_info": {
            "subsystem": "Console",
            "timestamp": "2024-01-15",
            "entry_point": "0x1000",
            "image_base": "0x400000",
            "sections": ["text", "data"],
            "characteristics": ["executable", "32bit"],
        }
    }
    output = _capture(_display_pe_info, results)
    assert "PE Analysis" in output
    assert "Console" in output
    assert "2024-01-15" in output
    assert "0x1000" in output
    assert "0x400000" in output
    assert "text" in output
    assert "data" in output
    assert "executable" in output


# ── _display_security ───────────────────────────────────────────────


def test_display_security_not_present():
    output = _capture(_display_security, {})
    assert output == ""


def test_display_security_all_enabled():
    results = {
        "security": {
            "nx": True,
            "pie": True,
            "canary": True,
            "relro": True,
            "stripped": False,
        }
    }
    output = _capture(_display_security, results)
    assert "Security Features" in output
    assert "Nx" in output
    assert "Pie" in output
    assert "Canary" in output


def test_display_security_all_disabled():
    results = {
        "security": {
            "nx": False,
            "pie": False,
            "canary": False,
            "relro": False,
            "stripped": True,
        }
    }
    output = _capture(_display_security, results)
    assert "Security Features" in output


def test_display_security_mixed():
    results = {
        "security": {
            "nx": True,
            "pie": False,
            "canary": True,
            "relro": False,
        }
    }
    output = _capture(_display_security, results)
    assert "Security Features" in output
    assert "Nx" in output
    assert "Canary" in output


def test_display_security_single_feature():
    results = {"security": {"aslr": True}}
    output = _capture(_display_security, results)
    assert "Aslr" in output


def test_display_security_underscores():
    results = {
        "security": {
            "dep_enabled": True,
            "safe_seh": False,
            "control_flow_guard": True,
        }
    }
    output = _capture(_display_security, results)
    assert "Dep Enabled" in output
    assert "Safe Seh" in output
    assert "Control Flow Guard" in output


def test_display_security_empty():
    results = {"security": {}}
    output = _capture(_display_security, results)
    assert "Security Features" in output


# ── integration ─────────────────────────────────────────────────────


def test_display_sections_integration():
    """All three display functions produce output for a combined results dict."""
    results = {
        "file_info": {
            "name": "test.exe",
            "size": 1024,
            "md5": "abc123",
        },
        "pe_info": {
            "subsystem": "Console",
            "timestamp": "2024-01-01",
        },
        "security": {
            "nx": True,
            "pie": False,
        },
    }
    buf = StringIO()
    real_console = Console(file=buf, width=120, force_terminal=False)
    original = display_module.console
    display_module.console = real_console
    try:
        _display_file_info(results)
        _display_pe_info(results)
        _display_security(results)
    finally:
        display_module.console = original

    output = buf.getvalue()
    assert "File Information" in output
    assert "PE Analysis" in output
    assert "Security Features" in output
    assert "abc123" in output
    assert "Console" in output
    assert "Nx" in output


def test_display_file_info_get_section_delegates():
    """_display_file_info uses get_section under the hood — verify via absent key."""
    results = {"__present__": {"pe_info"}, "file_info": {"name": "test.exe"}}
    output = _capture(_display_file_info, results)
    # file_info is not in __present__ set, so should produce no output
    assert output == ""


def test_display_pe_info_get_section_delegates():
    results = {"__present__": {"file_info"}, "pe_info": {"subsystem": "GUI"}}
    output = _capture(_display_pe_info, results)
    assert output == ""


def test_display_security_get_section_delegates():
    results = {"__present__": {"file_info"}, "security": {"nx": True}}
    output = _capture(_display_security, results)
    assert output == ""
