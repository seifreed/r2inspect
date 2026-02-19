#!/usr/bin/env python3
"""Comprehensive tests for r2inspect/cli/display_sections_file.py"""

from typing import Any
from unittest.mock import MagicMock, patch

from r2inspect.cli.display_sections_file import _display_file_info, _display_pe_info, _display_security


def test_display_file_info_not_present():
    results = {}
    with patch("r2inspect.cli.display_sections_file._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        _display_file_info(results)
        mock_console_obj.print.assert_not_called()


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
    with patch("r2inspect.cli.display_sections_file._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        _display_file_info(results)
        assert mock_console_obj.print.call_count == 2


def test_display_file_info_with_hashes():
    results = {
        "file_info": {
            "name": "test.exe",
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "sha512": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        }
    }
    with patch("r2inspect.cli.display_sections_file._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        _display_file_info(results)
        mock_console_obj.print.assert_called()


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
    with patch("r2inspect.cli.display_sections_file._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        _display_file_info(results)
        mock_console_obj.print.assert_called()


def test_display_file_info_empty_enhanced():
    results = {"file_info": {"name": "test.exe", "enhanced_detection": {}}}
    with patch("r2inspect.cli.display_sections_file._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        _display_file_info(results)
        mock_console_obj.print.assert_called()


def test_display_file_info_none_values():
    results = {
        "file_info": {
            "name": "test.exe",
            "size": None,
            "md5": None,
            "sha1": None,
        }
    }
    with patch("r2inspect.cli.display_sections_file._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        _display_file_info(results)
        mock_console_obj.print.assert_called()


def test_display_file_info_missing_enhanced_fields():
    results = {
        "file_info": {
            "name": "test.exe",
            "enhanced_detection": {
                "file_format": "PE",
            },
        }
    }
    with patch("r2inspect.cli.display_sections_file._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        _display_file_info(results)
        mock_console_obj.print.assert_called()


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
    with patch("r2inspect.cli.display_sections_file._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        _display_file_info(results)
        assert mock_console_obj.print.call_count == 2


def test_display_pe_info_not_present():
    results = {}
    with patch("r2inspect.cli.display_sections_file._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        _display_pe_info(results)
        mock_console_obj.print.assert_not_called()


def test_display_pe_info_basic():
    results = {
        "pe_info": {
            "subsystem": "GUI",
            "timestamp": "2024-01-01",
        }
    }
    with patch("r2inspect.cli.display_sections_file._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        _display_pe_info(results)
        assert mock_console_obj.print.call_count == 2


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
    with patch("r2inspect.cli.display_sections_file._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        _display_pe_info(results)
        mock_console_obj.print.assert_called()


def test_display_pe_info_with_list_values():
    results = {
        "pe_info": {
            "imports": ["kernel32.dll", "user32.dll"],
            "exports": ["func1", "func2"],
        }
    }
    with patch("r2inspect.cli.display_sections_file._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        _display_pe_info(results)
        mock_console_obj.print.assert_called()


def test_display_pe_info_with_dict_values():
    results = {
        "pe_info": {
            "metadata": {"key": "value"},
            "subsystem": "GUI",
        }
    }
    with patch("r2inspect.cli.display_sections_file._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        _display_pe_info(results)
        mock_console_obj.print.assert_called()


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
    with patch("r2inspect.cli.display_sections_file._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        _display_pe_info(results)
        assert mock_console_obj.print.call_count == 2


def test_display_security_not_present():
    results = {}
    with patch("r2inspect.cli.display_sections_file._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        _display_security(results)
        mock_console_obj.print.assert_not_called()


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
    with patch("r2inspect.cli.display_sections_file._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        _display_security(results)
        assert mock_console_obj.print.call_count == 2


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
    with patch("r2inspect.cli.display_sections_file._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        _display_security(results)
        assert mock_console_obj.print.call_count == 2


def test_display_security_mixed():
    results = {
        "security": {
            "nx": True,
            "pie": False,
            "canary": True,
            "relro": False,
        }
    }
    with patch("r2inspect.cli.display_sections_file._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        _display_security(results)
        assert mock_console_obj.print.call_count == 2


def test_display_security_single_feature():
    results = {"security": {"aslr": True}}
    with patch("r2inspect.cli.display_sections_file._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        _display_security(results)
        assert mock_console_obj.print.call_count == 2


def test_display_security_underscores():
    results = {
        "security": {
            "dep_enabled": True,
            "safe_seh": False,
            "control_flow_guard": True,
        }
    }
    with patch("r2inspect.cli.display_sections_file._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        _display_security(results)
        assert mock_console_obj.print.call_count == 2


def test_display_security_empty():
    results = {"security": {}}
    with patch("r2inspect.cli.display_sections_file._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        _display_security(results)
        assert mock_console_obj.print.call_count == 2


def test_display_sections_integration():
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
    with patch("r2inspect.cli.display_sections_file._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        _display_file_info(results)
        _display_pe_info(results)
        _display_security(results)
        assert mock_console_obj.print.call_count == 6


def test_display_file_info_get_section():
    results = {"file_info": {"name": "test.exe"}}
    with patch("r2inspect.cli.display_sections_file._get_section") as mock_get:
        mock_get.return_value = ({"name": "test.exe"}, True)
        with patch("r2inspect.cli.display_sections_file._get_console"):
            _display_file_info(results)
            mock_get.assert_called_once_with(results, "file_info", {})


def test_display_pe_info_get_section():
    results = {"pe_info": {"subsystem": "GUI"}}
    with patch("r2inspect.cli.display_sections_file._get_section") as mock_get:
        mock_get.return_value = ({"subsystem": "GUI"}, True)
        with patch("r2inspect.cli.display_sections_file._get_console"):
            _display_pe_info(results)
            mock_get.assert_called_once_with(results, "pe_info", {})


def test_display_security_get_section():
    results = {"security": {"nx": True}}
    with patch("r2inspect.cli.display_sections_file._get_section") as mock_get:
        mock_get.return_value = ({"nx": True}, True)
        with patch("r2inspect.cli.display_sections_file._get_console"):
            _display_security(results)
            mock_get.assert_called_once_with(results, "security", {})


def test_display_file_info_sha256_sha512_strings():
    results = {
        "file_info": {
            "name": "test.exe",
            "sha256": 12345,
            "sha512": 67890,
        }
    }
    with patch("r2inspect.cli.display_sections_file._get_console") as mock_console:
        mock_console_obj = MagicMock()
        mock_console.return_value = mock_console_obj
        _display_file_info(results)
        mock_console_obj.print.assert_called()
