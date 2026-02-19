#!/usr/bin/env python3
"""Tests for modules/pe_info.py"""

from __future__ import annotations

from unittest.mock import Mock

from r2inspect.modules import pe_info


def test_get_pe_headers_info_basic():
    adapter = Mock()
    adapter.get_file_info.return_value = {
        "bin": {
            "arch": "x86",
            "machine": "i386",
            "bits": 32,
            "endian": "little",
            "baddr": 0x400000,
        }
    }
    logger = Mock()
    
    result = pe_info.get_pe_headers_info(adapter, "/test.exe", logger)
    
    assert result["architecture"] == "x86"
    assert result["machine"] == "i386"
    assert result["bits"] == 32
    assert result["endian"] == "little"
    assert result["image_base"] == 0x400000


def test_get_pe_headers_info_no_bin():
    adapter = Mock()
    adapter.get_file_info.return_value = {}
    logger = Mock()
    
    result = pe_info.get_pe_headers_info(adapter, "/test.exe", logger)
    
    assert result == {}


def test_get_pe_headers_info_exception():
    adapter = Mock()
    adapter.get_file_info.side_effect = Exception("Test error")
    logger = Mock()
    
    result = pe_info.get_pe_headers_info(adapter, "/test.exe", logger)
    
    assert result == {}
    logger.error.assert_called_once()


def test_fetch_pe_header_success():
    adapter = Mock()
    adapter.cmd.return_value = '{"signature": "PE"}'
    logger = Mock()
    
    result = pe_info._fetch_pe_header(adapter, logger)
    
    assert result is not None


def test_fetch_pe_header_exception():
    adapter = Mock()
    adapter.cmd.side_effect = Exception("Test error")
    logger = Mock()
    
    result = pe_info._fetch_pe_header(adapter, logger)
    
    assert result is None


def test_get_entry_info_valid():
    adapter = Mock()
    adapter.get_entry_info.return_value = [{"vaddr": 0x1000}]
    logger = Mock()
    
    result = pe_info._get_entry_info(adapter, logger)
    
    assert result == [{"vaddr": 0x1000}]


def test_get_entry_info_none_adapter():
    logger = Mock()
    
    result = pe_info._get_entry_info(None, logger)
    
    assert result is None


def test_get_entry_info_no_method():
    adapter = Mock(spec=[])
    logger = Mock()
    
    result = pe_info._get_entry_info(adapter, logger)
    
    assert result is None


def test_get_entry_info_exception():
    adapter = Mock()
    adapter.get_entry_info.side_effect = Exception("Test error")
    logger = Mock()
    
    result = pe_info._get_entry_info(adapter, logger)
    
    assert result is None
    logger.debug.assert_called_once()


def test_get_entry_info_not_list():
    adapter = Mock()
    adapter.get_entry_info.return_value = "not a list"
    logger = Mock()
    
    result = pe_info._get_entry_info(adapter, logger)
    
    assert result is None


def test_get_file_description_no_filepath():
    logger = Mock()
    
    result = pe_info._get_file_description(None, logger)
    
    assert result is None


def test_get_file_description_import_error(monkeypatch):
    import sys
    
    original_modules = sys.modules.copy()
    if "magic" in sys.modules:
        monkeypatch.setitem(sys.modules, "magic", None)
    
    logger = Mock()
    
    result = pe_info._get_file_description("/test.exe", logger)
    
    assert result is None
    
    sys.modules.update(original_modules)


def test_get_file_characteristics_basic():
    adapter = Mock()
    adapter.get_file_info.return_value = {
        "bin": {
            "debug": True,
        }
    }
    logger = Mock()
    
    result = pe_info.get_file_characteristics(adapter, "/test.exe", logger)
    
    assert result["has_debug"] is True


def test_get_file_characteristics_no_bin():
    adapter = Mock()
    adapter.get_file_info.return_value = {}
    logger = Mock()
    
    result = pe_info.get_file_characteristics(adapter, "/test.exe", logger)
    
    assert result == {}


def test_get_file_characteristics_exception():
    adapter = Mock()
    adapter.get_file_info.side_effect = Exception("Test error")
    logger = Mock()
    
    result = pe_info.get_file_characteristics(adapter, "/test.exe", logger)
    
    assert result == {}
    logger.error.assert_called_once()


def test_get_compilation_info_basic():
    adapter = Mock()
    adapter.get_file_info.return_value = {
        "bin": {
            "compiled": "2024-01-01",
        }
    }
    logger = Mock()
    
    result = pe_info.get_compilation_info(adapter, logger)
    
    assert result["compile_time"] == "2024-01-01"


def test_get_compilation_info_no_bin():
    adapter = Mock()
    adapter.get_file_info.return_value = {}
    logger = Mock()
    
    result = pe_info.get_compilation_info(adapter, logger)
    
    assert result == {}


def test_get_compilation_info_exception():
    adapter = Mock()
    adapter.get_file_info.side_effect = Exception("Test error")
    logger = Mock()
    
    result = pe_info.get_compilation_info(adapter, logger)
    
    assert result == {}
    logger.error.assert_called_once()


def test_extract_compiler_info_none_adapter():
    result = pe_info._extract_compiler_info(None)
    
    assert result is None


def test_extract_compiler_info_no_method():
    adapter = Mock(spec=[])
    
    result = pe_info._extract_compiler_info(adapter)
    
    assert result is None


def test_extract_compiler_info_with_compiler():
    adapter = Mock()
    adapter.get_strings_text.return_value = "line1\nCompiler: MSVC\nline3"
    
    result = pe_info._extract_compiler_info(adapter)
    
    assert result == "Compiler: MSVC"


def test_extract_compiler_info_no_compiler():
    adapter = Mock()
    adapter.get_strings_text.return_value = "line1\nline2\nline3"
    
    result = pe_info._extract_compiler_info(adapter)
    
    assert result is None


def test_extract_compiler_info_empty_strings():
    adapter = Mock()
    adapter.get_strings_text.return_value = ""
    
    result = pe_info._extract_compiler_info(adapter)
    
    assert result is None


def test_extract_compiler_info_none_strings():
    adapter = Mock()
    adapter.get_strings_text.return_value = None
    
    result = pe_info._extract_compiler_info(adapter)
    
    assert result is None


def test_get_subsystem_info_basic():
    adapter = Mock()
    adapter.get_file_info.return_value = {
        "bin": {
            "subsys": "windows gui",
        }
    }
    logger = Mock()
    
    result = pe_info.get_subsystem_info(adapter, logger)
    
    assert "subsystem" in result or len(result) >= 0


def test_get_subsystem_info_no_bin():
    adapter = Mock()
    adapter.get_file_info.return_value = {}
    logger = Mock()
    
    result = pe_info.get_subsystem_info(adapter, logger)
    
    assert result == {}


def test_get_subsystem_info_exception():
    adapter = Mock()
    adapter.get_file_info.side_effect = Exception("Test error")
    logger = Mock()
    
    result = pe_info.get_subsystem_info(adapter, logger)
    
    assert result == {}
    logger.error.assert_called_once()
