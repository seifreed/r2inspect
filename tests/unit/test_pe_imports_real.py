#!/usr/bin/env python3
"""Tests for modules/pe_imports.py"""

from __future__ import annotations

from unittest.mock import Mock

from r2inspect.modules import pe_imports


def test_fetch_imports_with_method():
    adapter = Mock()
    adapter.get_imports.return_value = [{"name": "CreateFileA"}]
    
    result = pe_imports.fetch_imports(adapter)
    
    assert result == [{"name": "CreateFileA"}]


def test_fetch_imports_without_method():
    adapter = Mock(spec=[])
    
    result = pe_imports.fetch_imports(adapter)
    
    assert isinstance(result, list)


def test_fetch_imports_none_adapter():
    result = pe_imports.fetch_imports(None)
    
    assert result == []


def test_fetch_imports_empty():
    adapter = Mock()
    adapter.get_imports.return_value = None
    
    result = pe_imports.fetch_imports(adapter)
    
    assert result == []


def test_group_imports_by_library_basic():
    imports = [
        {"libname": "kernel32.dll", "name": "CreateFileA"},
        {"libname": "kernel32.dll", "name": "ReadFile"},
        {"libname": "user32.dll", "name": "MessageBoxA"},
    ]
    
    result = pe_imports.group_imports_by_library(imports)
    
    assert "kernel32.dll" in result
    assert "user32.dll" in result
    assert len(result["kernel32.dll"]) == 2
    assert len(result["user32.dll"]) == 1


def test_group_imports_by_library_no_libname():
    imports = [
        {"name": "CreateFileA"},
    ]
    
    result = pe_imports.group_imports_by_library(imports)
    
    assert "unknown" in result
    assert "CreateFileA" in result["unknown"]


def test_group_imports_by_library_empty_libname():
    imports = [
        {"libname": "", "name": "CreateFileA"},
        {"libname": "  ", "name": "ReadFile"},
    ]
    
    result = pe_imports.group_imports_by_library(imports)
    
    assert "unknown" in result
    assert len(result["unknown"]) == 2


def test_group_imports_by_library_no_name():
    imports = [
        {"libname": "kernel32.dll"},
    ]
    
    result = pe_imports.group_imports_by_library(imports)
    
    assert result == {}


def test_group_imports_by_library_empty_name():
    imports = [
        {"libname": "kernel32.dll", "name": ""},
        {"libname": "kernel32.dll", "name": "  "},
    ]
    
    result = pe_imports.group_imports_by_library(imports)
    
    assert result == {}


def test_group_imports_by_library_not_dict():
    imports = [
        "not a dict",
        123,
    ]
    
    result = pe_imports.group_imports_by_library(imports)
    
    assert result == {}


def test_normalize_library_name_basic():
    result = pe_imports.normalize_library_name("KERNEL32.DLL", ["dll", "ocx", "sys"])
    
    assert result == "kernel32"


def test_normalize_library_name_no_extension():
    result = pe_imports.normalize_library_name("kernel32", ["dll", "ocx", "sys"])
    
    assert result == "kernel32"


def test_normalize_library_name_non_matching_extension():
    result = pe_imports.normalize_library_name("kernel32.exe", ["dll", "ocx", "sys"])
    
    assert result == "kernel32.exe"


def test_normalize_library_name_bytes():
    result = pe_imports.normalize_library_name(b"KERNEL32.DLL", ["dll", "ocx", "sys"])
    
    assert result == "kernel32"


def test_normalize_library_name_ocx():
    result = pe_imports.normalize_library_name("control.ocx", ["dll", "ocx", "sys"])
    
    assert result == "control"


def test_normalize_library_name_sys():
    result = pe_imports.normalize_library_name("driver.sys", ["dll", "ocx", "sys"])
    
    assert result == "driver"


def test_compute_imphash_basic():
    import_strings = ["kernel32.createfilea", "kernel32.readfile"]
    
    result = pe_imports.compute_imphash(import_strings)
    
    assert len(result) == 32
    assert result != ""


def test_compute_imphash_empty():
    result = pe_imports.compute_imphash([])
    
    assert result == ""


def test_compute_imphash_single():
    import_strings = ["kernel32.createfilea"]
    
    result = pe_imports.compute_imphash(import_strings)
    
    assert len(result) == 32


def test_calculate_imphash_basic():
    adapter = Mock()
    adapter.get_imports.return_value = [
        {"libname": "kernel32.dll", "name": "CreateFileA"},
        {"libname": "user32.dll", "name": "MessageBoxA"},
    ]
    logger = Mock()
    
    result = pe_imports.calculate_imphash(adapter, logger)
    
    assert len(result) == 32
    assert result != ""


def test_calculate_imphash_no_imports():
    adapter = Mock()
    adapter.get_imports.return_value = []
    logger = Mock()
    
    result = pe_imports.calculate_imphash(adapter, logger)
    
    assert result == ""
    logger.debug.assert_called()


def test_calculate_imphash_none_imports():
    adapter = Mock()
    adapter.get_imports.return_value = None
    logger = Mock()
    
    result = pe_imports.calculate_imphash(adapter, logger)
    
    assert result == ""


def test_calculate_imphash_bytes_funcname():
    adapter = Mock()
    adapter.get_imports.return_value = [
        {"libname": "kernel32.dll", "name": b"CreateFileA"},
    ]
    logger = Mock()
    
    result = pe_imports.calculate_imphash(adapter, logger)
    
    assert len(result) == 32


def test_calculate_imphash_exception():
    adapter = Mock()
    adapter.get_imports.side_effect = Exception("Test error")
    logger = Mock()
    
    result = pe_imports.calculate_imphash(adapter, logger)
    
    assert result == ""
    logger.error.assert_called_once()
