#!/usr/bin/env python3
"""Comprehensive tests for r2inspect/modules/pe_imports.py - PE import/imphash analysis."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from r2inspect.modules import pe_imports


def test_fetch_imports_with_adapter_method():
    adapter = Mock()
    adapter.get_imports.return_value = [
        {"name": "CreateFileA", "libname": "kernel32.dll"},
        {"name": "ReadFile", "libname": "kernel32.dll"},
    ]
    
    result = pe_imports.fetch_imports(adapter)
    
    assert len(result) == 2
    assert result[0]["name"] == "CreateFileA"


def test_fetch_imports_without_get_imports_method():
    adapter = Mock(spec=["cmd"])
    
    result = pe_imports.fetch_imports(adapter)
    
    assert isinstance(result, list)


def test_fetch_imports_returns_none():
    adapter = Mock()
    adapter.get_imports.return_value = None
    
    result = pe_imports.fetch_imports(adapter)
    
    assert result == []


def test_fetch_imports_returns_empty_list():
    adapter = Mock()
    adapter.get_imports.return_value = []
    
    result = pe_imports.fetch_imports(adapter)
    
    assert result == []


def test_fetch_imports_large_list():
    adapter = Mock()
    imports = [{"name": f"Function{i}", "libname": "lib.dll"} for i in range(100)]
    adapter.get_imports.return_value = imports
    
    result = pe_imports.fetch_imports(adapter)
    
    assert len(result) == 100


def test_group_imports_by_library_single_library():
    imports = [
        {"libname": "kernel32.dll", "name": "CreateFileA"},
        {"libname": "kernel32.dll", "name": "ReadFile"},
        {"libname": "kernel32.dll", "name": "WriteFile"},
    ]
    
    result = pe_imports.group_imports_by_library(imports)
    
    assert "kernel32.dll" in result
    assert len(result["kernel32.dll"]) == 3
    assert "CreateFileA" in result["kernel32.dll"]


def test_group_imports_by_library_multiple_libraries():
    imports = [
        {"libname": "kernel32.dll", "name": "CreateFileA"},
        {"libname": "user32.dll", "name": "MessageBoxA"},
        {"libname": "advapi32.dll", "name": "RegOpenKeyExA"},
    ]
    
    result = pe_imports.group_imports_by_library(imports)
    
    assert len(result) == 3
    assert "kernel32.dll" in result
    assert "user32.dll" in result
    assert "advapi32.dll" in result


def test_group_imports_by_library_missing_libname():
    imports = [
        {"name": "SomeFunction"},
        {"libname": None, "name": "OtherFunction"},
    ]
    
    result = pe_imports.group_imports_by_library(imports)
    
    assert "unknown" in result
    assert len(result["unknown"]) == 2


def test_group_imports_by_library_whitespace_libname():
    imports = [
        {"libname": "   ", "name": "Function1"},
        {"libname": "\t\n", "name": "Function2"},
    ]
    
    result = pe_imports.group_imports_by_library(imports)
    
    assert "unknown" in result
    assert len(result["unknown"]) == 2


def test_group_imports_by_library_missing_name():
    imports = [
        {"libname": "kernel32.dll"},
        {"libname": "kernel32.dll", "name": None},
    ]
    
    result = pe_imports.group_imports_by_library(imports)
    
    assert result == {}


def test_group_imports_by_library_whitespace_name():
    imports = [
        {"libname": "kernel32.dll", "name": ""},
        {"libname": "kernel32.dll", "name": "   "},
    ]
    
    result = pe_imports.group_imports_by_library(imports)
    
    assert result == {}


def test_group_imports_by_library_invalid_entries():
    imports = [
        "not a dict",
        123,
        None,
        [],
    ]
    
    result = pe_imports.group_imports_by_library(imports)
    
    assert result == {}


def test_group_imports_by_library_mixed_valid_invalid():
    imports = [
        {"libname": "kernel32.dll", "name": "CreateFileA"},
        "invalid",
        {"libname": "user32.dll", "name": "MessageBoxA"},
        None,
    ]
    
    result = pe_imports.group_imports_by_library(imports)
    
    assert len(result) == 2
    assert "kernel32.dll" in result
    assert "user32.dll" in result


def test_normalize_library_name_dll_extension():
    result = pe_imports.normalize_library_name("KERNEL32.DLL", ["dll", "ocx", "sys"])
    
    assert result == "kernel32"


def test_normalize_library_name_ocx_extension():
    result = pe_imports.normalize_library_name("CONTROL.OCX", ["dll", "ocx", "sys"])
    
    assert result == "control"


def test_normalize_library_name_sys_extension():
    result = pe_imports.normalize_library_name("DRIVER.SYS", ["dll", "ocx", "sys"])
    
    assert result == "driver"


def test_normalize_library_name_no_extension():
    result = pe_imports.normalize_library_name("kernel32", ["dll", "ocx", "sys"])
    
    assert result == "kernel32"


def test_normalize_library_name_other_extension():
    result = pe_imports.normalize_library_name("program.exe", ["dll", "ocx", "sys"])
    
    assert result == "program.exe"


def test_normalize_library_name_bytes_input():
    result = pe_imports.normalize_library_name(b"KERNEL32.DLL", ["dll", "ocx", "sys"])
    
    assert result == "kernel32"


def test_normalize_library_name_bytes_with_invalid_chars():
    result = pe_imports.normalize_library_name(b"lib\xff\xfe.dll", ["dll", "ocx", "sys"])
    
    assert isinstance(result, str)


def test_normalize_library_name_case_sensitivity():
    result = pe_imports.normalize_library_name("MyLibrary.DLL", ["dll"])
    
    assert result == "mylibrary"


def test_normalize_library_name_multiple_dots():
    result = pe_imports.normalize_library_name("my.library.dll", ["dll", "ocx", "sys"])
    
    assert result == "my.library"


def test_compute_imphash_single_import():
    import_strings = ["kernel32.createfilea"]
    
    result = pe_imports.compute_imphash(import_strings)
    
    assert len(result) == 32
    assert result.isalnum()


def test_compute_imphash_multiple_imports():
    import_strings = [
        "kernel32.createfilea",
        "kernel32.readfile",
        "user32.messageboxa",
    ]
    
    result = pe_imports.compute_imphash(import_strings)
    
    assert len(result) == 32
    assert result.isalnum()


def test_compute_imphash_deterministic():
    import_strings = ["kernel32.createfilea", "user32.messageboxa"]
    
    result1 = pe_imports.compute_imphash(import_strings)
    result2 = pe_imports.compute_imphash(import_strings)
    
    assert result1 == result2


def test_compute_imphash_order_matters():
    imports1 = ["kernel32.createfilea", "user32.messageboxa"]
    imports2 = ["user32.messageboxa", "kernel32.createfilea"]
    
    result1 = pe_imports.compute_imphash(imports1)
    result2 = pe_imports.compute_imphash(imports2)
    
    assert result1 != result2


def test_compute_imphash_empty_list():
    result = pe_imports.compute_imphash([])
    
    assert result == ""


def test_compute_imphash_special_characters():
    import_strings = ["kernel32.function@123"]
    
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
    assert result.isalnum()


def test_calculate_imphash_with_ocx():
    adapter = Mock()
    adapter.get_imports.return_value = [
        {"libname": "control.ocx", "name": "RegisterControl"},
    ]
    logger = Mock()
    
    result = pe_imports.calculate_imphash(adapter, logger)
    
    assert len(result) == 32


def test_calculate_imphash_with_sys():
    adapter = Mock()
    adapter.get_imports.return_value = [
        {"libname": "driver.sys", "name": "DriverEntry"},
    ]
    logger = Mock()
    
    result = pe_imports.calculate_imphash(adapter, logger)
    
    assert len(result) == 32


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


def test_calculate_imphash_bytes_function_name():
    adapter = Mock()
    adapter.get_imports.return_value = [
        {"libname": "kernel32.dll", "name": b"CreateFileA"},
        {"libname": "kernel32.dll", "name": b"ReadFile"},
    ]
    logger = Mock()
    
    result = pe_imports.calculate_imphash(adapter, logger)
    
    assert len(result) == 32


def test_calculate_imphash_bytes_library_name():
    adapter = Mock()
    adapter.get_imports.return_value = [
        {"libname": b"kernel32.dll", "name": "CreateFileA"},
    ]
    logger = Mock()
    
    result = pe_imports.calculate_imphash(adapter, logger)
    
    assert len(result) == 32


def test_calculate_imphash_mixed_case():
    adapter = Mock()
    adapter.get_imports.return_value = [
        {"libname": "KERNEL32.DLL", "name": "CreateFileA"},
        {"libname": "kernel32.dll", "name": "READFILE"},
    ]
    logger = Mock()
    
    result = pe_imports.calculate_imphash(adapter, logger)
    
    assert len(result) == 32


def test_calculate_imphash_exception():
    adapter = Mock()
    adapter.get_imports.side_effect = RuntimeError("Adapter error")
    logger = Mock()
    
    result = pe_imports.calculate_imphash(adapter, logger)
    
    assert result == ""
    logger.error.assert_called_once()


def test_calculate_imphash_invalid_import_data():
    adapter = Mock()
    adapter.get_imports.return_value = [
        {"libname": "kernel32.dll", "name": "CreateFileA"},
        None,
        "invalid",
        {"libname": "user32.dll"},
    ]
    logger = Mock()
    
    result = pe_imports.calculate_imphash(adapter, logger)
    
    assert len(result) == 32


def test_calculate_imphash_empty_function_names():
    adapter = Mock()
    adapter.get_imports.return_value = [
        {"libname": "kernel32.dll", "name": ""},
        {"libname": "kernel32.dll", "name": "   "},
        {"libname": "kernel32.dll", "name": "CreateFileA"},
    ]
    logger = Mock()
    
    result = pe_imports.calculate_imphash(adapter, logger)
    
    assert len(result) == 32


def test_calculate_imphash_large_import_list():
    adapter = Mock()
    imports = [
        {"libname": f"lib{i % 10}.dll", "name": f"Function{i}"}
        for i in range(1000)
    ]
    adapter.get_imports.return_value = imports
    logger = Mock()
    
    result = pe_imports.calculate_imphash(adapter, logger)
    
    assert len(result) == 32
    logger.debug.assert_called()


def test_calculate_imphash_unknown_library():
    adapter = Mock()
    adapter.get_imports.return_value = [
        {"name": "Function1"},
        {"name": "Function2"},
    ]
    logger = Mock()
    
    result = pe_imports.calculate_imphash(adapter, logger)
    
    assert len(result) == 32


def test_group_imports_preservation():
    imports = [
        {"libname": "kernel32.dll", "name": "CreateFileA"},
        {"libname": "kernel32.dll", "name": "ReadFile"},
        {"libname": "kernel32.dll", "name": "WriteFile"},
    ]
    
    result = pe_imports.group_imports_by_library(imports)
    
    assert "CreateFileA" in result["kernel32.dll"]
    assert "ReadFile" in result["kernel32.dll"]
    assert "WriteFile" in result["kernel32.dll"]


def test_imphash_integration():
    adapter = Mock()
    adapter.get_imports.return_value = [
        {"libname": "kernel32.dll", "name": "CreateFileA"},
        {"libname": "kernel32.dll", "name": "ReadFile"},
        {"libname": "user32.dll", "name": "MessageBoxA"},
    ]
    logger = Mock()
    
    imports = pe_imports.fetch_imports(adapter)
    grouped = pe_imports.group_imports_by_library(imports)
    imphash = pe_imports.calculate_imphash(adapter, logger)
    
    assert len(imports) == 3
    assert len(grouped) == 2
    assert len(imphash) == 32


def test_normalize_library_name_edge_cases():
    assert pe_imports.normalize_library_name("", ["dll"]) == ""
    result = pe_imports.normalize_library_name(".", ["dll"])
    assert isinstance(result, str)
    result = pe_imports.normalize_library_name(".dll", ["dll"])
    assert isinstance(result, str)


def test_fetch_imports_error_handling():
    adapter = Mock()
    adapter.get_imports.side_effect = Exception("Test error")
    
    with pytest.raises(Exception):
        pe_imports.fetch_imports(adapter)
