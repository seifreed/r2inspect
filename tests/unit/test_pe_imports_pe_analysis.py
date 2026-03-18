#!/usr/bin/env python3
"""Comprehensive tests for r2inspect/modules/pe_imports.py - PE import/imphash analysis.

Zero mocks. Uses FakeR2 + R2PipeAdapter to exercise all code paths through real
adapter wiring instead of unittest.mock objects.
"""

from __future__ import annotations

import logging

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules import pe_imports


# ---------------------------------------------------------------------------
# FakeR2: minimal r2pipe stand-in routing cmdj/cmd via lookup maps
# ---------------------------------------------------------------------------


class FakeR2:
    """Minimal r2pipe stand-in that routes cmdj/cmd via lookup maps."""

    def __init__(self, cmdj_map=None, cmd_map=None):
        self.cmdj_map = cmdj_map or {}
        self.cmd_map = cmd_map or {}

    def cmdj(self, command):
        val = self.cmdj_map.get(command)
        if isinstance(val, Exception):
            raise val
        return val if val is not None else {}

    def cmd(self, command):
        val = self.cmd_map.get(command)
        if isinstance(val, Exception):
            raise val
        return val if val is not None else ""


class FakeR2Raising:
    """FakeR2 variant where every call raises."""

    def __init__(self, exc=None):
        self._exc = exc or RuntimeError("r2 failure")

    def cmdj(self, command):
        raise self._exc

    def cmd(self, command):
        raise self._exc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _adapter(cmdj_map=None, cmd_map=None):
    """Build an R2PipeAdapter backed by FakeR2."""
    return R2PipeAdapter(FakeR2(cmdj_map=cmdj_map, cmd_map=cmd_map))


def _raising_adapter(exc=None):
    """Build an R2PipeAdapter that raises on every r2 call."""
    return R2PipeAdapter(FakeR2Raising(exc=exc))


def _logger():
    """Return a real stdlib logger."""
    return logging.getLogger("test_pe_imports_pe_analysis")


# ---------------------------------------------------------------------------
# fetch_imports  –  via adapter.get_imports() (uses iij under the hood)
# ---------------------------------------------------------------------------


def test_fetch_imports_with_adapter_method():
    adapter = _adapter(
        cmdj_map={
            "iij": [
                {"name": "CreateFileA", "libname": "kernel32.dll"},
                {"name": "ReadFile", "libname": "kernel32.dll"},
            ],
        }
    )

    result = pe_imports.fetch_imports(adapter)

    assert len(result) == 2
    assert result[0]["name"] == "CreateFileA"


def test_fetch_imports_returns_none():
    # iij returns None -> adapter normalises to empty list
    adapter = _adapter(cmdj_map={"iij": None})

    result = pe_imports.fetch_imports(adapter)

    assert result == []


def test_fetch_imports_returns_empty_list():
    adapter = _adapter(cmdj_map={"iij": []})

    result = pe_imports.fetch_imports(adapter)

    assert result == []


def test_fetch_imports_large_list():
    imports = [{"name": f"Function{i}", "libname": "lib.dll"} for i in range(100)]
    adapter = _adapter(cmdj_map={"iij": imports})

    result = pe_imports.fetch_imports(adapter)

    assert len(result) == 100


def test_fetch_imports_error_handling():
    # When the adapter raises, silent_cmdj swallows it and returns None/empty,
    # so fetch_imports returns [] rather than propagating.
    adapter = _raising_adapter(RuntimeError("Test error"))

    result = pe_imports.fetch_imports(adapter)

    assert result == []


# ---------------------------------------------------------------------------
# group_imports_by_library  –  pure function, no adapter needed
# ---------------------------------------------------------------------------


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


def test_group_imports_by_library_accepts_library_key():
    imports = [
        {"library": "kernel32.dll", "name": "CreateFileA"},
        {"library": "user32.dll", "name": "MessageBoxA"},
    ]

    result = pe_imports.group_imports_by_library(imports)

    assert result == {
        "kernel32.dll": ["CreateFileA"],
        "user32.dll": ["MessageBoxA"],
    }


def test_group_imports_by_library_missing_libname():
    imports = [
        {"name": "SomeFunction"},
        {"libname": None, "name": "OtherFunction"},
    ]

    result = pe_imports.group_imports_by_library(imports)

    assert result == {}


def test_group_imports_by_library_whitespace_libname():
    imports = [
        {"libname": "   ", "name": "Function1"},
        {"libname": "\t\n", "name": "Function2"},
    ]

    result = pe_imports.group_imports_by_library(imports)

    assert result == {}


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


# ---------------------------------------------------------------------------
# normalize_library_name  –  pure function
# ---------------------------------------------------------------------------


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


def test_normalize_library_name_edge_cases():
    assert pe_imports.normalize_library_name("", ["dll"]) == ""
    result = pe_imports.normalize_library_name(".", ["dll"])
    assert isinstance(result, str)
    result = pe_imports.normalize_library_name(".dll", ["dll"])
    assert isinstance(result, str)


# ---------------------------------------------------------------------------
# compute_imphash  –  pure function
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# has_known_library_name  –  pure function
# ---------------------------------------------------------------------------


def test_has_known_library_name_rejects_unknown_and_blank_values():
    assert pe_imports.has_known_library_name("kernel32.dll") is True
    assert pe_imports.has_known_library_name("unknown") is False
    assert pe_imports.has_known_library_name("") is False
    assert pe_imports.has_known_library_name(None) is False


# ---------------------------------------------------------------------------
# calculate_imphash  –  uses adapter.get_imports() -> iij
# ---------------------------------------------------------------------------


_TWO_IMPORTS = [
    {"libname": "kernel32.dll", "name": "CreateFileA"},
    {"libname": "user32.dll", "name": "MessageBoxA"},
]


def test_calculate_imphash_basic():
    adapter = _adapter(cmdj_map={"iij": _TWO_IMPORTS})
    log = _logger()

    result = pe_imports.calculate_imphash(adapter, log)

    assert len(result) == 32
    assert result.isalnum()


def test_calculate_imphash_with_ocx():
    adapter = _adapter(
        cmdj_map={
            "iij": [{"libname": "control.ocx", "name": "RegisterControl"}],
        }
    )
    log = _logger()

    result = pe_imports.calculate_imphash(adapter, log)

    assert len(result) == 32


def test_calculate_imphash_with_sys():
    adapter = _adapter(
        cmdj_map={
            "iij": [{"libname": "driver.sys", "name": "DriverEntry"}],
        }
    )
    log = _logger()

    result = pe_imports.calculate_imphash(adapter, log)

    assert len(result) == 32


def test_calculate_imphash_accepts_library_key():
    adapter = _adapter(
        cmdj_map={
            "iij": [{"library": "KERNEL32.dll", "name": "CreateFileA"}],
        }
    )
    log = _logger()

    result = pe_imports.calculate_imphash(adapter, log)

    assert result == pe_imports.compute_imphash(["kernel32.createfilea"])


def test_calculate_imphash_no_imports():
    adapter = _adapter(cmdj_map={"iij": []})
    log = _logger()

    result = pe_imports.calculate_imphash(adapter, log)

    assert result == ""


def test_calculate_imphash_none_imports():
    # iij returning None -> fetch_imports normalises to []
    adapter = _adapter(cmdj_map={"iij": None})
    log = _logger()

    result = pe_imports.calculate_imphash(adapter, log)

    assert result == ""


def test_calculate_imphash_bytes_function_name():
    adapter = _adapter(
        cmdj_map={
            "iij": [
                {"libname": "kernel32.dll", "name": b"CreateFileA"},
                {"libname": "kernel32.dll", "name": b"ReadFile"},
            ],
        }
    )
    log = _logger()

    result = pe_imports.calculate_imphash(adapter, log)

    assert len(result) == 32


def test_calculate_imphash_bytes_library_name():
    adapter = _adapter(
        cmdj_map={
            "iij": [{"libname": b"kernel32.dll", "name": "CreateFileA"}],
        }
    )
    log = _logger()

    result = pe_imports.calculate_imphash(adapter, log)

    assert len(result) == 32


def test_calculate_imphash_mixed_case():
    adapter = _adapter(
        cmdj_map={
            "iij": [
                {"libname": "KERNEL32.DLL", "name": "CreateFileA"},
                {"libname": "kernel32.dll", "name": "READFILE"},
            ],
        }
    )
    log = _logger()

    result = pe_imports.calculate_imphash(adapter, log)

    assert len(result) == 32


def test_calculate_imphash_exception():
    adapter = _raising_adapter(RuntimeError("Adapter error"))
    log = _logger()

    result = pe_imports.calculate_imphash(adapter, log)

    assert result == ""


def test_calculate_imphash_invalid_import_data():
    adapter = _adapter(
        cmdj_map={
            "iij": [
                {"libname": "kernel32.dll", "name": "CreateFileA"},
                None,
                "invalid",
                {"libname": "user32.dll"},
            ],
        }
    )
    log = _logger()

    result = pe_imports.calculate_imphash(adapter, log)

    assert len(result) == 32


def test_calculate_imphash_empty_function_names():
    adapter = _adapter(
        cmdj_map={
            "iij": [
                {"libname": "kernel32.dll", "name": ""},
                {"libname": "kernel32.dll", "name": "   "},
                {"libname": "kernel32.dll", "name": "CreateFileA"},
            ],
        }
    )
    log = _logger()

    result = pe_imports.calculate_imphash(adapter, log)

    assert len(result) == 32


def test_calculate_imphash_large_import_list():
    imports = [{"libname": f"lib{i % 10}.dll", "name": f"Function{i}"} for i in range(1000)]
    adapter = _adapter(cmdj_map={"iij": imports})
    log = _logger()

    result = pe_imports.calculate_imphash(adapter, log)

    assert len(result) == 32


def test_calculate_imphash_unknown_library():
    adapter = _adapter(
        cmdj_map={
            "iij": [
                {"name": "Function1"},
                {"name": "Function2"},
            ],
        }
    )
    log = _logger()

    result = pe_imports.calculate_imphash(adapter, log)

    assert result == ""


def test_calculate_imphash_skips_none_library():
    adapter = _adapter(
        cmdj_map={
            "iij": [{"library": None, "name": "CreateFileA"}],
        }
    )
    log = _logger()

    result = pe_imports.calculate_imphash(adapter, log)

    assert result == ""


# ---------------------------------------------------------------------------
# Integration: fetch -> group -> imphash on the same adapter
# ---------------------------------------------------------------------------


def test_imphash_integration():
    payload = [
        {"libname": "kernel32.dll", "name": "CreateFileA"},
        {"libname": "kernel32.dll", "name": "ReadFile"},
        {"libname": "user32.dll", "name": "MessageBoxA"},
    ]
    adapter = _adapter(cmdj_map={"iij": payload})
    log = _logger()

    imports = pe_imports.fetch_imports(adapter)
    grouped = pe_imports.group_imports_by_library(imports)
    imphash = pe_imports.calculate_imphash(adapter, log)

    assert len(imports) == 3
    assert len(grouped) == 2
    assert len(imphash) == 32
