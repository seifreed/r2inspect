#!/usr/bin/env python3
"""Tests for modules/pe_imports.py -- no mocks, no monkeypatch, no @patch.

Uses FakeR2 + R2PipeAdapter. PE imports use the ``iij`` command.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules import pe_imports
from r2inspect.testing.fake_r2 import FakeR2


# ---------------------------------------------------------------------------
# FakeR2: minimal r2pipe-like backend driven by command maps
# ---------------------------------------------------------------------------


def _make_adapter(
    cmd_map: dict[str, str] | None = None,
    cmdj_map: dict[str, Any] | None = None,
) -> R2PipeAdapter:
    return R2PipeAdapter(FakeR2(cmd_map=cmd_map, cmdj_map=cmdj_map))


# ---------------------------------------------------------------------------
# Typical import data for a PE binary (returned by ``iij``)
# ---------------------------------------------------------------------------

KERNEL32_IMPORTS = [
    {"libname": "kernel32.dll", "name": "CreateFileA", "ordinal": 0, "plt": 0x401000},
    {"libname": "kernel32.dll", "name": "ReadFile", "ordinal": 0, "plt": 0x401004},
]

MIXED_IMPORTS = [
    {"libname": "kernel32.dll", "name": "CreateFileA"},
    {"libname": "kernel32.dll", "name": "ReadFile"},
    {"libname": "user32.dll", "name": "MessageBoxA"},
]


# ---------------------------------------------------------------------------
# A real logger (no Mock)
# ---------------------------------------------------------------------------


class _CapturingHandler(logging.Handler):
    """Simple handler that stores log records for later inspection."""

    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    @property
    def messages(self) -> list[str]:
        return [self.format(r) for r in self.records]


def _make_logger(name: str = "test_pe_imports") -> tuple[logging.Logger, _CapturingHandler]:
    log = logging.getLogger(name)
    log.setLevel(logging.DEBUG)
    handler = _CapturingHandler()
    log.addHandler(handler)
    return log, handler


# ---------------------------------------------------------------------------
# fetch_imports
# ---------------------------------------------------------------------------


class TestFetchImports:
    """Tests for ``pe_imports.fetch_imports`` using real adapter."""

    def test_returns_imports_from_adapter(self):
        adapter = _make_adapter(cmdj_map={"iij": KERNEL32_IMPORTS})
        result = pe_imports.fetch_imports(adapter)
        assert result == KERNEL32_IMPORTS

    def test_empty_imports_from_adapter(self):
        adapter = _make_adapter(cmdj_map={"iij": []})
        result = pe_imports.fetch_imports(adapter)
        assert result == []

    def test_none_adapter_returns_empty_list(self):
        result = pe_imports.fetch_imports(None)
        assert result == []

    def test_none_response_returns_empty_list(self):
        # cmdj returns None when the key is absent from the map
        adapter = _make_adapter(cmdj_map={})
        result = pe_imports.fetch_imports(adapter)
        assert result == []


# ---------------------------------------------------------------------------
# group_imports_by_library
# ---------------------------------------------------------------------------


class TestGroupImportsByLibrary:
    """Pure-data tests -- no adapter needed."""

    def test_basic_grouping(self):
        result = pe_imports.group_imports_by_library(MIXED_IMPORTS)
        assert "kernel32.dll" in result
        assert "user32.dll" in result
        assert len(result["kernel32.dll"]) == 2
        assert len(result["user32.dll"]) == 1

    def test_no_libname_key(self):
        imports = [{"name": "CreateFileA"}]
        result = pe_imports.group_imports_by_library(imports)
        assert result == {}

    def test_empty_libname(self):
        imports = [
            {"libname": "", "name": "CreateFileA"},
            {"libname": "  ", "name": "ReadFile"},
        ]
        result = pe_imports.group_imports_by_library(imports)
        assert result == {}

    def test_no_name_key(self):
        imports = [{"libname": "kernel32.dll"}]
        result = pe_imports.group_imports_by_library(imports)
        assert result == {}

    def test_empty_name(self):
        imports = [
            {"libname": "kernel32.dll", "name": ""},
            {"libname": "kernel32.dll", "name": "  "},
        ]
        result = pe_imports.group_imports_by_library(imports)
        assert result == {}

    def test_not_dict_entries(self):
        imports = ["not a dict", 123]
        result = pe_imports.group_imports_by_library(imports)
        assert result == {}

    def test_empty_list(self):
        result = pe_imports.group_imports_by_library([])
        assert result == {}

    def test_library_key_alternative(self):
        """The ``library`` key is used as a fallback for ``libname``."""
        imports = [{"library": "advapi32.dll", "name": "RegOpenKeyExA"}]
        result = pe_imports.group_imports_by_library(imports)
        assert "advapi32.dll" in result


# ---------------------------------------------------------------------------
# normalize_library_name
# ---------------------------------------------------------------------------


class TestNormalizeLibraryName:
    """Pure function -- no adapter needed."""

    EXTS = ["dll", "ocx", "sys"]

    def test_basic_dll(self):
        assert pe_imports.normalize_library_name("KERNEL32.DLL", self.EXTS) == "kernel32"

    def test_no_extension(self):
        assert pe_imports.normalize_library_name("kernel32", self.EXTS) == "kernel32"

    def test_non_matching_extension(self):
        assert pe_imports.normalize_library_name("kernel32.exe", self.EXTS) == "kernel32.exe"

    def test_bytes_input(self):
        assert pe_imports.normalize_library_name(b"KERNEL32.DLL", self.EXTS) == "kernel32"

    def test_ocx_extension(self):
        assert pe_imports.normalize_library_name("control.ocx", self.EXTS) == "control"

    def test_sys_extension(self):
        assert pe_imports.normalize_library_name("driver.sys", self.EXTS) == "driver"


# ---------------------------------------------------------------------------
# compute_imphash
# ---------------------------------------------------------------------------


class TestComputeImphash:
    """Pure function -- no adapter needed."""

    def test_basic(self):
        import_strings = ["kernel32.createfilea", "kernel32.readfile"]
        result = pe_imports.compute_imphash(import_strings)
        assert len(result) == 32
        assert result != ""

    def test_empty_returns_empty_string(self):
        assert pe_imports.compute_imphash([]) == ""

    def test_single_import(self):
        result = pe_imports.compute_imphash(["kernel32.createfilea"])
        assert len(result) == 32

    def test_deterministic(self):
        strings = ["kernel32.createfilea", "user32.messageboxa"]
        assert pe_imports.compute_imphash(strings) == pe_imports.compute_imphash(strings)


# ---------------------------------------------------------------------------
# calculate_imphash (end-to-end via adapter)
# ---------------------------------------------------------------------------


class TestCalculateImphash:
    """Integration through FakeR2 -> R2PipeAdapter -> calculate_imphash."""

    def test_basic(self):
        adapter = _make_adapter(cmdj_map={"iij": MIXED_IMPORTS})
        log, handler = _make_logger("test_calc_basic")
        result = pe_imports.calculate_imphash(adapter, log)
        assert len(result) == 32
        assert result != ""

    def test_no_imports_returns_empty(self):
        adapter = _make_adapter(cmdj_map={"iij": []})
        log, handler = _make_logger("test_calc_empty")
        result = pe_imports.calculate_imphash(adapter, log)
        assert result == ""
        # Logger should have recorded a debug message about no imports
        debug_msgs = [r.message for r in handler.records if r.levelno == logging.DEBUG]
        assert any("no imports" in m.lower() or "No imports" in m for m in debug_msgs)

    def test_none_imports_returns_empty(self):
        # iij not in the map -> cmdj returns None -> adapter returns []
        adapter = _make_adapter(cmdj_map={})
        log, handler = _make_logger("test_calc_none")
        result = pe_imports.calculate_imphash(adapter, log)
        assert result == ""

    def test_bytes_funcname(self):
        imports = [{"libname": "kernel32.dll", "name": b"CreateFileA"}]
        adapter = _make_adapter(cmdj_map={"iij": imports})
        log, _ = _make_logger("test_calc_bytes")
        result = pe_imports.calculate_imphash(adapter, log)
        assert len(result) == 32

    def test_exception_returns_empty_and_logs_error(self):
        """An adapter whose get_imports raises should be caught by calculate_imphash."""

        class _ExplodingAdapter:
            """Looks like a real adapter with get_imports, but raises."""

            def get_imports(self) -> list[dict[str, Any]]:
                raise RuntimeError("broken pipe")

        log, handler = _make_logger("test_calc_exc")
        result = pe_imports.calculate_imphash(_ExplodingAdapter(), log)
        assert result == ""
        error_msgs = [r.message for r in handler.records if r.levelno >= logging.ERROR]
        assert len(error_msgs) >= 1

    def test_broken_r2_returns_empty_gracefully(self):
        """An R2 backend that raises is silenced by the adapter layer."""

        class _BrokenR2:
            def cmd(self, command: str) -> str:
                raise RuntimeError("broken pipe")

            def cmdj(self, command: str) -> Any:
                raise RuntimeError("broken pipe")

        adapter = R2PipeAdapter(_BrokenR2())
        log, handler = _make_logger("test_calc_broken")
        result = pe_imports.calculate_imphash(adapter, log)
        # The adapter suppresses the error; calculate_imphash sees empty imports
        assert result == ""
        debug_msgs = [r.message for r in handler.records if r.levelno == logging.DEBUG]
        assert any("no imports" in m.lower() or "No imports" in m for m in debug_msgs)

    def test_imphash_deterministic_across_calls(self):
        adapter = _make_adapter(cmdj_map={"iij": MIXED_IMPORTS})
        log1, _ = _make_logger("test_det1")
        log2, _ = _make_logger("test_det2")
        h1 = pe_imports.calculate_imphash(adapter, log1)
        # Clear cache so second call goes through the same path
        adapter._cache.clear()
        h2 = pe_imports.calculate_imphash(adapter, log2)
        assert h1 == h2


# ---------------------------------------------------------------------------
# has_known_library_name
# ---------------------------------------------------------------------------


class TestHasKnownLibraryName:
    def test_valid_name(self):
        assert pe_imports.has_known_library_name("kernel32.dll") is True

    def test_none(self):
        assert pe_imports.has_known_library_name(None) is False

    def test_empty(self):
        assert pe_imports.has_known_library_name("") is False

    def test_whitespace(self):
        assert pe_imports.has_known_library_name("   ") is False

    def test_unknown(self):
        assert pe_imports.has_known_library_name("unknown") is False

    def test_bytes(self):
        assert pe_imports.has_known_library_name(b"kernel32.dll") is True
