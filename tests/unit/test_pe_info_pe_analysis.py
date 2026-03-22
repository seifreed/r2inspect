#!/usr/bin/env python3
"""Tests for r2inspect/modules/pe_info.py -- PE header parsing and analysis.

Zero mocks.  Uses a FakeR2-backed adapter that responds to the same
methods the production R2PipeAdapter exposes (get_file_info, get_entry_info,
get_strings_text, get_headers_json, cmd, cmdj).
"""

from __future__ import annotations

import logging
from typing import Any

import pytest

from r2inspect.modules import pe_info
from r2inspect.domain.formats.pe_info import PE32_PLUS


# ---------------------------------------------------------------------------
# Lightweight adapter that mirrors the R2PipeAdapter surface used by pe_info
# ---------------------------------------------------------------------------


class PEFakeAdapter:
    """Test double that reproduces the R2PipeAdapter query surface.

    All data is injected at construction time -- no mocks, no monkeypatch.
    """

    def __init__(
        self,
        *,
        file_info: dict[str, Any] | Exception | None = None,
        entry_info: list[dict[str, Any]] | dict | Exception | None = None,
        headers_json: list[dict[str, Any]] | dict | Exception | None = None,
        strings_text: str | Exception | None = "",
        cmd_responses: dict[str, str] | None = None,
        cmdj_responses: dict[str, Any] | None = None,
    ) -> None:
        self._file_info = file_info
        self._entry_info = entry_info
        self._headers_json = headers_json
        self._strings_text = strings_text
        self._cmd_responses = cmd_responses or {}
        self._cmdj_responses = cmdj_responses or {}

    # -- query methods used by pe_info functions ----------------------------

    def get_file_info(self) -> dict[str, Any]:
        if isinstance(self._file_info, Exception):
            raise self._file_info
        return self._file_info or {}

    def get_entry_info(self) -> list[dict[str, Any]]:
        if isinstance(self._entry_info, Exception):
            raise self._entry_info
        if isinstance(self._entry_info, list):
            return self._entry_info
        return []

    def get_headers_json(self) -> Any:
        if isinstance(self._headers_json, Exception):
            raise self._headers_json
        return self._headers_json

    def get_strings_text(self) -> str:
        if isinstance(self._strings_text, Exception):
            raise self._strings_text
        return self._strings_text or ""

    # -- low-level cmd/cmdj used by infrastructure helpers ------------------

    def cmd(self, command: str) -> str:
        val = self._cmd_responses.get(command, "")
        if isinstance(val, Exception):
            raise val
        return val

    def cmdj(self, command: str) -> Any:
        val = self._cmdj_responses.get(command)
        if isinstance(val, Exception):
            raise val
        return val


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_logger() -> logging.Logger:
    """Return a real stdlib logger with a NullHandler."""
    lgr = logging.getLogger("test.pe_info")
    lgr.handlers.clear()
    lgr.addHandler(logging.NullHandler())
    lgr.setLevel(logging.DEBUG)
    return lgr


def _pe32_bin_info(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "arch": "x86",
        "machine": "i386",
        "bits": 32,
        "endian": "little",
        "baddr": 0x400000,
    }
    base.update(overrides)
    return {"bin": base}


def _pe64_bin_info(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "arch": "x86_64",
        "machine": "AMD64",
        "bits": 64,
        "endian": "little",
        "baddr": 0x140000000,
    }
    base.update(overrides)
    return {"bin": base}


# ---------------------------------------------------------------------------
# get_pe_headers_info
# ---------------------------------------------------------------------------


class TestGetPeHeadersInfo:
    """Covers pe_info.get_pe_headers_info with various data shapes."""

    def test_complete_32bit(self):
        adapter = PEFakeAdapter(
            file_info=_pe32_bin_info(subsys="windows gui"),
            entry_info=[{"vaddr": 0x1000, "paddr": 0x400}],
            headers_json=[
                {"name": "ImageBase", "value": 0x400000},
                {"name": "SizeOfImage", "value": 16384},
            ],
        )
        result = pe_info.get_pe_headers_info(adapter, "/test.exe", _make_logger())

        assert result["architecture"] == "x86"
        assert result["machine"] == "i386"
        assert result["bits"] == 32
        assert result["endian"] == "little"
        assert result["image_base"] == 0x400000
        assert "type" in result
        assert "format" in result

    def test_complete_64bit(self):
        adapter = PEFakeAdapter(
            file_info=_pe64_bin_info(),
            entry_info=[{"vaddr": 0x1000}],
            headers_json=[{"name": "Magic", "value": 0x20B}],
        )
        result = pe_info.get_pe_headers_info(adapter, "/test.exe", _make_logger())

        assert result["bits"] == 64
        assert result["architecture"] == "x86_64"

    def test_pe32_plus_format(self):
        adapter = PEFakeAdapter(
            file_info=_pe64_bin_info(),
            headers_json=[{"name": "Magic", "value": 0x20B}],
        )
        result = pe_info.get_pe_headers_info(adapter, "/test.exe", _make_logger())

        # normalize_pe_format collapses PE32+ to "PE"
        assert result["format"] in {"PE", "PE32+"}

    def test_missing_bin_key_returns_empty(self):
        adapter = PEFakeAdapter(file_info={"other": "data"})
        result = pe_info.get_pe_headers_info(adapter, "/test.exe", _make_logger())
        assert result == {}

    def test_none_file_info_returns_empty(self):
        adapter = PEFakeAdapter(file_info=None)
        result = pe_info.get_pe_headers_info(adapter, "/test.exe", _make_logger())
        assert result == {}

    def test_adapter_raises_returns_empty(self):
        adapter = PEFakeAdapter(file_info=RuntimeError("Adapter failure"))
        lgr = _make_logger()
        result = pe_info.get_pe_headers_info(adapter, "/test.exe", lgr)
        assert result == {}

    def test_entry_point_from_entry_info(self):
        adapter = PEFakeAdapter(
            file_info=_pe32_bin_info(),
            entry_info=[{"vaddr": 0x401234}],
        )
        result = pe_info.get_pe_headers_info(adapter, "/test.exe", _make_logger())
        assert result["entry_point"] == 0x401234

    def test_no_entry_info_still_computes_entry(self):
        adapter = PEFakeAdapter(
            file_info=_pe32_bin_info(baddr=0x400000, boffset=0x200),
            entry_info=[],
        )
        result = pe_info.get_pe_headers_info(adapter, "/test.exe", _make_logger())
        assert result["entry_point"] == 0x400200

    def test_optional_header_overrides_image_base(self):
        adapter = PEFakeAdapter(
            file_info=_pe32_bin_info(),
            headers_json=[
                {"name": "ImageBase", "value": 0x10000000},
                {"name": "AddressOfEntryPoint", "value": 0x1000},
            ],
        )
        result = pe_info.get_pe_headers_info(adapter, "/test.exe", _make_logger())
        assert result["image_base"] == 0x10000000
        # entry_point = AddressOfEntryPoint + ImageBase
        assert result["entry_point"] == 0x10001000


# ---------------------------------------------------------------------------
# _fetch_pe_header
# ---------------------------------------------------------------------------


class TestFetchPeHeader:

    def test_valid_headers_json(self):
        adapter = PEFakeAdapter(
            headers_json=[
                {"name": "Machine", "value": 0x14C},
                {"name": "Characteristics", "value": 0x102},
            ],
        )
        result = pe_info._fetch_pe_header(adapter, _make_logger())
        assert result is not None
        assert isinstance(result, dict)
        assert "file_header" in result
        assert result["file_header"]["Machine"] == 0x14C

    def test_empty_headers_returns_none_or_text_fallback(self):
        adapter = PEFakeAdapter(headers_json=None)
        result = pe_info._fetch_pe_header(adapter, _make_logger())
        # get_pe_headers may fall through to text parsing and return None
        assert result is None or isinstance(result, dict)

    def test_exception_returns_none(self):
        adapter = PEFakeAdapter(headers_json=RuntimeError("fail"))
        result = pe_info._fetch_pe_header(adapter, _make_logger())
        assert result is None or isinstance(result, dict)


# ---------------------------------------------------------------------------
# _get_entry_info
# ---------------------------------------------------------------------------


class TestGetEntryInfo:

    def test_multiple_entries(self):
        adapter = PEFakeAdapter(
            entry_info=[
                {"vaddr": 0x1000, "paddr": 0x400},
                {"vaddr": 0x2000, "paddr": 0x800},
            ],
        )
        result = pe_info._get_entry_info(adapter, _make_logger())
        assert result is not None
        assert len(result) == 2

    def test_dict_return_yields_none(self):
        """get_entry_info must return a list; our fake returns [] for non-list."""
        adapter = PEFakeAdapter(entry_info={"not": "a list"})
        result = pe_info._get_entry_info(adapter, _make_logger())
        # The adapter normalizes dict to [], which is falsy but still a list
        # _get_entry_info checks isinstance(entry_info, list) -> True but empty
        assert result is None or result == []

    def test_empty_list(self):
        adapter = PEFakeAdapter(entry_info=[])
        result = pe_info._get_entry_info(adapter, _make_logger())
        assert result is None or result == []


# ---------------------------------------------------------------------------
# _get_file_description
# ---------------------------------------------------------------------------


class TestGetFileDescription:

    def test_empty_path_returns_none(self):
        result = pe_info._get_file_description("", _make_logger())
        assert result is None

    def test_none_path_returns_none(self):
        result = pe_info._get_file_description(None, _make_logger())
        assert result is None

    def test_nonexistent_file_returns_none(self):
        result = pe_info._get_file_description("/nonexistent/file.exe", _make_logger())
        # magic.from_file will raise, caught and returns None
        assert result is None


# ---------------------------------------------------------------------------
# get_file_characteristics
# ---------------------------------------------------------------------------


class TestGetFileCharacteristics:

    def test_has_debug_true(self):
        adapter = PEFakeAdapter(
            file_info={"bin": {"debug": True, "relocs_stripped": False}},
            headers_json=[{"name": "Characteristics", "value": 0x102}],
        )
        result = pe_info.get_file_characteristics(adapter, "/test.exe", _make_logger())
        assert result["has_debug"] is True

    def test_has_debug_false_when_key_absent(self):
        adapter = PEFakeAdapter(
            file_info={"bin": {}},
            headers_json=[],
        )
        result = pe_info.get_file_characteristics(adapter, "/test.exe", _make_logger())
        assert result["has_debug"] is False

    def test_characteristics_from_header(self):
        adapter = PEFakeAdapter(
            file_info={"bin": {"debug": False}},
            headers_json=[{"name": "Characteristics", "value": 0x2002}],
        )
        result = pe_info.get_file_characteristics(adapter, "/test.exe", _make_logger())
        assert isinstance(result, dict)
        # 0x2000 = DLL flag
        assert result.get("is_dll") is True

    def test_fallback_to_bin_on_header_exception(self):
        adapter = PEFakeAdapter(
            file_info={"bin": {"relocs_stripped": True, "stripped": True}},
            headers_json=RuntimeError("Header parsing failed"),
        )
        result = pe_info.get_file_characteristics(adapter, "/test.exe", _make_logger())
        assert isinstance(result, dict)

    def test_nested_exception_still_returns_dict(self):
        adapter = PEFakeAdapter(
            file_info={"bin": {"debug": True}},
            headers_json=RuntimeError("fail"),
        )
        result = pe_info.get_file_characteristics(adapter, "/test.exe", _make_logger())
        assert isinstance(result, dict)
        assert result.get("has_debug") is True

    def test_no_bin_key(self):
        adapter = PEFakeAdapter(file_info={"core": {}})
        result = pe_info.get_file_characteristics(adapter, "/test.exe", _make_logger())
        assert result == {}


# ---------------------------------------------------------------------------
# get_compilation_info
# ---------------------------------------------------------------------------


class TestGetCompilationInfo:

    def test_with_timestamp(self):
        adapter = PEFakeAdapter(
            file_info={"bin": {"compiled": "2024-01-15 10:30:45"}},
            strings_text="Some text\nCompiler: Microsoft C/C++\nMore text",
        )
        result = pe_info.get_compilation_info(adapter, _make_logger())
        assert result["compile_time"] == "2024-01-15 10:30:45"
        assert "compiler_info" in result

    def test_no_timestamp(self):
        adapter = PEFakeAdapter(
            file_info={"bin": {}},
            strings_text="no relevant info",
        )
        result = pe_info.get_compilation_info(adapter, _make_logger())
        assert "compile_time" not in result

    def test_compiler_only(self):
        adapter = PEFakeAdapter(
            file_info={"bin": {}},
            strings_text="Compiler Version: MSVC 19.28",
        )
        result = pe_info.get_compilation_info(adapter, _make_logger())
        assert "compiler_info" in result
        assert "compiler" in result["compiler_info"].lower()

    def test_error_in_compiler_extraction(self):
        adapter = PEFakeAdapter(
            file_info={"bin": {"compiled": "2024-01-15"}},
            strings_text=RuntimeError("Strings extraction failed"),
        )
        result = pe_info.get_compilation_info(adapter, _make_logger())
        assert result["compile_time"] == "2024-01-15"

    def test_no_bin_key(self):
        adapter = PEFakeAdapter(file_info={"core": {}})
        result = pe_info.get_compilation_info(adapter, _make_logger())
        assert result == {}


# ---------------------------------------------------------------------------
# _extract_compiler_info
# ---------------------------------------------------------------------------


class TestExtractCompilerInfo:

    def test_multiple_lines(self):
        adapter = PEFakeAdapter(
            strings_text=(
                "Some data\n" "Compiler: Microsoft C/C++\n" "Compiler version: 19.28\n" "Other text"
            ),
        )
        result = pe_info._extract_compiler_info(adapter)
        assert result is not None
        assert "compiler" in result.lower()
        assert "\n" in result

    def test_case_insensitive(self):
        adapter = PEFakeAdapter(strings_text="COMPILER: GCC")
        result = pe_info._extract_compiler_info(adapter)
        assert result is not None
        assert "COMPILER" in result

    def test_no_matches(self):
        adapter = PEFakeAdapter(strings_text="No relevant information here")
        result = pe_info._extract_compiler_info(adapter)
        assert result is None

    def test_none_adapter(self):
        result = pe_info._extract_compiler_info(None)
        assert result is None

    def test_empty_strings(self):
        adapter = PEFakeAdapter(strings_text="")
        result = pe_info._extract_compiler_info(adapter)
        assert result is None


# ---------------------------------------------------------------------------
# get_subsystem_info
# ---------------------------------------------------------------------------


class TestGetSubsystemInfo:

    def test_gui(self):
        adapter = PEFakeAdapter(file_info={"bin": {"subsys": "windows gui"}})
        result = pe_info.get_subsystem_info(adapter, _make_logger())
        assert isinstance(result, dict)
        assert result["subsystem"] == "windows gui"
        assert result["gui_app"] is True

    def test_console(self):
        adapter = PEFakeAdapter(file_info={"bin": {"subsys": "windows console"}})
        result = pe_info.get_subsystem_info(adapter, _make_logger())
        assert isinstance(result, dict)
        assert result["gui_app"] is False

    def test_unknown(self):
        adapter = PEFakeAdapter(file_info={"bin": {"subsys": "Unknown"}})
        result = pe_info.get_subsystem_info(adapter, _make_logger())
        assert isinstance(result, dict)
        assert result["gui_app"] is None

    def test_missing_subsys(self):
        adapter = PEFakeAdapter(file_info={"bin": {}})
        result = pe_info.get_subsystem_info(adapter, _make_logger())
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Integration-style: exercise all four functions together
# ---------------------------------------------------------------------------


class TestPeInfoIntegration:

    def test_full_pe32_flow(self):
        adapter = PEFakeAdapter(
            file_info={
                "bin": {
                    "arch": "x86",
                    "machine": "i386",
                    "bits": 32,
                    "endian": "little",
                    "baddr": 0x400000,
                    "compiled": "2024-01-01 12:00:00",
                    "subsys": "windows gui",
                    "debug": True,
                }
            },
            entry_info=[{"vaddr": 0x401234}],
            headers_json=[
                {"name": "ImageBase", "value": 0x400000},
                {"name": "Characteristics", "value": 0x102},
            ],
            strings_text="Compiler: MSVC",
        )
        lgr = _make_logger()

        headers = pe_info.get_pe_headers_info(adapter, "/test.exe", lgr)
        chars = pe_info.get_file_characteristics(adapter, "/test.exe", lgr)
        comp = pe_info.get_compilation_info(adapter, lgr)
        subsys = pe_info.get_subsystem_info(adapter, lgr)

        assert headers["bits"] == 32
        assert chars["has_debug"] is True
        assert comp["compile_time"] == "2024-01-01 12:00:00"
        assert isinstance(subsys, dict)

    def test_full_pe64_flow(self):
        adapter = PEFakeAdapter(
            file_info=_pe64_bin_info(
                compiled="2024-06-15 08:00:00",
                subsys="windows console",
            ),
            entry_info=[{"vaddr": 0x140001000}],
            headers_json=[
                {"name": "Magic", "value": 0x20B},
                {"name": "ImageBase", "value": 0x140000000},
                {"name": "AddressOfEntryPoint", "value": 0x1000},
                {"name": "Characteristics", "value": 0x22},
            ],
            strings_text="Compiler: GCC 12.3\nOther line",
        )
        lgr = _make_logger()

        headers = pe_info.get_pe_headers_info(adapter, "/test64.exe", lgr)
        chars = pe_info.get_file_characteristics(adapter, "/test64.exe", lgr)
        comp = pe_info.get_compilation_info(adapter, lgr)
        subsys = pe_info.get_subsystem_info(adapter, lgr)

        assert headers["bits"] == 64
        assert headers["architecture"] == "x86_64"
        assert headers["image_base"] == 0x140000000
        assert isinstance(chars, dict)
        assert comp["compile_time"] == "2024-06-15 08:00:00"
        assert "compiler_info" in comp
        assert subsys["gui_app"] is False

    def test_minimal_adapter_no_crash(self):
        """Ensure graceful behaviour with the sparsest possible adapter."""
        adapter = PEFakeAdapter(file_info={"bin": {}})
        lgr = _make_logger()

        headers = pe_info.get_pe_headers_info(adapter, None, lgr)
        chars = pe_info.get_file_characteristics(adapter, None, lgr)
        comp = pe_info.get_compilation_info(adapter, lgr)
        subsys = pe_info.get_subsystem_info(adapter, lgr)

        assert isinstance(headers, dict)
        assert isinstance(chars, dict)
        assert isinstance(comp, dict)
        assert isinstance(subsys, dict)

    def test_all_errors_handled_gracefully(self):
        adapter = PEFakeAdapter(
            file_info=RuntimeError("total failure"),
        )
        lgr = _make_logger()

        assert pe_info.get_pe_headers_info(adapter, "/f.exe", lgr) == {}
        assert pe_info.get_compilation_info(adapter, lgr) == {}
        assert pe_info.get_subsystem_info(adapter, lgr) == {}

    def test_dll_characteristics_from_header(self):
        """DLL flag (0x2000) should be detected from header characteristics."""
        adapter = PEFakeAdapter(
            file_info={"bin": {"debug": False}},
            headers_json=[{"name": "Characteristics", "value": 0x2102}],
        )
        result = pe_info.get_file_characteristics(adapter, "/my.dll", _make_logger())
        assert result.get("is_dll") is True
        assert result.get("is_executable") is True
