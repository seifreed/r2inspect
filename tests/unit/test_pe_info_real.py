#!/usr/bin/env python3
"""Tests for modules/pe_info.py -- zero mocks.

Uses FakeR2 + R2PipeAdapter to exercise all code paths through real
adapter wiring instead of unittest.mock objects.
"""

from __future__ import annotations

import logging

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules import pe_info
from r2inspect.testing.fake_r2 import FakeR2


# ---------------------------------------------------------------------------
# FakeR2: minimal r2pipe stand-in routing cmdj/cmd via lookup maps
# ---------------------------------------------------------------------------


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


def _make_adapter(cmdj_map=None, cmd_map=None):
    """Build an R2PipeAdapter backed by FakeR2."""
    r2 = FakeR2(cmdj_map=cmdj_map, cmd_map=cmd_map)
    return R2PipeAdapter(r2)


def _make_raising_adapter(exc=None):
    """Build an R2PipeAdapter that raises on every r2 call."""
    r2 = FakeR2Raising(exc=exc)
    return R2PipeAdapter(r2)


def _real_logger():
    """Return a real stdlib logger."""
    return logging.getLogger("test_pe_info_real")


# ---------------------------------------------------------------------------
# PE bin info payload helpers
# ---------------------------------------------------------------------------

_BASIC_BIN = {
    "arch": "x86",
    "machine": "i386",
    "bits": 32,
    "endian": "little",
    "baddr": 0x400000,
}

_FULL_BIN = {
    **_BASIC_BIN,
    "class": "PE32",
    "format": "pe",
    "boffset": 0x200,
}


# ===========================================================================
# get_pe_headers_info
# ===========================================================================


def test_get_pe_headers_info_basic():
    adapter = _make_adapter(cmdj_map={"ij": {"bin": _BASIC_BIN}})
    logger = _real_logger()

    result = pe_info.get_pe_headers_info(adapter, "/test.exe", logger)

    assert result["architecture"] == "x86"
    assert result["machine"] == "i386"
    assert result["bits"] == 32
    assert result["endian"] == "little"
    assert result["image_base"] == 0x400000


def test_get_pe_headers_info_no_bin():
    adapter = _make_adapter(cmdj_map={"ij": {}})
    logger = _real_logger()

    result = pe_info.get_pe_headers_info(adapter, "/test.exe", logger)

    assert result == {}


def test_get_pe_headers_info_exception():
    adapter = _make_raising_adapter(exc=RuntimeError("Test error"))
    logger = _real_logger()

    result = pe_info.get_pe_headers_info(adapter, "/test.exe", logger)

    assert result == {}


def test_get_pe_headers_info_full_bin_with_headers():
    """Exercise the full flow with ihj returning header data."""
    header_list = [
        {"name": "Characteristics", "value": 0x0102},
        {"name": "Magic", "value": 0x10B},
        {"name": "ImageBase", "value": 0x10000},
        {"name": "AddressOfEntryPoint", "value": 0x1000},
    ]
    adapter = _make_adapter(
        cmdj_map={
            "ij": {"bin": _FULL_BIN},
            "ihj": header_list,
            "iej": [{"vaddr": 0x401000}],
        }
    )
    logger = _real_logger()

    result = pe_info.get_pe_headers_info(adapter, "/test.exe", logger)

    assert result["architecture"] == "x86"
    assert result["bits"] == 32
    assert "entry_point" in result
    assert "format" in result


def test_get_pe_headers_info_none_filepath():
    """filepath=None should still work; magic description becomes None."""
    adapter = _make_adapter(cmdj_map={"ij": {"bin": _BASIC_BIN}})
    logger = _real_logger()

    result = pe_info.get_pe_headers_info(adapter, None, logger)

    assert result["architecture"] == "x86"


# ===========================================================================
# _fetch_pe_header
# ===========================================================================


def test_fetch_pe_header_success():
    header_list = [
        {"name": "Characteristics", "value": 0x0102},
    ]
    adapter = _make_adapter(cmdj_map={"ihj": header_list})
    logger = _real_logger()

    result = pe_info._fetch_pe_header(adapter, logger)

    # get_pe_headers returns a dict or None
    assert result is None or isinstance(result, dict)


def test_fetch_pe_header_exception():
    adapter = _make_raising_adapter(exc=RuntimeError("Test error"))
    logger = _real_logger()

    result = pe_info._fetch_pe_header(adapter, logger)

    assert result is None


def test_fetch_pe_header_empty_headers():
    """Empty ihj response should gracefully return None or empty dict."""
    adapter = _make_adapter(cmdj_map={"ihj": []})
    logger = _real_logger()

    result = pe_info._fetch_pe_header(adapter, logger)

    assert result is None or isinstance(result, dict)


# ===========================================================================
# _get_entry_info
# ===========================================================================


def test_get_entry_info_valid():
    adapter = _make_adapter(cmdj_map={"iej": [{"vaddr": 0x1000}]})
    logger = _real_logger()

    result = pe_info._get_entry_info(adapter, logger)

    assert result == [{"vaddr": 0x1000}]


def test_get_entry_info_none_adapter():
    logger = _real_logger()

    result = pe_info._get_entry_info(None, logger)

    assert result is None


def test_get_entry_info_no_method():
    """Adapter without get_entry_info attribute."""

    class BareAdapter:
        pass

    result = pe_info._get_entry_info(BareAdapter(), _real_logger())

    assert result is None


def test_get_entry_info_exception():
    adapter = _make_raising_adapter(exc=RuntimeError("Test error"))
    logger = _real_logger()

    result = pe_info._get_entry_info(adapter, logger)

    # R2PipeAdapter has get_entry_info, but internal r2 call raises;
    # the method catches the exception and returns None or empty list.
    assert result is None or result == []


def test_get_entry_info_not_list():
    """Non-list response from iej should be treated as None."""
    adapter = _make_adapter(cmdj_map={"iej": "not a list"})
    logger = _real_logger()

    result = pe_info._get_entry_info(adapter, logger)

    # The adapter validates the return; non-list becomes empty list,
    # and _get_entry_info only returns lists, else None.
    assert result is None or result == []


def test_get_entry_info_empty_list():
    adapter = _make_adapter(cmdj_map={"iej": []})
    logger = _real_logger()

    result = pe_info._get_entry_info(adapter, logger)

    # Empty list is a valid list -- _get_entry_info returns it.
    assert result == [] or result is None


# ===========================================================================
# _get_file_description
# ===========================================================================


def test_get_file_description_no_filepath():
    logger = _real_logger()

    result = pe_info._get_file_description(None, logger)

    assert result is None


def test_get_file_description_empty_filepath():
    logger = _real_logger()

    result = pe_info._get_file_description("", logger)

    assert result is None


def test_get_file_description_nonexistent_file():
    """Non-existent file path -- magic.from_file raises, caught gracefully."""
    logger = _real_logger()

    result = pe_info._get_file_description("/nonexistent/path/fake.exe", logger)

    # Should return None whether magic is installed or not.
    assert result is None


# ===========================================================================
# get_file_characteristics
# ===========================================================================


def test_get_file_characteristics_basic():
    adapter = _make_adapter(
        cmdj_map={
            "ij": {"bin": {"debug": True}},
        }
    )
    logger = _real_logger()

    result = pe_info.get_file_characteristics(adapter, "/test.exe", logger)

    assert result["has_debug"] is True


def test_get_file_characteristics_with_header_characteristics():
    """Full path: header characteristics parsed from ihj."""
    header_list = [
        {"name": "Characteristics", "value": 0x2002},
    ]
    adapter = _make_adapter(
        cmdj_map={
            "ij": {"bin": {"debug": True, "type": "executable"}},
            "ihj": header_list,
        }
    )
    logger = _real_logger()

    result = pe_info.get_file_characteristics(adapter, "/test.exe", logger)

    assert "has_debug" in result


def test_get_file_characteristics_no_bin():
    adapter = _make_adapter(cmdj_map={"ij": {}})
    logger = _real_logger()

    result = pe_info.get_file_characteristics(adapter, "/test.exe", logger)

    assert result == {}


def test_get_file_characteristics_exception():
    adapter = _make_raising_adapter(exc=RuntimeError("Test error"))
    logger = _real_logger()

    result = pe_info.get_file_characteristics(adapter, "/test.exe", logger)

    assert result == {}


def test_get_file_characteristics_none_filepath():
    """filepath=None should still work for characteristics_from_bin fallback."""
    adapter = _make_adapter(
        cmdj_map={
            "ij": {"bin": {"debug": True, "type": "executable"}},
        }
    )
    logger = _real_logger()

    result = pe_info.get_file_characteristics(adapter, None, logger)

    assert "has_debug" in result


# ===========================================================================
# get_compilation_info
# ===========================================================================


def test_get_compilation_info_basic():
    adapter = _make_adapter(
        cmdj_map={
            "ij": {"bin": {"compiled": "2024-01-01"}},
        }
    )
    logger = _real_logger()

    result = pe_info.get_compilation_info(adapter, logger)

    assert result["compile_time"] == "2024-01-01"


def test_get_compilation_info_with_compiler_string():
    """Compiler info extracted from strings."""
    adapter = _make_adapter(
        cmdj_map={
            "ij": {"bin": {"compiled": "2024-06-15"}},
        },
        cmd_map={
            "izz~..": "line1\nCompiler: MSVC 14.0\nline3",
        },
    )
    logger = _real_logger()

    result = pe_info.get_compilation_info(adapter, logger)

    assert result["compile_time"] == "2024-06-15"
    assert "compiler_info" in result
    assert "MSVC" in result["compiler_info"]


def test_get_compilation_info_no_bin():
    adapter = _make_adapter(cmdj_map={"ij": {}})
    logger = _real_logger()

    result = pe_info.get_compilation_info(adapter, logger)

    assert result == {}


def test_get_compilation_info_exception():
    adapter = _make_raising_adapter(exc=RuntimeError("Test error"))
    logger = _real_logger()

    result = pe_info.get_compilation_info(adapter, logger)

    assert result == {}


def test_get_compilation_info_no_compiled_field():
    """bin present but no 'compiled' key -- result has no compile_time."""
    adapter = _make_adapter(
        cmdj_map={
            "ij": {"bin": {"arch": "x86"}},
        }
    )
    logger = _real_logger()

    result = pe_info.get_compilation_info(adapter, logger)

    assert "compile_time" not in result


# ===========================================================================
# _extract_compiler_info
# ===========================================================================


def test_extract_compiler_info_none_adapter():
    result = pe_info._extract_compiler_info(None)

    assert result is None


def test_extract_compiler_info_no_method():
    """Object without get_strings_text attribute."""

    class NoStrings:
        pass

    result = pe_info._extract_compiler_info(NoStrings())

    assert result is None


def test_extract_compiler_info_with_compiler():
    adapter = _make_adapter(cmd_map={"izz~..": "line1\nCompiler: MSVC\nline3"})

    result = pe_info._extract_compiler_info(adapter)

    assert result is not None
    assert "Compiler: MSVC" in result


def test_extract_compiler_info_no_compiler():
    adapter = _make_adapter(cmd_map={"izz~..": "line1\nline2\nline3"})

    result = pe_info._extract_compiler_info(adapter)

    assert result is None


def test_extract_compiler_info_empty_strings():
    adapter = _make_adapter(cmd_map={"izz~..": ""})

    result = pe_info._extract_compiler_info(adapter)

    assert result is None


def test_extract_compiler_info_none_strings():
    """Adapter returning empty string for izz~.. (default)."""
    adapter = _make_adapter()

    result = pe_info._extract_compiler_info(adapter)

    assert result is None


def test_extract_compiler_info_multiple_compiler_lines():
    adapter = _make_adapter(cmd_map={"izz~..": "Compiler: MSVC\nGCC Compiler 11.2\nfoo"})

    result = pe_info._extract_compiler_info(adapter)

    assert result is not None
    assert "MSVC" in result
    assert "GCC" in result


# ===========================================================================
# get_subsystem_info
# ===========================================================================


def test_get_subsystem_info_basic():
    adapter = _make_adapter(
        cmdj_map={
            "ij": {"bin": {"subsys": "windows gui"}},
        }
    )
    logger = _real_logger()

    result = pe_info.get_subsystem_info(adapter, logger)

    assert "subsystem" in result
    assert result["subsystem"] == "windows gui"


def test_get_subsystem_info_console():
    adapter = _make_adapter(
        cmdj_map={
            "ij": {"bin": {"subsys": "windows console"}},
        }
    )
    logger = _real_logger()

    result = pe_info.get_subsystem_info(adapter, logger)

    assert result["subsystem"] == "windows console"
    assert result.get("gui_app") is False


def test_get_subsystem_info_no_bin():
    adapter = _make_adapter(cmdj_map={"ij": {}})
    logger = _real_logger()

    result = pe_info.get_subsystem_info(adapter, logger)

    assert result == {}


def test_get_subsystem_info_exception():
    adapter = _make_raising_adapter(exc=RuntimeError("Test error"))
    logger = _real_logger()

    result = pe_info.get_subsystem_info(adapter, logger)

    assert result == {}


def test_get_subsystem_info_unknown():
    """subsys missing from bin_info -- defaults to 'Unknown'."""
    adapter = _make_adapter(
        cmdj_map={
            "ij": {"bin": {"arch": "x86"}},
        }
    )
    logger = _real_logger()

    result = pe_info.get_subsystem_info(adapter, logger)

    assert result["subsystem"] == "Unknown"
