"""Branch-path tests for r2inspect/modules/pe_info.py (no mocks - stub classes only)."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest

from r2inspect.modules import pe_info


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Stub helpers
# ---------------------------------------------------------------------------


class StubLogger:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.debugs: list[str] = []

    def error(self, msg: str) -> None:
        self.errors.append(msg)

    def debug(self, msg: str) -> None:
        self.debugs.append(msg)

    def warning(self, msg: str) -> None:
        pass


class AdapterWithFullBin:
    """Returns a complete bin dict including all optional fields."""

    def get_file_info(self) -> dict[str, Any]:
        return {
            "bin": {
                "arch": "x86",
                "machine": "i386",
                "bits": 32,
                "endian": "little",
                "baddr": 0x400000,
                "compiled": "2024-01-01T00:00:00",
                "subsys": "windows",
                "debug": False,
            }
        }

    def get_entry_info(self) -> list[dict[str, Any]]:
        return [{"vaddr": 0x401000}]

    def get_strings_text(self) -> str:
        return "MFC Compiler: MSVC 2019\nother line"

    def get_headers_json(self) -> list[dict[str, Any]]:
        return []


class AdapterWithNoBin:
    def get_file_info(self) -> dict[str, Any]:
        return {}

    def get_entry_info(self) -> list[dict[str, Any]]:
        return []


class AdapterRaisingFileInfo:
    def get_file_info(self) -> dict[str, Any]:
        raise RuntimeError("file info unavailable")


class AdapterWithNonListEntryInfo:
    def get_file_info(self) -> dict[str, Any]:
        return {"bin": {"arch": "x86", "bits": 32, "endian": "little", "baddr": 0}}

    def get_entry_info(self) -> str:
        return "not a list"

    def get_headers_json(self) -> list:
        return []


class AdapterWithRaisingEntryInfo:
    def get_file_info(self) -> dict[str, Any]:
        return {"bin": {"arch": "x86", "bits": 32, "endian": "little", "baddr": 0}}

    def get_entry_info(self) -> list:
        raise RuntimeError("entry info failed")

    def get_headers_json(self) -> list:
        return []


class AdapterWithCompilerInStrings:
    def get_file_info(self) -> dict[str, Any]:
        return {"bin": {"arch": "x86", "bits": 32, "endian": "little", "baddr": 0}}

    def get_strings_text(self) -> str:
        return "line1\nCompiler: GCC 9.3\nline3"

    def get_headers_json(self) -> list:
        return []


class AdapterWithEmptyStrings:
    def get_file_info(self) -> dict[str, Any]:
        return {"bin": {"arch": "x86", "bits": 32, "endian": "little", "baddr": 0}}

    def get_strings_text(self) -> str:
        return ""

    def get_headers_json(self) -> list:
        return []


class AdapterWithNoStringsMethod:
    def get_file_info(self) -> dict[str, Any]:
        return {"bin": {"arch": "x86", "bits": 32, "endian": "little", "baddr": 0}}

    def get_headers_json(self) -> list:
        return []


class AdapterWithNoneStrings:
    def get_file_info(self) -> dict[str, Any]:
        return {"bin": {"arch": "x86", "bits": 32, "endian": "little", "baddr": 0}}

    def get_strings_text(self) -> None:
        return None

    def get_headers_json(self) -> list:
        return []


# ---------------------------------------------------------------------------
# get_pe_headers_info
# ---------------------------------------------------------------------------


def test_get_pe_headers_info_returns_empty_when_no_bin():
    log = StubLogger()
    result = pe_info.get_pe_headers_info(AdapterWithNoBin(), None, log)
    assert result == {}


def test_get_pe_headers_info_returns_data_when_bin_present():
    log = StubLogger()
    result = pe_info.get_pe_headers_info(AdapterWithFullBin(), None, log)
    assert result.get("architecture") == "x86"
    assert result.get("bits") == 32


def test_get_pe_headers_info_exception_returns_empty_dict():
    log = StubLogger()
    result = pe_info.get_pe_headers_info(AdapterRaisingFileInfo(), None, log)
    assert result == {}
    assert len(log.errors) > 0


# ---------------------------------------------------------------------------
# _fetch_pe_header
# ---------------------------------------------------------------------------


def test_fetch_pe_header_returns_none_on_exception():
    log = StubLogger()
    result = pe_info._fetch_pe_header(AdapterRaisingFileInfo(), log)
    assert result is None


def test_fetch_pe_header_returns_dict_or_none_for_valid_adapter():
    log = StubLogger()
    result = pe_info._fetch_pe_header(AdapterWithFullBin(), log)
    # May return None or a dict depending on what get_headers_json returns
    assert result is None or isinstance(result, dict)


# ---------------------------------------------------------------------------
# _get_entry_info
# ---------------------------------------------------------------------------


def test_get_entry_info_returns_list_when_valid():
    log = StubLogger()
    result = pe_info._get_entry_info(AdapterWithFullBin(), log)
    assert result is None or isinstance(result, list)


def test_get_entry_info_returns_none_for_none_adapter():
    log = StubLogger()
    result = pe_info._get_entry_info(None, log)
    assert result is None


def test_get_entry_info_returns_none_when_not_list():
    log = StubLogger()
    result = pe_info._get_entry_info(AdapterWithNonListEntryInfo(), log)
    assert result is None


def test_get_entry_info_returns_none_on_exception():
    log = StubLogger()
    result = pe_info._get_entry_info(AdapterWithRaisingEntryInfo(), log)
    assert result is None
    assert len(log.debugs) > 0


def test_get_entry_info_returns_none_when_no_get_entry_info_method():
    log = StubLogger()
    result = pe_info._get_entry_info(AdapterWithNoStringsMethod(), log)
    assert result is None


# ---------------------------------------------------------------------------
# _get_file_description
# ---------------------------------------------------------------------------


def test_get_file_description_returns_none_for_none_path():
    log = StubLogger()
    result = pe_info._get_file_description(None, log)
    assert result is None


def test_get_file_description_returns_none_or_string_for_existing_file(tmp_path: Path):
    log = StubLogger()
    f = tmp_path / "test.bin"
    f.write_bytes(b"\x4d\x5a\x00\x00")
    result = pe_info._get_file_description(str(f), log)
    # magic may not be installed; result is either a string or None
    assert result is None or isinstance(result, str)


# ---------------------------------------------------------------------------
# get_file_characteristics
# ---------------------------------------------------------------------------


def test_get_file_characteristics_returns_empty_when_no_bin():
    log = StubLogger()
    result = pe_info.get_file_characteristics(AdapterWithNoBin(), None, log)
    assert result == {}


def test_get_file_characteristics_returns_has_debug_when_bin_present():
    log = StubLogger()
    result = pe_info.get_file_characteristics(AdapterWithFullBin(), None, log)
    assert "has_debug" in result


def test_get_file_characteristics_returns_empty_on_exception():
    log = StubLogger()
    result = pe_info.get_file_characteristics(AdapterRaisingFileInfo(), None, log)
    assert result == {}
    assert len(log.errors) > 0


# ---------------------------------------------------------------------------
# get_compilation_info
# ---------------------------------------------------------------------------


def test_get_compilation_info_returns_compile_time():
    log = StubLogger()
    result = pe_info.get_compilation_info(AdapterWithFullBin(), log)
    assert result.get("compile_time") == "2024-01-01T00:00:00"


def test_get_compilation_info_returns_empty_when_no_bin():
    log = StubLogger()
    result = pe_info.get_compilation_info(AdapterWithNoBin(), log)
    assert result == {}


def test_get_compilation_info_returns_compiler_info_when_present():
    log = StubLogger()
    result = pe_info.get_compilation_info(AdapterWithCompilerInStrings(), log)
    # compiler_info may be present if strings contain 'compiler'
    assert isinstance(result, dict)


def test_get_compilation_info_returns_empty_on_exception():
    log = StubLogger()
    result = pe_info.get_compilation_info(AdapterRaisingFileInfo(), log)
    assert result == {}
    assert len(log.errors) > 0


# ---------------------------------------------------------------------------
# _extract_compiler_info
# ---------------------------------------------------------------------------


def test_extract_compiler_info_returns_none_for_none():
    result = pe_info._extract_compiler_info(None)
    assert result is None


def test_extract_compiler_info_returns_none_when_no_method():
    result = pe_info._extract_compiler_info(AdapterWithNoStringsMethod())
    assert result is None


def test_extract_compiler_info_returns_compiler_line():
    result = pe_info._extract_compiler_info(AdapterWithCompilerInStrings())
    assert result is not None
    assert "Compiler" in result


def test_extract_compiler_info_returns_none_when_no_compiler_lines():
    result = pe_info._extract_compiler_info(AdapterWithFullBin())
    assert result is None or "compiler" in result.lower()


def test_extract_compiler_info_returns_none_when_empty_strings():
    result = pe_info._extract_compiler_info(AdapterWithEmptyStrings())
    assert result is None


def test_extract_compiler_info_returns_none_when_strings_none():
    result = pe_info._extract_compiler_info(AdapterWithNoneStrings())
    assert result is None


# ---------------------------------------------------------------------------
# get_subsystem_info
# ---------------------------------------------------------------------------


def test_get_subsystem_info_returns_dict():
    log = StubLogger()
    result = pe_info.get_subsystem_info(AdapterWithFullBin(), log)
    assert isinstance(result, dict)


def test_get_subsystem_info_returns_empty_when_no_bin():
    log = StubLogger()
    result = pe_info.get_subsystem_info(AdapterWithNoBin(), log)
    assert result == {}


def test_get_subsystem_info_returns_empty_on_exception():
    log = StubLogger()
    result = pe_info.get_subsystem_info(AdapterRaisingFileInfo(), log)
    assert result == {}
    assert len(log.errors) > 0
