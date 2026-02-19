#!/usr/bin/env python3
"""Branch-path tests for r2inspect/utils/file_type.py.

Uses hand-written stub adapters (no unittest.mock) so that the real
_maybe_use_adapter routing is exercised through the adapter protocol.

Missing lines targeted: 33-58 (is_pe_file), 76-98 (is_elf_file),
102-110 (_bin_info_has_pe), 113-117 (_bin_info_has_elf).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from r2inspect.utils.file_type import (
    _bin_info_has_elf,
    _bin_info_has_pe,
    is_elf_file,
    is_pe_file,
)


# ---------------------------------------------------------------------------
# Stub adapters (no mocks – plain Python classes)
# ---------------------------------------------------------------------------


class _StubBase:
    """Minimal stub that returns safe defaults for every adapter method."""

    def get_info_text(self) -> str:
        return ""

    def get_file_info(self) -> dict[str, Any]:
        return {}

    def get_imports(self) -> list:
        return []

    def get_sections(self) -> list:
        return []

    def get_strings(self) -> list:
        return []

    def get_strings_basic(self) -> list:
        return []

    def get_symbols(self) -> list:
        return []

    def get_functions(self) -> list:
        return []


class PEInfoTextAdapter(_StubBase):
    """Adapter that reports 'PE' via the info-text path."""

    def get_info_text(self) -> str:
        return "format: PE 32-bit executable"


class ELFInfoTextAdapter(_StubBase):
    """Adapter that reports 'ELF' via the info-text path."""

    def get_info_text(self) -> str:
        return "format: ELF 64-bit LSB executable"


class PEFileInfoAdapter(_StubBase):
    """Adapter that reports PE via the ij / get_file_info path."""

    def get_file_info(self) -> dict[str, Any]:
        return {"bin": {"format": "pe", "class": "PE32"}}


class ELFFileInfoAdapter(_StubBase):
    """Adapter that reports ELF via the ij / get_file_info path."""

    def get_file_info(self) -> dict[str, Any]:
        return {"bin": {"format": "elf", "class": "ELF64"}}


class UnknownFormatAdapter(_StubBase):
    """Adapter that never reports a known format."""

    def get_info_text(self) -> str:
        return "format: unknown binary"

    def get_file_info(self) -> dict[str, Any]:
        return {"bin": {"format": "unknown", "class": "unknown"}}


class PEClassOnlyAdapter(_StubBase):
    """Adapter whose ij output has PE only in the class field."""

    def get_file_info(self) -> dict[str, Any]:
        return {"bin": {"format": "coff", "class": "pe64"}}


class ELFClassOnlyAdapter(_StubBase):
    """Adapter whose ij output has ELF only in the class field."""

    def get_file_info(self) -> dict[str, Any]:
        return {"bin": {"format": "unknown", "type": "unknown", "class": "elf"}}


# ---------------------------------------------------------------------------
# is_pe_file – MZ magic detection (line 30-32)
# ---------------------------------------------------------------------------


def test_is_pe_file_mz_magic_detected(tmp_path: Path):
    pe_file = tmp_path / "sample.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 64)
    result = is_pe_file(str(pe_file), _StubBase(), None)
    assert result is True


# ---------------------------------------------------------------------------
# is_pe_file – info-text path (lines 36-45)
# ---------------------------------------------------------------------------


def test_is_pe_file_info_text_path(tmp_path: Path):
    f = tmp_path / "not_mz.bin"
    f.write_bytes(b"\x00" * 8)
    result = is_pe_file(str(f), PEInfoTextAdapter(), None)
    assert result is True


def test_is_pe_file_info_text_no_pe(tmp_path: Path):
    f = tmp_path / "elf.bin"
    f.write_bytes(b"\x7fELF" + b"\x00" * 8)
    result = is_pe_file(str(f), ELFInfoTextAdapter(), None)
    assert result is False


# ---------------------------------------------------------------------------
# is_pe_file – ij / get_file_info path (lines 47-54)
# ---------------------------------------------------------------------------


def test_is_pe_file_ij_format_field(tmp_path: Path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"\x00" * 8)
    result = is_pe_file(str(f), PEFileInfoAdapter(), None)
    assert result is True


def test_is_pe_file_ij_class_field(tmp_path: Path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"\x00" * 8)
    result = is_pe_file(str(f), PEClassOnlyAdapter(), None)
    assert result is True


def test_is_pe_file_no_pe_indicators(tmp_path: Path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"\x00" * 8)
    result = is_pe_file(str(f), UnknownFormatAdapter(), None)
    assert result is False


# ---------------------------------------------------------------------------
# is_pe_file – filepath=None falls through to adapter check (line 27)
# ---------------------------------------------------------------------------


def test_is_pe_file_none_filepath_uses_adapter():
    result = is_pe_file(None, PEInfoTextAdapter(), None)
    assert result is True


def test_is_pe_file_none_filepath_no_pe():
    result = is_pe_file(None, UnknownFormatAdapter(), None)
    assert result is False


# ---------------------------------------------------------------------------
# is_pe_file – custom logger used (line 24)
# ---------------------------------------------------------------------------


class _CapturingLogger:
    def __init__(self):
        self.messages: list[str] = []

    def debug(self, msg: str, *a, **kw) -> None:
        self.messages.append(str(msg))

    def error(self, msg: str, *a, **kw) -> None:
        self.messages.append(str(msg))


def test_is_pe_file_custom_logger_receives_debug(tmp_path: Path):
    pe_file = tmp_path / "sample.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 8)
    log = _CapturingLogger()
    result = is_pe_file(str(pe_file), _StubBase(), None, logger=log)
    assert result is True
    assert any("MZ" in m or "PE" in m or "pe" in m for m in log.messages)


# ---------------------------------------------------------------------------
# is_elf_file – info-text path (lines 73-77)
# ---------------------------------------------------------------------------


def test_is_elf_file_info_text_path(tmp_path: Path):
    f = tmp_path / "elf.bin"
    f.write_bytes(b"\x00" * 8)
    result = is_elf_file(str(f), ELFInfoTextAdapter(), None)
    assert result is True


def test_is_elf_file_info_text_no_elf(tmp_path: Path):
    f = tmp_path / "pe.bin"
    f.write_bytes(b"\x00" * 8)
    result = is_elf_file(str(f), PEInfoTextAdapter(), None)
    assert result is False


# ---------------------------------------------------------------------------
# is_elf_file – ij / get_file_info path (lines 79-87)
# ---------------------------------------------------------------------------


def test_is_elf_file_ij_format_field(tmp_path: Path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"\x00" * 8)
    result = is_elf_file(str(f), ELFFileInfoAdapter(), None)
    assert result is True


def test_is_elf_file_ij_class_field(tmp_path: Path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"\x00" * 8)
    result = is_elf_file(str(f), ELFClassOnlyAdapter(), None)
    assert result is True


# ---------------------------------------------------------------------------
# is_elf_file – ELF magic bytes path (lines 88-94)
# ---------------------------------------------------------------------------


def test_is_elf_file_magic_bytes(tmp_path: Path):
    elf_file = tmp_path / "real.elf"
    elf_file.write_bytes(b"\x7fELF" + b"\x00" * 8)
    result = is_elf_file(str(elf_file), UnknownFormatAdapter(), None)
    assert result is True


def test_is_elf_file_no_elf_indicators(tmp_path: Path):
    f = tmp_path / "pe.bin"
    f.write_bytes(b"MZ" + b"\x00" * 8)
    result = is_elf_file(str(f), UnknownFormatAdapter(), None)
    assert result is False


def test_is_elf_file_none_filepath(tmp_path: Path):
    # filepath=None skips the magic-bytes branch; adapter decides
    result = is_elf_file(None, ELFInfoTextAdapter(), None)
    assert result is True


# ---------------------------------------------------------------------------
# _bin_info_has_pe – lines 102-110
# ---------------------------------------------------------------------------


def test_bin_info_has_pe_format_contains_pe():
    assert _bin_info_has_pe({"format": "PE32", "class": "unknown"}) is True


def test_bin_info_has_pe_class_contains_pe():
    assert _bin_info_has_pe({"format": "coff", "class": "PE64"}) is True


def test_bin_info_has_pe_neither_field_contains_pe():
    assert _bin_info_has_pe({"format": "elf", "class": "ELF64"}) is False


def test_bin_info_has_pe_empty_dict():
    assert _bin_info_has_pe({}) is False


def test_bin_info_has_pe_case_insensitive_format():
    assert _bin_info_has_pe({"format": "pe", "class": ""}) is True


def test_bin_info_has_pe_case_insensitive_class():
    assert _bin_info_has_pe({"format": "", "class": "pe32"}) is True


# ---------------------------------------------------------------------------
# _bin_info_has_elf – lines 113-117
# ---------------------------------------------------------------------------


def test_bin_info_has_elf_format_field():
    assert _bin_info_has_elf({"format": "elf", "type": "x", "class": "x"}) is True


def test_bin_info_has_elf_type_field():
    assert _bin_info_has_elf({"format": "x", "type": "elf64", "class": "x"}) is True


def test_bin_info_has_elf_class_field():
    assert _bin_info_has_elf({"format": "x", "type": "x", "class": "ELF"}) is True


def test_bin_info_has_elf_no_match():
    assert _bin_info_has_elf({"format": "pe", "type": "EXEC", "class": "PE32"}) is False


def test_bin_info_has_elf_empty_dict():
    assert _bin_info_has_elf({}) is False
