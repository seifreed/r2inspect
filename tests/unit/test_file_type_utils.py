"""Tests for r2inspect/infrastructure/file_type.py – NO mocks, NO monkeypatch."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import pytest

from r2inspect.infrastructure.file_type import (
    _bin_info_has_elf,
    _bin_info_has_pe,
    is_elf_file,
    is_pe_file,
)


# ---------------------------------------------------------------------------
# Lightweight stub adapter that delegates to real command dispatch
# ---------------------------------------------------------------------------


class _StubAdapter:
    """Adapter with controllable responses routed through real dispatch."""

    def __init__(
        self,
        info_text: str = "",
        file_info: dict[str, Any] | None = None,
        *,
        info_text_error: bool = False,
        file_info_error: bool = False,
    ) -> None:
        self._info_text = info_text
        self._file_info = file_info
        self._info_text_error = info_text_error
        self._file_info_error = file_info_error

    def get_info_text(self) -> str:
        if self._info_text_error:
            raise RuntimeError("Adapter info text error")
        return self._info_text

    def get_file_info(self) -> dict[str, Any] | None:
        if self._file_info_error:
            raise RuntimeError("Adapter file info error")
        return self._file_info


class _StubR2:
    """Minimal r2 stand-in – never actually called when adapter provides data."""

    def cmd(self, _command: str) -> str:
        return ""

    def cmdj(self, _command: str) -> dict[str, Any]:
        return {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_pe(tmp_path: Path, name: str = "sample.exe") -> Path:
    """Write a minimal file with an MZ header."""
    f = tmp_path / name
    f.write_bytes(b"MZ" + b"\x00" * 100)
    return f


def _write_elf(tmp_path: Path, name: str = "sample.elf") -> Path:
    """Write a minimal file with an ELF magic header."""
    f = tmp_path / name
    f.write_bytes(b"\x7fELF" + b"\x00" * 100)
    return f


def _write_raw(tmp_path: Path, content: bytes = b"\x00" * 100, name: str = "sample.bin") -> Path:
    f = tmp_path / name
    f.write_bytes(content)
    return f


# ===================================================================
# _bin_info_has_pe – pure dict helper, no IO at all
# ===================================================================


class TestBinInfoHasPe:
    def test_format_pe(self):
        assert _bin_info_has_pe({"format": "pe", "class": "PE32"}) is True

    def test_class_pe(self):
        assert _bin_info_has_pe({"format": "unknown", "class": "pe64"}) is True

    def test_case_insensitive(self):
        assert _bin_info_has_pe({"format": "PE32", "class": "UNKNOWN"}) is True

    def test_no_pe(self):
        assert _bin_info_has_pe({"format": "elf", "class": "ELF64"}) is False

    def test_empty_dict(self):
        assert _bin_info_has_pe({}) is False

    def test_format_contains_pe_substring(self):
        assert _bin_info_has_pe({"format": "xpey", "class": ""}) is True

    def test_class_contains_pe_substring(self):
        assert _bin_info_has_pe({"format": "none", "class": "dpe32"}) is True


# ===================================================================
# _bin_info_has_elf – pure dict helper, no IO at all
# ===================================================================


class TestBinInfoHasElf:
    def test_format_elf(self):
        assert _bin_info_has_elf({"format": "elf", "type": "EXEC", "class": "ELF64"}) is True

    def test_type_elf(self):
        assert _bin_info_has_elf({"format": "unknown", "type": "elf64", "class": "X"}) is True

    def test_class_elf(self):
        assert _bin_info_has_elf({"format": "unknown", "type": "EXEC", "class": "elf"}) is True

    def test_case_insensitive(self):
        assert _bin_info_has_elf({"format": "ELF64", "type": "X", "class": "X"}) is True

    def test_no_elf(self):
        assert _bin_info_has_elf({"format": "pe", "type": "EXEC", "class": "PE32"}) is False

    def test_empty_dict(self):
        assert _bin_info_has_elf({}) is False


# ===================================================================
# is_pe_file – real file IO, stub adapter
# ===================================================================


class TestIsPeFile:
    """Exercise is_pe_file with real temp files and stub adapter objects."""

    def test_mz_header_detected(self, tmp_path: Path):
        pe = _write_pe(tmp_path)
        adapter = _StubAdapter(info_text="", file_info={})
        result = is_pe_file(str(pe), adapter, _StubR2())
        assert result is True

    def test_mz_header_takes_priority(self, tmp_path: Path):
        """MZ magic is checked first – adapter never queried for other fields."""
        pe = _write_pe(tmp_path)
        adapter = _StubAdapter(info_text="", file_info={"bin": {"format": "elf"}})
        assert is_pe_file(str(pe), adapter, _StubR2()) is True

    def test_info_text_pe_keyword(self, tmp_path: Path):
        raw = _write_raw(tmp_path)
        adapter = _StubAdapter(info_text="format: PE 32-bit executable")
        assert is_pe_file(str(raw), adapter, _StubR2()) is True

    def test_info_text_pe_case_insensitive(self, tmp_path: Path):
        raw = _write_raw(tmp_path)
        adapter = _StubAdapter(info_text="format: pe executable")
        assert is_pe_file(str(raw), adapter, _StubR2()) is True

    def test_file_info_format_pe(self, tmp_path: Path):
        raw = _write_raw(tmp_path)
        adapter = _StubAdapter(
            info_text="",
            file_info={"bin": {"format": "pe", "class": "PE32"}},
        )
        assert is_pe_file(str(raw), adapter, _StubR2()) is True

    def test_file_info_class_pe(self, tmp_path: Path):
        raw = _write_raw(tmp_path)
        adapter = _StubAdapter(
            info_text="",
            file_info={"bin": {"format": "unknown", "class": "PE64"}},
        )
        assert is_pe_file(str(raw), adapter, _StubR2()) is True

    def test_no_pe_indicators_returns_false(self, tmp_path: Path):
        elf = _write_elf(tmp_path)
        adapter = _StubAdapter(
            info_text="format: ELF 64-bit",
            file_info={"bin": {"format": "elf", "class": "ELF64"}},
        )
        assert is_pe_file(str(elf), adapter, _StubR2()) is False

    def test_none_filepath_with_pe_info_text(self):
        adapter = _StubAdapter(info_text="format: PE 32-bit")
        assert is_pe_file(None, adapter, _StubR2()) is True

    def test_none_filepath_no_pe(self):
        adapter = _StubAdapter(info_text="format: ELF")
        assert is_pe_file(None, adapter, _StubR2()) is False

    def test_adapter_info_text_error_falls_through(self, tmp_path: Path):
        raw = _write_raw(tmp_path)
        adapter = _StubAdapter(
            info_text_error=True,
            file_info={"bin": {"format": "pe"}},
        )
        assert is_pe_file(str(raw), adapter, _StubR2()) is True

    def test_adapter_all_errors_returns_false(self, tmp_path: Path):
        raw = _write_raw(tmp_path)
        adapter = _StubAdapter(info_text_error=True, file_info_error=True)
        assert is_pe_file(str(raw), adapter, _StubR2()) is False

    def test_nonexistent_file_falls_through(self):
        adapter = _StubAdapter(info_text="format: PE 32-bit")
        assert is_pe_file("/nonexistent/path.exe", adapter, _StubR2()) is True

    def test_nonexistent_file_no_pe_info(self):
        adapter = _StubAdapter(info_text="", file_info={})
        assert is_pe_file("/nonexistent/path.exe", adapter, _StubR2()) is False

    def test_empty_file(self, tmp_path: Path):
        empty = _write_raw(tmp_path, content=b"", name="empty.bin")
        adapter = _StubAdapter(info_text="", file_info={})
        assert is_pe_file(str(empty), adapter, _StubR2()) is False

    def test_one_byte_file(self, tmp_path: Path):
        tiny = _write_raw(tmp_path, content=b"M", name="tiny.bin")
        adapter = _StubAdapter(info_text="", file_info={})
        assert is_pe_file(str(tiny), adapter, _StubR2()) is False

    def test_custom_logger(self, tmp_path: Path):
        pe = _write_pe(tmp_path)
        adapter = _StubAdapter()
        custom_logger = logging.getLogger("test.pe_logger")
        custom_logger.setLevel(logging.DEBUG)
        result = is_pe_file(str(pe), adapter, _StubR2(), logger=custom_logger)
        assert result is True

    @pytest.mark.skipif(
        getattr(os, "getuid", lambda: -1)() == 0,
        reason="Root bypasses permission checks; os.getuid unavailable on Windows",
    )
    def test_permission_error_falls_through(self, tmp_path: Path):
        pe = _write_pe(tmp_path)
        os.chmod(pe, 0o000)
        try:
            adapter = _StubAdapter(info_text="", file_info={})
            result = is_pe_file(str(pe), adapter, _StubR2())
            assert result is False
        finally:
            os.chmod(pe, 0o644)

    def test_file_info_without_bin_key(self, tmp_path: Path):
        raw = _write_raw(tmp_path)
        adapter = _StubAdapter(info_text="", file_info={"core": {"file": "test"}})
        assert is_pe_file(str(raw), adapter, _StubR2()) is False

    def test_file_info_none(self, tmp_path: Path):
        raw = _write_raw(tmp_path)
        adapter = _StubAdapter(info_text="", file_info=None)
        assert is_pe_file(str(raw), adapter, _StubR2()) is False


# ===================================================================
# is_elf_file – real file IO, stub adapter
# ===================================================================


class TestIsElfFile:
    """Exercise is_elf_file with real temp files and stub adapter objects."""

    def test_info_text_elf_keyword(self, tmp_path: Path):
        raw = _write_raw(tmp_path)
        adapter = _StubAdapter(info_text="format: ELF 64-bit LSB executable")
        assert is_elf_file(str(raw), adapter, _StubR2()) is True

    def test_info_text_elf_case_insensitive(self, tmp_path: Path):
        raw = _write_raw(tmp_path)
        adapter = _StubAdapter(info_text="format: elf executable")
        assert is_elf_file(str(raw), adapter, _StubR2()) is True

    def test_file_info_format_elf(self, tmp_path: Path):
        raw = _write_raw(tmp_path)
        adapter = _StubAdapter(
            info_text="",
            file_info={"bin": {"format": "elf", "type": "EXEC"}},
        )
        assert is_elf_file(str(raw), adapter, _StubR2()) is True

    def test_file_info_type_elf(self, tmp_path: Path):
        raw = _write_raw(tmp_path)
        adapter = _StubAdapter(
            info_text="",
            file_info={"bin": {"format": "unknown", "type": "elf64"}},
        )
        assert is_elf_file(str(raw), adapter, _StubR2()) is True

    def test_file_info_class_elf(self, tmp_path: Path):
        raw = _write_raw(tmp_path)
        adapter = _StubAdapter(
            info_text="",
            file_info={"bin": {"format": "x", "type": "x", "class": "ELF64"}},
        )
        assert is_elf_file(str(raw), adapter, _StubR2()) is True

    def test_magic_bytes_fallback(self, tmp_path: Path):
        elf = _write_elf(tmp_path)
        adapter = _StubAdapter(info_text="", file_info={"bin": {"format": "unknown"}})
        assert is_elf_file(str(elf), adapter, _StubR2()) is True

    def test_no_elf_indicators(self, tmp_path: Path):
        pe = _write_pe(tmp_path)
        adapter = _StubAdapter(
            info_text="format: PE 32-bit",
            file_info={"bin": {"format": "pe", "class": "PE32"}},
        )
        assert is_elf_file(str(pe), adapter, _StubR2()) is False

    def test_none_filepath_with_elf_info(self):
        adapter = _StubAdapter(info_text="format: ELF 64-bit")
        assert is_elf_file(None, adapter, _StubR2()) is True

    def test_none_filepath_no_elf(self):
        adapter = _StubAdapter(info_text="format: PE 32-bit", file_info={})
        assert is_elf_file(None, adapter, _StubR2()) is False

    def test_adapter_info_text_error_falls_through(self, tmp_path: Path):
        elf = _write_elf(tmp_path)
        adapter = _StubAdapter(
            info_text_error=True,
            file_info={"bin": {"format": "unknown"}},
        )
        # info text errors -> falls through to file_info, then to magic bytes
        assert is_elf_file(str(elf), adapter, _StubR2()) is True

    def test_adapter_all_errors_with_elf_magic(self, tmp_path: Path):
        elf = _write_elf(tmp_path)
        adapter = _StubAdapter(info_text_error=True, file_info_error=True)
        assert is_elf_file(str(elf), adapter, _StubR2()) is True

    def test_adapter_all_errors_no_elf_magic(self, tmp_path: Path):
        raw = _write_raw(tmp_path)
        adapter = _StubAdapter(info_text_error=True, file_info_error=True)
        assert is_elf_file(str(raw), adapter, _StubR2()) is False

    def test_nonexistent_file_with_elf_info(self):
        adapter = _StubAdapter(info_text="format: ELF 64-bit")
        assert is_elf_file("/nonexistent/path.elf", adapter, _StubR2()) is True

    def test_nonexistent_file_no_elf_info(self):
        adapter = _StubAdapter(info_text="", file_info={})
        assert is_elf_file("/nonexistent/path.elf", adapter, _StubR2()) is False

    def test_empty_file(self, tmp_path: Path):
        empty = _write_raw(tmp_path, content=b"", name="empty.bin")
        adapter = _StubAdapter(info_text="", file_info={})
        assert is_elf_file(str(empty), adapter, _StubR2()) is False

    def test_partial_elf_magic(self, tmp_path: Path):
        """Only 3 of the 4 ELF magic bytes present."""
        partial = _write_raw(tmp_path, content=b"\x7fEL" + b"\x00" * 100, name="partial.bin")
        adapter = _StubAdapter(info_text="", file_info={})
        assert is_elf_file(str(partial), adapter, _StubR2()) is False

    def test_custom_logger(self, tmp_path: Path):
        elf = _write_elf(tmp_path)
        adapter = _StubAdapter(info_text="", file_info={"bin": {"format": "unknown"}})
        custom_logger = logging.getLogger("test.elf_logger")
        custom_logger.setLevel(logging.DEBUG)
        result = is_elf_file(str(elf), adapter, _StubR2(), logger=custom_logger)
        assert result is True

    @pytest.mark.skipif(
        getattr(os, "getuid", lambda: -1)() == 0,
        reason="Root bypasses permission checks; os.getuid unavailable on Windows",
    )
    def test_permission_error_falls_through(self, tmp_path: Path):
        elf = _write_elf(tmp_path)
        os.chmod(elf, 0o000)
        try:
            adapter = _StubAdapter(info_text="", file_info={})
            result = is_elf_file(str(elf), adapter, _StubR2())
            assert result is False
        finally:
            os.chmod(elf, 0o644)

    def test_file_info_without_bin_key(self, tmp_path: Path):
        raw = _write_raw(tmp_path)
        adapter = _StubAdapter(info_text="", file_info={"core": {"file": "test"}})
        assert is_elf_file(str(raw), adapter, _StubR2()) is False

    def test_file_info_none(self, tmp_path: Path):
        raw = _write_raw(tmp_path)
        adapter = _StubAdapter(info_text="", file_info=None)
        assert is_elf_file(str(raw), adapter, _StubR2()) is False


# ===================================================================
# Edge cases combining PE / ELF checks on the same file
# ===================================================================


class TestCrossFormatEdgeCases:
    def test_pe_file_is_not_elf(self, tmp_path: Path):
        pe = _write_pe(tmp_path)
        adapter = _StubAdapter(info_text="", file_info={})
        assert is_pe_file(str(pe), adapter, _StubR2()) is True
        assert is_elf_file(str(pe), adapter, _StubR2()) is False

    def test_elf_file_is_not_pe(self, tmp_path: Path):
        elf = _write_elf(tmp_path)
        adapter = _StubAdapter(info_text="", file_info={})
        assert is_elf_file(str(elf), adapter, _StubR2()) is True
        assert is_pe_file(str(elf), adapter, _StubR2()) is False

    def test_random_binary_is_neither(self, tmp_path: Path):
        raw = _write_raw(tmp_path, content=b"\xca\xfe\xba\xbe" + b"\x00" * 100)
        adapter = _StubAdapter(info_text="", file_info={})
        assert is_pe_file(str(raw), adapter, _StubR2()) is False
        assert is_elf_file(str(raw), adapter, _StubR2()) is False
