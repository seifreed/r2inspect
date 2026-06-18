"""Unit coverage for the extracted telfhash_analysis ELF-detection helpers."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from r2inspect.modules.telfhash_analysis import (
    _format_excludes_elf,
    _magic_rules_out_elf,
    is_elf_binary,
)

_LOGGER = logging.getLogger("test_telfhash_analysis_helpers")


def test_format_excludes_elf_handles_non_dict_and_format_variants() -> None:
    assert _format_excludes_elf("not-a-dict") is False
    assert _format_excludes_elf({"bin": "not-a-dict"}) is False
    assert _format_excludes_elf({"bin": {}}) is False
    assert _format_excludes_elf({"bin": {"format": "elf64", "class": "ELF64"}}) is False
    assert _format_excludes_elf({"bin": {"format": "pe", "class": "PE32"}}) is True


def test_magic_rules_out_elf_paths(tmp_path: Path) -> None:
    missing = tmp_path / "absent.bin"
    assert _magic_rules_out_elf(missing) is False

    not_elf = tmp_path / "mz.bin"
    not_elf.write_bytes(b"MZ\x00\x00")
    assert _magic_rules_out_elf(not_elf) is True

    elf = tmp_path / "elf.bin"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 8)
    assert _magic_rules_out_elf(elf) is False

    # A directory exists but cannot be read as bytes -> OSError -> rules out ELF.
    assert _magic_rules_out_elf(tmp_path) is True


class _Host:
    def __init__(self, filepath: str, *, info: Any, raise_cmdj: bool = False) -> None:
        self.adapter: Any = object()
        self.filepath = filepath
        self._info = info
        self._raise_cmdj = raise_cmdj

    def _cmdj(self, command: str, default: Any | None = None) -> Any:
        if self._raise_cmdj:
            raise RuntimeError("boom")
        return self._info

    def _has_elf_symbols(self, info_cmd: Any) -> bool:
        return True


def _never(*_args: Any, **_kwargs: Any) -> bool:
    return False


def _elf_file(tmp_path: Path) -> str:
    target = tmp_path / "sample.elf"
    target.write_bytes(b"\x7fELF" + b"\x00" * 100)
    return str(target)


def test_is_elf_binary_returns_false_when_no_adapter() -> None:
    host = _Host("/nonexistent", info={})
    host.adapter = None
    assert is_elf_binary(host, logger=_LOGGER, is_elf_file_fn=_never, is_pe_file_fn=_never) is False


def test_is_elf_binary_false_when_format_excludes_elf(tmp_path: Path) -> None:
    host = _Host(_elf_file(tmp_path), info={"bin": {"format": "pe", "class": "PE32"}})
    assert is_elf_binary(host, logger=_LOGGER, is_elf_file_fn=_never, is_pe_file_fn=_never) is False


def test_is_elf_binary_swallows_unexpected_errors(tmp_path: Path) -> None:
    host = _Host(_elf_file(tmp_path), info={}, raise_cmdj=True)
    assert is_elf_binary(host, logger=_LOGGER, is_elf_file_fn=_never, is_pe_file_fn=_never) is False


def test_is_elf_binary_returns_false_when_filepath_missing() -> None:
    host = _Host("/tmp/sample", info={})
    host.filepath = None
    assert is_elf_binary(host, logger=_LOGGER, is_elf_file_fn=_never, is_pe_file_fn=_never) is False
