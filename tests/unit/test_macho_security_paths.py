#!/usr/bin/env python3
"""Branch-path tests for r2inspect/modules/macho_security.py."""

from __future__ import annotations

import logging

from r2inspect.modules import macho_security


class _Adapter:
    def __init__(self, file_info=None, symbols=None, headers=None) -> None:
        self._file_info = file_info
        self._symbols = symbols
        self._headers = headers

    def get_file_info(self):
        return self._file_info

    def get_symbols(self):
        return self._symbols

    def get_headers_json(self):
        return self._headers


def test_get_load_commands_text_returns_empty_for_none_adapter() -> None:
    assert macho_security._get_load_commands_text(None) == ""


def test_get_load_commands_text_returns_command_output() -> None:
    class _CmdAdapter:
        def cmd(self, command: str) -> str:
            return "0x100 cmd LC_CODE_SIGNATURE" if command == "iH" else ""

    assert "LC_CODE_SIGNATURE" in macho_security._get_load_commands_text(_CmdAdapter())


def test_get_load_commands_text_non_str_returns_empty() -> None:
    class _BadCmd:
        def cmd(self, command: str) -> int:
            return 123

    assert macho_security._get_load_commands_text(_BadCmd()) == ""


def test_get_info_returns_none_for_empty_payload() -> None:
    adapter = _Adapter(file_info={})
    assert macho_security._get_info(adapter) is None


def test_get_info_returns_none_for_none_adapter() -> None:
    assert macho_security._get_info(None) is None


def test_get_info_with_payload() -> None:
    payload = {"format": "Mach-O"}
    adapter = _Adapter(file_info=payload)
    assert macho_security._get_info(adapter) == payload


def test_get_security_features_success_path() -> None:
    adapter = _Adapter(
        file_info={"machine": "arm64"},
        symbols=[{"name": "_main"}],
        headers=[{"type": "LC_VERSION_MIN_MACOSX"}],
    )
    logger = logging.getLogger("test_macho_security")

    assert macho_security.get_security_features(
        adapter,
        logger=logger,
    ) == {
        "pie": False,
        "nx": True,
        "stack_canary": False,
        "arc": False,
        "encrypted": False,
        "signed": False,
    }


def test_get_security_features_exception_path() -> None:
    class _BadAdapter:
        def get_file_info(self):
            raise RuntimeError("bad file info")

    logger = logging.getLogger("test_macho_security_exception")
    result = macho_security.get_security_features(_BadAdapter(), logger=logger)
    assert result == {
        "pie": False,
        "nx": False,
        "stack_canary": False,
        "arc": False,
        "encrypted": False,
        "signed": False,
    }
