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


def test_get_headers_returns_empty_for_none_adapter() -> None:
    assert macho_security._get_headers(None) == []


def test_get_headers_handles_dict_adapter_returns_list() -> None:
    adapter = _Adapter(headers={"type": "mach-o"})
    assert macho_security._get_headers(adapter) == [{"type": "mach-o"}]


def test_get_headers_with_list_adapter() -> None:
    headers = [{"type": "x"}, {"type": "y"}]
    adapter = _Adapter(headers=headers)
    assert macho_security._get_headers(adapter) == headers


def test_get_headers_with_invalid_payload() -> None:
    adapter = _Adapter(headers="invalid")
    assert macho_security._get_headers(adapter) == []


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
