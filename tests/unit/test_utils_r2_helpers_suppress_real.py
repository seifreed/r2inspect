from __future__ import annotations

import importlib
import os
import time
from pathlib import Path

import pytest

import r2inspect.utils as utils_pkg
from r2inspect.factory import create_inspector
from r2inspect.utils import r2_helpers
from r2inspect.utils.r2_suppress import (
    R2PipeErrorSuppressor,
    _parse_raw_result,
    _try_cmd_parse,
    silent_cmdj,
    suppress_r2pipe_errors,
)

pytestmark = pytest.mark.requires_r2


class _SlowR2:
    def cmd(self, _command: str) -> str:
        time.sleep(0.05)
        return '{"ok": true}'


class _BadR2:
    def cmdj(self, _command: str) -> None:
        raise OSError("boom")

    def cmd(self, _command: str) -> str:
        raise OSError("boom")


class _JsonErrorR2:
    def cmdj(self, _command: str) -> None:
        import json

        raise json.JSONDecodeError("bad", "doc", 0)

    def cmd(self, _command: str) -> str:
        return '{"ok": true}'


class _TextR2:
    def cmdj(self, _command: str) -> None:
        import json

        raise json.JSONDecodeError("bad", "doc", 0)

    def cmd(self, _command: str) -> str:
        return "raw text"


def test_utils_init_lazy_getattr() -> None:
    utils_mod = importlib.import_module("r2inspect.utils")
    assert callable(utils_mod.safe_cmdj)
    assert callable(utils_mod.safe_cmd)
    with pytest.raises(AttributeError):
        _ = utils_mod.__getattr__("missing")


def test_safe_cmdj_and_cmd_with_real_r2(tmp_path: Path) -> None:
    from r2inspect.config import Config

    config = Config(str(tmp_path / "r2inspect_r2_helpers.json"))
    with create_inspector(
        filename="samples/fixtures/hello_pe.exe", config=config, verbose=False
    ) as inspector:
        adapter = inspector.adapter
        assert r2_helpers.safe_cmdj(adapter, "ij", {}) is not None
        assert isinstance(r2_helpers.safe_cmd_list(adapter, "iSj"), list)
        assert isinstance(r2_helpers.safe_cmd_dict(adapter, "ij"), dict)
        assert isinstance(r2_helpers.safe_cmd(adapter, "i"), str)


def test_r2_helpers_timeout_and_parse_branches() -> None:
    old_timeout = os.environ.get("R2INSPECT_CMD_TIMEOUT_SECONDS")
    try:
        os.environ["R2INSPECT_CMD_TIMEOUT_SECONDS"] = "0.001"
        result = r2_helpers.safe_cmdj(_SlowR2(), "ij", default={})
        assert result == {}
    finally:
        if old_timeout is None:
            os.environ.pop("R2INSPECT_CMD_TIMEOUT_SECONDS", None)
        else:
            os.environ["R2INSPECT_CMD_TIMEOUT_SECONDS"] = old_timeout

    os.environ["R2INSPECT_CMD_TIMEOUT_SECONDS"] = "bad"
    try:
        result = r2_helpers.safe_cmd(_BadR2(), "i", default="fallback")
        assert result == "fallback"
    finally:
        if old_timeout is None:
            os.environ.pop("R2INSPECT_CMD_TIMEOUT_SECONDS", None)
        else:
            os.environ["R2INSPECT_CMD_TIMEOUT_SECONDS"] = old_timeout


def test_parse_pe_header_text_and_headers_fallbacks() -> None:
    class _TextR2:
        def cmd(self, _command: str) -> str:
            return "IMAGE_FILE_HEADERS\nNumberOfSections: 5"

    parsed = r2_helpers.parse_pe_header_text(_TextR2())
    assert parsed is not None
    assert parsed["file_header"]["NumberOfSections"] == "5"

    class _HeaderR2:
        def get_headers_json(self) -> list[dict[str, int]]:
            return [{"name": "Signature", "value": 0x4550}]

        def cmd(self, _command: str) -> str:
            return ""

    headers = r2_helpers.get_pe_headers(_HeaderR2())
    assert headers is not None
    assert headers["file_header"]["Signature"] == 0x4550


def test_r2_suppressor_and_silent_cmdj() -> None:
    with R2PipeErrorSuppressor():
        assert True

    assert silent_cmdj(None, "ij", default=None) is None
    assert silent_cmdj(_BadR2(), "ij", default={}) == {}

    assert silent_cmdj(_JsonErrorR2(), "ij", default={}) == {"ok": True}
    assert silent_cmdj(_TextR2(), "ij", default={}) == "raw text"

    with suppress_r2pipe_errors():
        assert silent_cmdj(_BadR2(), "ij", default={}) == {}


def test_r2_suppress_parse_edges() -> None:
    class _EmptyTextR2:
        def cmd(self, _command: str) -> str:
            return " "

    assert _try_cmd_parse(_EmptyTextR2(), "ij", default={}) == {}
    assert _parse_raw_result("{}") == {}
    assert _parse_raw_result("x") is None
