import json
import os
import time

from r2inspect.utils import r2_helpers
from r2inspect.utils.r2_suppress import (
    R2PipeErrorSuppressor,
    _parse_raw_result,
    silent_cmdj,
    suppress_r2pipe_errors,
)


class DummyR2:
    def __init__(self, cmd_result: str = "", cmdj_result=None):
        self.cmd_result = cmd_result
        self.cmdj_result = cmdj_result
        self.headers_json = None
        self.header_text = ""

    def cmd(self, command: str):
        if command == "sleep":
            time.sleep(0.05)
        return self.cmd_result

    def cmdj(self, command: str):
        return self.cmdj_result

    def get_headers_json(self):
        return self.headers_json

    def get_header_text(self):
        return self.header_text


class DummyR2Raises(DummyR2):
    def cmdj(self, command: str):
        raise OSError("boom")

    def cmd(self, command: str):
        return "{bad json"


def test_r2_suppressor_and_parsing():
    with R2PipeErrorSuppressor():
        print("suppressed")

    assert _parse_raw_result('{"a": 1}') == {"a": 1}
    assert _parse_raw_result("okay") == "okay"
    assert _parse_raw_result(" ") is None

    assert silent_cmdj(None, "ij", default={"a": 1}) == {"a": 1}

    r2 = DummyR2(cmdj_result={"x": 1})
    assert silent_cmdj(r2, "ij", default=None) == {"x": 1}

    r2_bad = DummyR2Raises()
    assert silent_cmdj(r2_bad, "ij", default={"fallback": True}) == {"fallback": True}

    with suppress_r2pipe_errors():
        print("suppressed")


def test_r2_helpers_validate_and_safe_cmds(monkeypatch):
    assert r2_helpers.validate_r2_data({"a": 1}, "dict") == {"a": 1}
    assert r2_helpers.validate_r2_data([{"name": "a"}], "list") == [{"name": "a"}]
    assert r2_helpers.validate_r2_data("x", "dict") == {}
    assert r2_helpers.validate_r2_data("x", "list") == []

    data = [{"name": "a&amp;b"}, "bad"]
    cleaned = r2_helpers._clean_list_items(data)
    assert cleaned[0]["name"] == "a&b"

    r2 = DummyR2(cmd_result=json.dumps({"ok": True}))
    assert r2_helpers.safe_cmdj(r2, "ij", {}) == {"ok": True}

    r2_empty = DummyR2(cmd_result="")
    assert r2_helpers.safe_cmdj(r2_empty, "ij", {"d": 1}) == {"d": 1}

    r2_list = DummyR2(cmd_result="[]")
    assert r2_helpers.safe_cmd_list(r2_list, "iij") == []

    r2_bad = DummyR2(cmd_result="{bad")
    assert r2_helpers.safe_cmd_dict(r2_bad, "ij") == {}

    assert r2_helpers.safe_cmd(r2, "ij", default="") == json.dumps({"ok": True})

    monkeypatch.setenv("R2INSPECT_CMD_TIMEOUT_SECONDS", "0.01")
    r2_slow = DummyR2(cmd_result="done")
    assert r2_helpers._run_cmd_with_timeout(r2_slow, "sleep", default="timeout") == "timeout"

    monkeypatch.delenv("R2INSPECT_CMD_TIMEOUT_SECONDS", raising=False)


def test_pe_elf_macho_header_helpers():
    r2 = DummyR2()
    r2.headers_json = [
        {"name": "Signature", "value": 1},
        {"name": "Magic", "value": 2},
        {"name": "Custom", "value": 3},
    ]
    pe_headers = r2_helpers.get_pe_headers(r2)
    assert pe_headers is not None
    assert pe_headers["file_header"]["Signature"] == 1
    assert pe_headers["optional_header"]["Magic"] == 2
    assert pe_headers["nt_headers"]["Custom"] == 3

    r2.headers_json = None
    r2.cmd_result = "IMAGE_NT_HEADERS\nKey: 0x10\n"
    parsed = r2_helpers.parse_pe_header_text(r2)
    assert parsed is not None
    assert parsed["nt_headers"]["Key"] == 0x10

    r2.header_text = "type: LOAD\nflags: R\n"
    elf_headers = r2_helpers.get_elf_headers(r2)
    assert elf_headers == [{"type": "LOAD"}, {"flags": "R"}]

    r2.headers_json = {"cmd": "LC"}
    macho_headers = r2_helpers.get_macho_headers(r2)
    assert macho_headers == [{"cmd": "LC"}]

    r2.headers_json = None
    r2.header_text = ""
    assert r2_helpers.get_macho_headers(r2) == []
