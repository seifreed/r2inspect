from __future__ import annotations

from r2inspect.utils import r2_helpers
from r2inspect.utils.retry_manager import get_retry_stats, reset_retry_stats


class DummyR2:
    def __init__(self, cmdj_result=None, cmd_result=""):
        self._cmdj_result = cmdj_result
        self._cmd_result = cmd_result

    def cmdj(self, command):
        return self._cmdj_result

    def cmd(self, command):
        return self._cmd_result


def test_validate_helpers_and_cleaning():
    assert r2_helpers.validate_r2_data({"a": 1}, "dict") == {"a": 1}
    assert r2_helpers.validate_r2_data([{"name": "A&amp;B"}], "list") == [{"name": "A&B"}]
    assert r2_helpers.validate_r2_data("x", "other") == "x"


def test_safe_cmd_and_select_policy():
    r2_json = DummyR2(cmdj_result={"ok": True}, cmd_result='{"ok": true}')
    assert r2_helpers.safe_cmdj(r2_json, "ij", default={}) == {"ok": True}
    assert r2_helpers.safe_cmd_list(r2_json, "ij") == []
    assert r2_helpers.safe_cmd_dict(r2_json, "ij") == {"ok": True}

    r2_text = DummyR2(cmdj_result=None, cmd_result="text")
    assert r2_helpers.safe_cmd(r2_text, "i") == "text"


def test_parse_pe_header_text_and_key_values():
    text = """
IMAGE_NT_HEADERS
Signature: 0x4550
IMAGE_FILE_HEADERS
NumberOfSections: 0x3
IMAGE_OPTIONAL_HEADERS
ImageBase: 0x400000
"""
    r2 = DummyR2(cmd_result=text)
    parsed = r2_helpers.parse_pe_header_text(r2)
    assert parsed["nt_headers"]["Signature"] == 0x4550
    assert parsed["file_header"]["NumberOfSections"] == 3
    assert parsed["optional_header"]["ImageBase"] == 0x400000


def test_get_pe_headers_from_json_list():
    headers_list = [
        {"name": "Signature", "value": 17744},
        {"name": "ImageBase", "value": 4194304},
        {"name": "CustomField", "value": 1},
    ]
    r2 = DummyR2(cmdj_result=headers_list, cmd_result=str(headers_list).replace("'", '"'))
    headers = r2_helpers.get_pe_headers(r2)
    assert headers["file_header"]["Signature"] == 17744
    assert headers["optional_header"]["ImageBase"] == 4194304
    assert headers["nt_headers"]["CustomField"] == 1


def test_get_elf_headers_json_and_text():
    r2_json = DummyR2(cmdj_result=[{"type": "LOAD"}], cmd_result='[{"type": "LOAD"}]')
    headers = r2_helpers.get_elf_headers(r2_json)
    assert headers == [{"type": "LOAD"}]

    text = "Type: LOAD\nOffset: 0x40\nBadLine"
    r2_text = DummyR2(cmdj_result=None, cmd_result=text)
    headers2 = r2_helpers.get_elf_headers(r2_text)
    assert headers2 == [{"type": "LOAD"}, {"offset": "0x40"}]


def test_get_macho_headers_paths():
    r2_json = DummyR2(cmdj_result={"cmd": "LC_SEGMENT"}, cmd_result='{"cmd": "LC_SEGMENT"}')
    headers = r2_helpers.get_macho_headers(r2_json)
    assert headers == [{"cmd": "LC_SEGMENT"}]

    r2_empty = DummyR2(cmdj_result=None, cmd_result="nope")
    headers2 = r2_helpers.get_macho_headers(r2_empty)
    assert headers2 == []


def test_retry_stats_wrappers():
    stats = get_retry_stats()
    assert isinstance(stats, dict)
    reset_retry_stats()
