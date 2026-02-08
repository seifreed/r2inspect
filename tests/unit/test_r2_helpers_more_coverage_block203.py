from __future__ import annotations

import time
from pathlib import Path

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.core.r2_session import R2Session
from r2inspect.utils import r2_helpers as h


@pytest.fixture
def r2_pe(samples_dir: Path):
    path = samples_dir / "hello_pe.exe"
    session = R2Session(str(path))
    r2 = session.open(file_size_mb=path.stat().st_size / (1024 * 1024))
    yield r2
    session.close()


@pytest.fixture
def r2_elf(samples_dir: Path):
    path = samples_dir / "hello_elf"
    session = R2Session(str(path))
    r2 = session.open(file_size_mb=path.stat().st_size / (1024 * 1024))
    yield r2
    session.close()


@pytest.fixture
def r2_macho(samples_dir: Path):
    path = samples_dir / "hello_macho"
    session = R2Session(str(path))
    r2 = session.open(file_size_mb=path.stat().st_size / (1024 * 1024))
    yield r2
    session.close()


def test_validate_r2_data_non_list_and_non_dict() -> None:
    assert h.validate_r2_data("nope", "list") == []
    assert h.validate_r2_data("nope", "dict") == {}
    assert h.validate_r2_data("noop", "other") == "noop"


def test_validate_helpers_clean_entities() -> None:
    assert h._validate_dict_data("nope") == {}
    assert h._validate_dict_data({"ok": True}) == {"ok": True}
    assert h._validate_list_data("nope") == []
    assert h._validate_list_data([{"name": "x"}]) == [{"name": "x"}]
    cleaned = h._clean_list_items([{"name": "a&nbsp;b&amp;c"}, "bad"])
    assert cleaned == [{"name": "a b&c"}]


@pytest.mark.requires_r2
def test_safe_cmdj_non_json_returns_default(r2_pe) -> None:
    assert h.safe_cmdj(r2_pe, "i", {}) == {}


@pytest.mark.requires_r2
def test_parse_pe_header_text(r2_pe) -> None:
    parsed = h.parse_pe_header_text(r2_pe)
    assert parsed is None or isinstance(parsed, dict)


def test_parse_pe_header_text_empty() -> None:
    class EmptyCmd:
        def cmd(self, command: str):
            return ""

    assert h.parse_pe_header_text(EmptyCmd()) is None


@pytest.mark.requires_r2
def test_get_pe_headers_fallback_on_non_pe(r2_elf) -> None:
    headers = h.get_pe_headers(r2_elf)
    assert headers is None or isinstance(headers, dict)


@pytest.mark.requires_r2
def test_get_elf_headers_and_macho_headers(r2_elf, r2_macho) -> None:
    elf_headers = h.get_elf_headers(r2_elf)
    assert elf_headers is not None
    macho_headers = h.get_macho_headers(r2_macho)
    assert macho_headers is not None


def test_parse_elf_headers_text() -> None:
    text = """\nType: PT_LOAD\nFlags: r-x\nOffset: 0x1000\nVaddr: 0x2000\nPaddr: 0x2000\nFilesz: 0x10\nMemsz: 0x20\n"""
    headers = h._parse_elf_headers_text(text)
    assert headers


def test_parse_section_and_key_value_pairs() -> None:
    result = {"nt_headers": {}, "file_header": {}, "optional_header": {}}
    section = h._parse_section_header("IMAGE_FILE_HEADERS", None)
    assert section == "file_header"
    h._parse_key_value_pair("Magic: 0x20B", result, section)
    assert result["file_header"]["Magic"] == 0x20B
    assert h._parse_section_header("IMAGE_NT_HEADERS", None) == "nt_headers"
    assert h._parse_section_header("IMAGE_OPTIONAL_HEADERS", None) == "optional_header"
    h._parse_key_value_pair("Bogus: 0xZZ", result, section)
    assert result["file_header"]["Bogus"] == "0xZZ"


def test_get_headers_json_variants() -> None:
    class HeadersObj:
        def __init__(self, value):
            self._value = value

        def get_headers_json(self):
            return self._value

    assert h._get_headers_json(HeadersObj({"key": "value"})) == [{"key": "value"}]
    assert h._get_headers_json(HeadersObj([{"a": 1}])) == [{"a": 1}]
    assert h._get_headers_json(HeadersObj(None)) is None

    class HeadersObjList:
        def get_headers_json(self):
            return [{"pe": {"optional_header": {"Magic": "0x20B"}}}, "noise"]

    headers = h._get_headers_json(HeadersObjList())
    assert headers is not None

    class HeadersObjBad:
        def get_headers_json(self):
            return "bad"

    assert h._get_headers_json(HeadersObjBad()) is None


def test_get_macho_headers_text_fallback() -> None:
    class MachoObj:
        def get_headers_json(self):
            return None

        def get_header_text(self):
            return "SOME HEADER"

        def cmd(self, command: str):
            return ""

    headers = h.get_macho_headers(MachoObj())
    assert headers == []


def test_get_pe_headers_with_custom_object() -> None:
    class PeObj:
        def get_headers_json(self):
            return [{"pe": {"optional_header": {"Magic": "0x10B"}}}, "noise"]

        def get_header_text(self):
            return ""

        def cmd(self, command: str):
            return ""

    headers = h.get_pe_headers(PeObj())
    assert headers is not None


def test_get_pe_headers_mapping() -> None:
    class PeObj:
        def get_headers_json(self):
            return [
                {"name": "Signature", "value": 1},
                {"name": "Magic", "value": 0x20B},
                {"name": "Other", "value": 7},
            ]

        def get_header_text(self):
            return ""

        def cmd(self, command: str):
            return ""

    headers = h.get_pe_headers(PeObj())
    assert headers["file_header"]["Signature"] == 1
    assert headers["optional_header"]["Magic"] == 0x20B
    assert headers["nt_headers"]["Other"] == 7


def test_get_pe_headers_fallback_to_text() -> None:
    class PeObj:
        def get_headers_json(self):
            return []

        def cmd(self, command: str):
            return "IMAGE_FILE_HEADERS\n\nMagic: 0x20B\n"

    headers = h.get_pe_headers(PeObj())
    assert headers is not None


def test_safe_cmdj_error_returns_default() -> None:
    class BadCmd:
        def cmd(self, command: str):
            raise RuntimeError("boom")

    assert h.safe_cmdj(BadCmd(), "i", {"ok": True}) == {"ok": True}


def test_safe_cmdj_timeout_returns_default() -> None:
    class SlowCmd:
        def cmd(self, command: str):
            time.sleep(0.05)
            return "{}"

    import os

    os.environ["R2INSPECT_CMD_TIMEOUT_SECONDS"] = "0.001"
    try:
        assert h.safe_cmdj(SlowCmd(), "ij", {"ok": True}) == {"ok": True}
    finally:
        os.environ.pop("R2INSPECT_CMD_TIMEOUT_SECONDS", None)


def test_safe_cmdj_timeout_invalid_env_uses_default() -> None:
    class SlowCmd:
        def cmd(self, command: str):
            time.sleep(0.01)
            return "{}"

    import os

    os.environ["R2INSPECT_CMD_TIMEOUT_SECONDS"] = "bad"
    try:
        assert h.safe_cmdj(SlowCmd(), "ij", {"ok": True}) == {}
    finally:
        os.environ.pop("R2INSPECT_CMD_TIMEOUT_SECONDS", None)


def test_select_json_policy_branches() -> None:
    assert h._select_json_policy("aa", {}) is h.R2_ANALYSIS_POLICY
    assert h._select_json_policy("ij", []) is h.R2_JSON_LIST_POLICY
    assert h._select_json_policy("ij", {}) is h.R2_JSON_DICT_POLICY


def test_safe_cmd_list_and_dict_and_text() -> None:
    class SimpleCmd:
        def cmd(self, command: str):
            return '{"a": 1}'

    class SimpleCmdList:
        def cmd(self, command: str):
            return '[{"a": 1}]'

    class SimpleCmdText:
        def cmd(self, command: str):
            return "ok"

    assert h.safe_cmd_dict(SimpleCmd(), "ij") == {"a": 1}
    assert h.safe_cmd_list(SimpleCmdList(), "iSj") == [{"a": 1}]
    assert h.safe_cmd(SimpleCmdText(), "i") == "ok"


def test_get_macho_headers_uses_header_text() -> None:
    class MachoObj:
        def get_headers_json(self):
            return None

        def get_header_text(self):
            return "cmd LC_SEGMENT_64\noffset 0x0"

        def cmd(self, command: str):
            return ""

    headers = h.get_macho_headers(MachoObj())
    assert headers is not None


def test_get_elf_headers_with_empty_header_text() -> None:
    class ElfObj:
        def get_headers_json(self):
            return None

        def get_header_text(self):
            return ""

        def cmd(self, command: str):
            return ""

    headers = h.get_elf_headers(ElfObj())
    assert headers == []


def test_get_elf_headers_parses_text() -> None:
    class ElfObj:
        def get_headers_json(self):
            return None

        def get_header_text(self):
            return "Type: PT_LOAD\nOffset: 0x0"

        def cmd(self, command: str):
            return ""

    headers = h.get_elf_headers(ElfObj())
    assert headers == [{"type": "PT_LOAD"}, {"offset": "0x0"}]


def test_get_macho_headers_from_dict() -> None:
    class MachoObj:
        def get_headers_json(self):
            return {"cmd": "LC_SEGMENT_64"}

        def get_header_text(self):
            return ""

        def cmd(self, command: str):
            return ""

    headers = h.get_macho_headers(MachoObj())
    assert headers == [{"cmd": "LC_SEGMENT_64"}]


def test_get_macho_headers_empty_text_fallback() -> None:
    class MachoObj:
        def get_headers_json(self):
            return None

        def get_header_text(self):
            return ""

        def cmd(self, command: str):
            return ""

    headers = h.get_macho_headers(MachoObj())
    assert headers == []


def test_parse_elf_headers_text_with_bad_parts() -> None:
    text = "Type PT_LOAD\nFlags\nOffset: 0x0"
    headers = h._parse_elf_headers_text(text)
    assert headers == [{"offset": "0x0"}]
