"""Branch-path coverage tests for r2inspect/infrastructure/r2_helpers.py.

Targets lines:
  84-86   safe_cmdj._execute: raw not string / empty
  97-98   _run_cmd_with_timeout: exception in cmd
  105-108 _run_cmd_with_timeout: env timeout parsing
  115-116 _run_cmd_with_timeout: thread timeout
  128     _parse_address: empty address text
  131-132 _parse_address: valid / invalid int conversion
  138     _parse_size: single word returns None
  141-142 _parse_size: two parts hex / invalid
  151     _handle_search: /x prefix
  184     _handle_simple: aflj with address
  197-203 _handle_disasm branches
  211-218 _handle_bytes branches
  222     _handle_bytes: no address
  227     _handle_bytes: p8j no size
  237     _maybe_use_adapter: bytes path
  252     _cmdj_fallback: no cmd method
  354-379 parse_pe_header_text body
  384-390 _parse_section_header all branches
  397-409 _parse_key_value_pair
  434     get_pe_headers: fallback to text
  446     get_pe_headers: non-dict item skip
  523-531 get_elf_headers._get_headers body
  543-548 _get_headers_json
  552-563 _parse_elf_headers_text
  588-604 get_macho_headers branches
"""

from __future__ import annotations

import os
import time
from typing import Any

import pytest

from r2inspect.infrastructure.r2_helpers import (
    _cmd_fallback,
    _cmdj_fallback,
    _get_headers_json,
    _handle_bytes,
    _handle_disasm,
    _handle_search,
    _handle_simple,
    _maybe_use_adapter,
    _parse_address,
    _parse_elf_headers_text,
    _parse_key_value_pair,
    _parse_section_header,
    _parse_size,
    _run_cmd_with_timeout,
    _select_json_policy,
    cmd,
    cmd_list,
    cmdj,
    get_elf_headers,
    get_macho_headers,
    get_pe_headers,
    parse_pe_header_text,
    safe_cmd,
    safe_cmd_dict,
    safe_cmd_list,
    safe_cmdj,
    safe_cmdj_any,
)


# ---------------------------------------------------------------------------
# Minimal fake r2 / adapter helpers
# ---------------------------------------------------------------------------


class FakeR2:
    def __init__(self, cmd_result: str = "", json_result: Any = None):
        self._cmd_result = cmd_result
        self._json_result = json_result

    def cmd(self, command: str) -> str:
        return self._cmd_result

    def cmdj(self, command: str) -> Any:
        if self._json_result is None:
            raise RuntimeError("no json")
        return self._json_result


class ErrorR2:
    def cmd(self, command: str) -> str:
        raise RuntimeError("r2 exploded")

    def cmdj(self, command: str) -> Any:
        raise RuntimeError("r2 json exploded")


class NoCmdR2:
    """r2-like object that has no cmd method."""
    pass


# ---------------------------------------------------------------------------
# safe_cmdj  (lines 84-86): raw not-str or empty triggers return default
# ---------------------------------------------------------------------------


def test_safe_cmdj_empty_cmd_result_returns_default():
    r2 = FakeR2(cmd_result="")
    result = safe_cmdj(r2, "ij", {"fallback": True})
    assert result == {"fallback": True}


def test_safe_cmdj_whitespace_only_returns_default():
    r2 = FakeR2(cmd_result="   ")
    result = safe_cmdj(r2, "ij", [])
    assert result == []


def test_safe_cmdj_non_json_returns_default():
    r2 = FakeR2(cmd_result="this is not json")
    result = safe_cmdj(r2, "ij", {"default": 1})
    assert result == {"default": 1}


def test_safe_cmdj_valid_json_returns_parsed():
    import json
    data = {"format": "ELF", "arch": "x86_64"}
    r2 = FakeR2(cmd_result=json.dumps(data))
    result = safe_cmdj(r2, "ij", {})
    assert result == data


def test_safe_cmdj_exception_returns_default():
    r2 = ErrorR2()
    result = safe_cmdj(r2, "aflj", [])
    assert result == []


# ---------------------------------------------------------------------------
# _run_cmd_with_timeout  (lines 97-98): exception in _run
# ---------------------------------------------------------------------------


def test_run_cmd_with_timeout_exception_returns_default():
    r2 = ErrorR2()
    result = _run_cmd_with_timeout(r2, "ij", "default_val")
    assert result == "default_val"


# ---------------------------------------------------------------------------
# _run_cmd_with_timeout  (lines 105-108): env timeout parsing
# ---------------------------------------------------------------------------


def test_run_cmd_with_timeout_valid_env_timeout():
    r2 = FakeR2(cmd_result="ok")
    os.environ["R2INSPECT_CMD_TIMEOUT_SECONDS"] = "3.0"
    try:
        result = _run_cmd_with_timeout(r2, "i", "default")
    finally:
        del os.environ["R2INSPECT_CMD_TIMEOUT_SECONDS"]
    assert result == "ok"


def test_run_cmd_with_timeout_invalid_env_timeout_uses_constant():
    r2 = FakeR2(cmd_result="result_text")
    os.environ["R2INSPECT_CMD_TIMEOUT_SECONDS"] = "not_a_float"
    try:
        result = _run_cmd_with_timeout(r2, "i", "fallback")
    finally:
        del os.environ["R2INSPECT_CMD_TIMEOUT_SECONDS"]
    assert result == "result_text"


# ---------------------------------------------------------------------------
# _run_cmd_with_timeout  (lines 115-116): thread does not finish in time
# ---------------------------------------------------------------------------


def test_run_cmd_with_timeout_thread_times_out():
    class SlowR2:
        def cmd(self, command: str) -> str:
            time.sleep(10)
            return "never_returned"

    os.environ["R2INSPECT_CMD_TIMEOUT_SECONDS"] = "0.001"
    try:
        result = _run_cmd_with_timeout(SlowR2(), "i", "timed_out_default")
    finally:
        del os.environ["R2INSPECT_CMD_TIMEOUT_SECONDS"]
    assert result == "timed_out_default"


# ---------------------------------------------------------------------------
# _parse_address  (lines 128, 131-132)
# ---------------------------------------------------------------------------


def test_parse_address_no_at_sign():
    base, addr = _parse_address("aflj")
    assert base == "aflj"
    assert addr is None


def test_parse_address_empty_address_text_returns_none():
    base, addr = _parse_address("pdfj @")
    assert base == "pdfj"
    assert addr is None


def test_parse_address_hex_address():
    base, addr = _parse_address("pdfj @ 0x1000")
    assert base == "pdfj"
    assert addr == 0x1000


def test_parse_address_decimal_address():
    base, addr = _parse_address("pdj 10 @ 4096")
    assert addr == 4096


def test_parse_address_invalid_address_returns_none():
    base, addr = _parse_address("pdfj @ notanumber")
    assert base == "pdfj"
    assert addr is None


def test_parse_address_strips_whitespace():
    base, addr = _parse_address("  ij  @  0xff  ")
    assert base == "ij"
    assert addr == 0xFF


# ---------------------------------------------------------------------------
# _parse_size  (lines 138, 141-142)
# ---------------------------------------------------------------------------


def test_parse_size_single_word_returns_none():
    assert _parse_size("pdfj") is None


def test_parse_size_decimal():
    assert _parse_size("pd 20") == 20


def test_parse_size_hex():
    assert _parse_size("p8 0x10") == 16


def test_parse_size_invalid_number_returns_none():
    assert _parse_size("p8 badnum") is None


# ---------------------------------------------------------------------------
# _handle_search  (line 151 = /x branch)
# ---------------------------------------------------------------------------


class SearchAdapter:
    def search_hex_json(self, pattern: str) -> list:
        return [{"addr": 0x1000, "pattern": pattern}]

    def search_text(self, pattern: str) -> list:
        return [pattern]

    def search_hex(self, pattern: str) -> str:
        return f"hit {pattern}"


def test_handle_search_hex_json():
    result = _handle_search(SearchAdapter(), "/xj DEADBEEF")
    assert result[0]["pattern"] == "DEADBEEF"


def test_handle_search_text():
    result = _handle_search(SearchAdapter(), "/c my_string")
    assert result == ["my_string"]


def test_handle_search_hex():
    result = _handle_search(SearchAdapter(), "/x CAFEBABE")
    assert "CAFEBABE" in result


def test_handle_search_unknown_returns_none():
    result = _handle_search(SearchAdapter(), "ij")
    assert result is None


def test_handle_search_xj_no_method_returns_none():
    class NoMethod:
        pass

    assert _handle_search(NoMethod(), "/xj DEAD") is None


# ---------------------------------------------------------------------------
# _handle_simple  (line 184: aflj with address)
# ---------------------------------------------------------------------------


class SimpleAdapter:
    def get_functions(self) -> list:
        return [{"name": "main"}]

    def get_functions_at(self, addr: int) -> list:
        return [{"name": "at_func", "addr": addr}]

    def get_function_info(self, addr: int) -> dict:
        return {"name": "info_func", "addr": addr}

    def get_imports(self) -> list:
        return [{"name": "printf"}]

    def get_file_info(self) -> dict:
        return {"format": "PE"}

    def get_strings_filtered(self, command: str) -> list:
        return ["filtered"]

    def get_info_text(self) -> str:
        return "file info"

    def get_sections(self) -> list:
        return [{"name": ".text"}]

    def get_exports(self) -> list:
        return []

    def get_symbols(self) -> list:
        return []

    def get_entry_info(self) -> dict:
        return {}

    def get_headers_json(self) -> list:
        return []

    def get_pe_optional_header(self) -> dict:
        return {}

    def get_data_directories(self) -> list:
        return []

    def get_resources_info(self) -> list:
        return []

    def get_strings(self) -> list:
        return []

    def get_strings_basic(self) -> list:
        return []

    def analyze_all(self) -> str:
        return ""

    def get_dynamic_info_text(self) -> str:
        return ""

    def get_entropy_pattern(self) -> str:
        return ""

    def get_pe_version_info_text(self) -> str:
        return ""

    def get_pe_security_text(self) -> str:
        return ""

    def get_strings_text(self) -> str:
        return ""


def test_handle_simple_aflj_without_address():
    result = _handle_simple(SimpleAdapter(), "aflj", "aflj", None)
    assert result == [{"name": "main"}]


def test_handle_simple_aflj_with_address():
    result = _handle_simple(SimpleAdapter(), "aflj", "aflj @ 0x1000", 0x1000)
    assert result == [{"name": "at_func", "addr": 0x1000}]


def test_handle_simple_afij_with_address():
    result = _handle_simple(SimpleAdapter(), "afij @ 0x400", "afij @ 0x400", 0x400)
    assert result == {"name": "info_func", "addr": 0x400}


def test_handle_simple_iz_filtered():
    result = _handle_simple(SimpleAdapter(), "iz~hello", "iz~hello", None)
    assert result == ["filtered"]


def test_handle_simple_iij_mapped():
    result = _handle_simple(SimpleAdapter(), "iij", "iij", None)
    assert result == [{"name": "printf"}]


def test_handle_simple_ij_mapped():
    result = _handle_simple(SimpleAdapter(), "ij", "ij", None)
    assert result == {"format": "PE"}


def test_handle_simple_unknown_returns_none():
    result = _handle_simple(SimpleAdapter(), "xyz_cmd", "xyz_cmd", None)
    assert result is None


# ---------------------------------------------------------------------------
# _handle_disasm  (lines 197-203)
# ---------------------------------------------------------------------------


class DisasmAdapter:
    def get_disasm(self, address=None, size=None) -> dict:
        return {"ops": [], "address": address}

    def get_disasm_text(self, address=None, size=None) -> str:
        return "push rbp"

    def get_cfg(self, address=None) -> dict:
        return {"nodes": []}


def test_handle_disasm_pdfj():
    result = _handle_disasm(DisasmAdapter(), "pdfj", 0x1000)
    assert result["address"] == 0x1000


def test_handle_disasm_pdj():
    result = _handle_disasm(DisasmAdapter(), "pdj 10", None)
    assert isinstance(result, dict)


def test_handle_disasm_pi():
    result = _handle_disasm(DisasmAdapter(), "pi 5", 0x1000)
    assert "push" in result


def test_handle_disasm_agj():
    result = _handle_disasm(DisasmAdapter(), "agj", 0x1000)
    assert result == {"nodes": []}


def test_handle_disasm_no_method_returns_none():
    class Empty:
        pass

    assert _handle_disasm(Empty(), "pdfj", 0x1000) is None


def test_handle_disasm_unknown_prefix_returns_none():
    result = _handle_disasm(DisasmAdapter(), "xyz", 0x1000)
    assert result is None


# ---------------------------------------------------------------------------
# _handle_bytes  (lines 211-222)
# ---------------------------------------------------------------------------


class BytesAdapter:
    def read_bytes_list(self, address: int, size: int) -> list:
        return list(range(size))

    def read_bytes(self, address: int, size: int) -> bytes:
        return bytes(range(size))


def test_handle_bytes_no_address_returns_none():
    assert _handle_bytes(BytesAdapter(), "p8j 4", None) is None


def test_handle_bytes_p8j_with_size():
    result = _handle_bytes(BytesAdapter(), "p8j 4", 0x1000)
    assert result == [0, 1, 2, 3]


def test_handle_bytes_p8j_no_size_returns_none():
    result = _handle_bytes(BytesAdapter(), "p8j", 0x1000)
    assert result is None


def test_handle_bytes_p8_with_size():
    result = _handle_bytes(BytesAdapter(), "p8 4", 0x1000)
    assert isinstance(result, str)


def test_handle_bytes_p8_no_size_returns_none():
    result = _handle_bytes(BytesAdapter(), "p8", 0x1000)
    assert result is None


def test_handle_bytes_p8_empty_data_returns_empty_string():
    class EmptyBytesAdapter:
        def read_bytes(self, addr, size):
            return b""

    result = _handle_bytes(EmptyBytesAdapter(), "p8 4", 0x1000)
    assert result == ""


def test_handle_bytes_pxj_with_size():
    result = _handle_bytes(BytesAdapter(), "pxj 3", 0x2000)
    assert result == [0, 1, 2]


def test_handle_bytes_pxj_no_size_returns_none():
    result = _handle_bytes(BytesAdapter(), "pxj", 0x1000)
    assert result is None


def test_handle_bytes_unknown_prefix_returns_none():
    result = _handle_bytes(BytesAdapter(), "xyz", 0x1000)
    assert result is None


# ---------------------------------------------------------------------------
# _maybe_use_adapter  (line 237: bytes path)
# ---------------------------------------------------------------------------


def test_maybe_use_adapter_none_returns_none():
    assert _maybe_use_adapter(None, "aflj") is None


def test_maybe_use_adapter_search_path():
    result = _maybe_use_adapter(SearchAdapter(), "/xj DEAD")
    assert result is not None


def test_maybe_use_adapter_simple_path():
    result = _maybe_use_adapter(SimpleAdapter(), "ij")
    assert result == {"format": "PE"}


def test_maybe_use_adapter_disasm_path():
    result = _maybe_use_adapter(DisasmAdapter(), "pdfj @ 0x1000")
    assert result is not None


def test_maybe_use_adapter_bytes_path():
    result = _maybe_use_adapter(BytesAdapter(), "p8j 4 @ 0x1000")
    assert result == [0, 1, 2, 3]


def test_maybe_use_adapter_unknown_returns_none():
    class Empty:
        pass

    assert _maybe_use_adapter(Empty(), "unknown_cmd_xyz") is None


# ---------------------------------------------------------------------------
# _cmd_fallback / _cmdj_fallback  (line 252)
# ---------------------------------------------------------------------------


def test_cmd_fallback_none_r2_returns_empty():
    assert _cmd_fallback(None, "i") == ""


def test_cmd_fallback_no_cmd_attr_returns_empty():
    assert _cmd_fallback(NoCmdR2(), "i") == ""


def test_cmd_fallback_with_valid_r2():
    r2 = FakeR2(cmd_result="some text")
    result = _cmd_fallback(r2, "i")
    assert result == "some text"


def test_cmdj_fallback_none_r2_returns_default():
    result = _cmdj_fallback(None, "ij", {"d": True})
    assert result == {"d": True}


def test_cmdj_fallback_no_cmd_attr_returns_default():
    result = _cmdj_fallback(NoCmdR2(), "ij", [])
    assert result == []


def test_cmdj_fallback_with_valid_r2():
    import json
    r2 = FakeR2(cmd_result=json.dumps({"key": "val"}))
    result = _cmdj_fallback(r2, "ij", {})
    assert result == {"key": "val"}


# ---------------------------------------------------------------------------
# cmd / cmdj / cmd_list
# ---------------------------------------------------------------------------


def test_cmd_adapter_string_result():
    result = cmd(SimpleAdapter(), None, "i")
    assert isinstance(result, str)


def test_cmd_falls_back_when_adapter_returns_non_string():
    r2 = FakeR2(cmd_result="r2_output")
    result = cmd(SimpleAdapter(), r2, "ij")
    assert isinstance(result, str)


def test_cmdj_uses_adapter_when_not_none():
    result = cmdj(SimpleAdapter(), None, "ij", {})
    assert result == {"format": "PE"}


def test_cmdj_falls_back_to_r2_on_empty_adapter():
    import json

    class EmptyAdapter:
        pass

    r2 = FakeR2(cmd_result=json.dumps({"from": "r2"}))
    result = cmdj(EmptyAdapter(), r2, "ij", {})
    assert result == {"from": "r2"}


def test_cmd_list_returns_list():
    import json

    class EmptyAdapter:
        pass

    r2 = FakeR2(cmd_result=json.dumps([{"name": "func"}]))
    result = cmd_list(EmptyAdapter(), r2, "aflj")
    assert result == [{"name": "func"}]


def test_cmd_list_returns_empty_when_result_is_dict():
    result = cmd_list(SimpleAdapter(), None, "ij")
    assert result == []


# ---------------------------------------------------------------------------
# _select_json_policy
# ---------------------------------------------------------------------------


def test_select_json_policy_aaa_is_analysis():
    from r2inspect.error_handling.presets import R2_ANALYSIS_POLICY
    assert _select_json_policy("aaa", None) is R2_ANALYSIS_POLICY


def test_select_json_policy_list_default():
    from r2inspect.error_handling.presets import R2_JSON_LIST_POLICY
    assert _select_json_policy("iij", []) is R2_JSON_LIST_POLICY


def test_select_json_policy_dict_default():
    from r2inspect.error_handling.presets import R2_JSON_DICT_POLICY
    assert _select_json_policy("ij", None) is R2_JSON_DICT_POLICY


# ---------------------------------------------------------------------------
# _parse_section_header  (lines 384-390)
# ---------------------------------------------------------------------------


def test_parse_section_header_nt():
    assert _parse_section_header("IMAGE_NT_HEADERS", None) == "nt_headers"


def test_parse_section_header_file():
    assert _parse_section_header("IMAGE_FILE_HEADERS", None) == "file_header"


def test_parse_section_header_optional():
    assert _parse_section_header("IMAGE_OPTIONAL_HEADERS", None) == "optional_header"


def test_parse_section_header_unknown_preserves_current():
    assert _parse_section_header("SOME_OTHER_LINE", "file_header") == "file_header"


def test_parse_section_header_unknown_with_no_current():
    assert _parse_section_header("random stuff", None) is None


# ---------------------------------------------------------------------------
# _parse_key_value_pair  (lines 397-409)
# ---------------------------------------------------------------------------


def test_parse_key_value_pair_hex_value():
    result: dict = {"nt_headers": {}, "file_header": {}, "optional_header": {}}
    _parse_key_value_pair("Magic: 0x20b", result, "optional_header")
    assert result["optional_header"]["Magic"] == 0x20b


def test_parse_key_value_pair_string_value():
    result: dict = {"nt_headers": {}, "file_header": {}, "optional_header": {}}
    _parse_key_value_pair("Subsystem: Windows GUI", result, "optional_header")
    assert result["optional_header"]["Subsystem"] == "Windows GUI"


def test_parse_key_value_pair_invalid_hex_stays_string():
    result: dict = {"nt_headers": {}, "file_header": {}, "optional_header": {}}
    _parse_key_value_pair("Key: 0xZZZZ", result, "nt_headers")
    assert result["nt_headers"]["Key"] == "0xZZZZ"


def test_parse_key_value_pair_plain_integer_string():
    result: dict = {"nt_headers": {}, "file_header": {}, "optional_header": {}}
    _parse_key_value_pair("Count: 42", result, "file_header")
    assert result["file_header"]["Count"] == "42"


# ---------------------------------------------------------------------------
# _parse_elf_headers_text  (lines 552-563)
# ---------------------------------------------------------------------------


def test_parse_elf_headers_text_basic():
    text = "type: PT_LOAD\nflags: r-x\noffset: 0x1000\n"
    result = _parse_elf_headers_text(text)
    assert isinstance(result, list)
    assert len(result) >= 1


def test_parse_elf_headers_text_empty():
    assert _parse_elf_headers_text("") == []


def test_parse_elf_headers_text_skips_unknown_keys():
    text = "type: PT_LOAD\nunknown: value\n"
    result = _parse_elf_headers_text(text)
    assert any("type" in item for item in result)
    assert not any("unknown" in item for item in result)


def test_parse_elf_headers_text_skips_lines_without_colon():
    text = "no colon here\ntype: PT_LOAD\n"
    result = _parse_elf_headers_text(text)
    assert len(result) == 1


def test_parse_elf_headers_text_all_valid_keys():
    text = "type: PT_LOAD\nflags: rwx\noffset: 0\nvaddr: 0x400000\npaddr: 0x400000\nfilesz: 100\nmemsz: 100\n"
    result = _parse_elf_headers_text(text)
    keys_found = {list(item.keys())[0] for item in result}
    assert {"type", "flags", "offset", "vaddr", "paddr", "filesz", "memsz"} == keys_found


# ---------------------------------------------------------------------------
# parse_pe_header_text  (lines 354-379)
# ---------------------------------------------------------------------------


def test_parse_pe_header_text_empty_output_returns_none():
    class EmptyR2:
        def cmd(self, cmd: str) -> str:
            return ""

    result = parse_pe_header_text(EmptyR2())
    assert result is None


def test_parse_pe_header_text_parses_all_sections():
    pe_text = (
        "IMAGE_NT_HEADERS\n"
        "Signature: 0x4550\n"
        "IMAGE_FILE_HEADERS\n"
        "Machine: 0x8664\n"
        "NumberOfSections: 0x5\n"
        "IMAGE_OPTIONAL_HEADERS\n"
        "Magic: 0x20b\n"
        "ImageBase: 0x140000000\n"
    )

    class PETextR2:
        def cmd(self, cmd: str) -> str:
            return pe_text

    result = parse_pe_header_text(PETextR2())
    assert result is not None
    assert result["nt_headers"]["Signature"] == 0x4550
    assert result["file_header"]["Machine"] == 0x8664
    assert result["optional_header"]["Magic"] == 0x20b


def test_parse_pe_header_text_skips_blank_lines():
    pe_text = "IMAGE_FILE_HEADERS\n\nMachine: 0x14c\n\n"

    class R2:
        def cmd(self, cmd: str) -> str:
            return pe_text

    result = parse_pe_header_text(R2())
    assert result is not None
    assert result["file_header"]["Machine"] == 0x14c


def test_parse_pe_header_text_no_section_header_skips_kv():
    pe_text = "Machine: 0x8664\n"  # no section header before key-value

    class R2:
        def cmd(self, cmd: str) -> str:
            return pe_text

    result = parse_pe_header_text(R2())
    # current_section remains None so _parse_key_value_pair is not called
    assert result is not None


# ---------------------------------------------------------------------------
# _get_headers_json  (lines 543-548)
# ---------------------------------------------------------------------------


def test_get_headers_json_with_list_result():
    class R2WithHeaders:
        def get_headers_json(self):
            return [{"name": "Signature", "value": 0x4550}]

    result = _get_headers_json(R2WithHeaders())
    assert result == [{"name": "Signature", "value": 0x4550}]


def test_get_headers_json_with_dict_result_wraps_in_list():
    class R2WithDictHeaders:
        def get_headers_json(self):
            return {"name": "Magic", "value": 0x10b}

    result = _get_headers_json(R2WithDictHeaders())
    assert isinstance(result, list)
    assert len(result) == 1


def test_get_headers_json_empty_list_returns_none():
    class R2Empty:
        def get_headers_json(self):
            return []

    assert _get_headers_json(R2Empty()) is None


def test_get_headers_json_truthy_non_list_non_dict_returns_none():
    class R2StringHeaders:
        def get_headers_json(self):
            return "some string"

    result = _get_headers_json(R2StringHeaders())
    assert result is None


def test_get_headers_json_via_cmdj_fallback():
    import json
    r2 = FakeR2(cmd_result=json.dumps([{"name": "Signature", "value": 0x4550}]))
    result = _get_headers_json(r2)
    assert result == [{"name": "Signature", "value": 0x4550}]


# ---------------------------------------------------------------------------
# get_pe_headers  (lines 434, 446)
# ---------------------------------------------------------------------------


def test_get_pe_headers_with_file_header_fields():
    class R2Headers:
        def get_headers_json(self):
            return [
                {"name": "Machine", "value": 0x8664},
                {"name": "NumberOfSections", "value": 5},
            ]

    result = get_pe_headers(R2Headers())
    assert result is not None
    assert result["file_header"]["Machine"] == 0x8664


def test_get_pe_headers_with_optional_header_fields():
    class R2Headers:
        def get_headers_json(self):
            return [{"name": "ImageBase", "value": 0x140000000}]

    result = get_pe_headers(R2Headers())
    assert result is not None
    assert result["optional_header"]["ImageBase"] == 0x140000000


def test_get_pe_headers_unknown_field_goes_to_nt_headers():
    class R2Headers:
        def get_headers_json(self):
            return [{"name": "UnknownField", "value": 42}]

    result = get_pe_headers(R2Headers())
    assert result is not None
    assert result["nt_headers"]["UnknownField"] == 42


def test_get_pe_headers_skips_non_dict_items():
    class R2Headers:
        def get_headers_json(self):
            return ["not_a_dict", None, {"name": "Machine", "value": 0x8664}]

    result = get_pe_headers(R2Headers())
    assert result is not None
    assert result["file_header"]["Machine"] == 0x8664


def test_get_pe_headers_falls_back_to_text_when_empty_list():
    pe_text = "IMAGE_FILE_HEADERS\nMachine: 0x8664\n"

    class FallbackR2:
        def get_headers_json(self):
            return []

        def cmd(self, cmd: str) -> str:
            return pe_text

    result = get_pe_headers(FallbackR2())
    assert result is not None


def test_get_pe_headers_falls_back_to_text_when_not_list():
    pe_text = "IMAGE_OPTIONAL_HEADERS\nMagic: 0x20b\n"

    class R2:
        def cmd(self, cmd: str) -> str:
            return pe_text

    result = get_pe_headers(R2())
    assert result is not None


# ---------------------------------------------------------------------------
# get_elf_headers  (lines 523-531)
# ---------------------------------------------------------------------------


def test_get_elf_headers_with_json_method():
    class R2ELF:
        def get_headers_json(self):
            return [{"type": "PT_LOAD", "flags": "r-x"}]

    result = get_elf_headers(R2ELF())
    assert isinstance(result, list)
    assert len(result) > 0


def test_get_elf_headers_fallback_to_text():
    class R2ELFText:
        def get_headers_json(self):
            return []

        def get_header_text(self):
            return "type: PT_LOAD\nflags: r-x\n"

    result = get_elf_headers(R2ELFText())
    assert isinstance(result, list)


def test_get_elf_headers_empty_fallback():
    class EmptyR2:
        def cmd(self, cmd: str) -> str:
            return ""

    result = get_elf_headers(EmptyR2())
    assert result == [] or result is None


def test_get_elf_headers_dict_headers_wrapped():
    class R2DictHeaders:
        def get_headers_json(self):
            return {"type": "PT_LOAD"}

    result = get_elf_headers(R2DictHeaders())
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# get_macho_headers  (lines 588-604)
# ---------------------------------------------------------------------------


def test_get_macho_headers_with_list_headers():
    class R2MachO:
        def get_headers_json(self):
            return [{"cmd": "LC_SEGMENT_64", "cmdsize": 72}]

    result = get_macho_headers(R2MachO())
    assert isinstance(result, list)
    assert len(result) > 0


def test_get_macho_headers_dict_headers_returns_list():
    class R2MachODict:
        def get_headers_json(self):
            return {"cmd": "LC_DYLIB", "cmdsize": 56}

    result = get_macho_headers(R2MachODict())
    assert isinstance(result, list)
    assert len(result) == 1


def test_get_macho_headers_empty_json_falls_back_to_text():
    class R2MachOText:
        def get_headers_json(self):
            return None

        def get_header_text(self):
            return "LC_SEGMENT_64: offset=0x1000"

    result = get_macho_headers(R2MachOText())
    assert result == []


def test_get_macho_headers_no_data_returns_empty():
    class EmptyR2:
        def cmd(self, cmd: str) -> str:
            return ""

    result = get_macho_headers(EmptyR2())
    assert result == [] or result is None


def test_get_macho_headers_empty_text_returns_empty():
    class R2Empty:
        def get_headers_json(self):
            return None

        def get_header_text(self):
            return ""

    result = get_macho_headers(R2Empty())
    assert result == [] or result is None


# ---------------------------------------------------------------------------
# safe_cmd
# ---------------------------------------------------------------------------


def test_safe_cmd_returns_text():
    r2 = FakeR2(cmd_result="binary info")
    assert safe_cmd(r2, "i") == "binary info"


def test_safe_cmd_returns_default_on_exception():
    r2 = ErrorR2()
    assert safe_cmd(r2, "i", default="fallback") == "fallback"


# ---------------------------------------------------------------------------
# safe_cmd_list / safe_cmd_dict
# ---------------------------------------------------------------------------


def test_safe_cmd_list_valid_json():
    import json
    r2 = FakeR2(cmd_result=json.dumps([{"n": "f"}]))
    result = safe_cmd_list(r2, "aflj")
    assert result == [{"n": "f"}]


def test_safe_cmd_list_empty_on_error():
    assert safe_cmd_list(ErrorR2(), "aflj") == []


def test_safe_cmd_dict_valid_json():
    import json
    r2 = FakeR2(cmd_result=json.dumps({"format": "ELF"}))
    result = safe_cmd_dict(r2, "ij")
    assert result == {"format": "ELF"}


def test_safe_cmd_dict_empty_on_error():
    assert safe_cmd_dict(ErrorR2(), "ij") == {}


# ---------------------------------------------------------------------------
# safe_cmdj_any
# ---------------------------------------------------------------------------


def test_safe_cmdj_any_uses_cmdj():
    r2 = FakeR2(json_result={"from_cmdj": True})
    result = safe_cmdj_any(r2, "ij", {})
    assert result == {"from_cmdj": True}


def test_safe_cmdj_any_falls_back_when_cmdj_raises():
    import json
    r2 = FakeR2(cmd_result=json.dumps({"fallback": True}), json_result=None)
    result = safe_cmdj_any(r2, "ij", {})
    assert result == {"fallback": True}


def test_safe_cmdj_any_no_cmdj_method():
    import json

    class NoCmdjR2:
        def cmd(self, command: str) -> str:
            return '{"key": 99}'

    result = safe_cmdj_any(NoCmdjR2(), "ij", {})
    assert result == {"key": 99}
