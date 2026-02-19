#!/usr/bin/env python3
"""Coverage tests for r2inspect/infrastructure/r2_helpers.py"""
from __future__ import annotations

from typing import Any

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
# _parse_address
# ---------------------------------------------------------------------------

def test_parse_address_no_at_sign():
    base, addr = _parse_address("aflj")
    assert base == "aflj"
    assert addr is None


def test_parse_address_with_hex_address():
    base, addr = _parse_address("pdfj @ 0x1000")
    assert base == "pdfj"
    assert addr == 0x1000


def test_parse_address_with_decimal_address():
    base, addr = _parse_address("pdfj @ 4096")
    assert base == "pdfj"
    assert addr == 4096


def test_parse_address_with_empty_address_part():
    base, addr = _parse_address("pdfj @")
    assert base == "pdfj"
    assert addr is None


def test_parse_address_with_invalid_address():
    base, addr = _parse_address("pdfj @ notanumber")
    assert base == "pdfj"
    assert addr is None


def test_parse_address_preserves_whitespace_stripping():
    base, addr = _parse_address("  aflj  @  0x400  ")
    assert base == "aflj"
    assert addr == 0x400


# ---------------------------------------------------------------------------
# _parse_size
# ---------------------------------------------------------------------------

def test_parse_size_single_word_returns_none():
    assert _parse_size("aflj") is None


def test_parse_size_two_parts_decimal():
    assert _parse_size("pd 10") == 10


def test_parse_size_two_parts_hex():
    assert _parse_size("p8 0x20") == 32


def test_parse_size_invalid_number_returns_none():
    assert _parse_size("p8 notnum") is None


# ---------------------------------------------------------------------------
# _parse_section_header
# ---------------------------------------------------------------------------

def test_parse_section_header_nt_headers():
    assert _parse_section_header("IMAGE_NT_HEADERS", None) == "nt_headers"


def test_parse_section_header_file_headers():
    assert _parse_section_header("IMAGE_FILE_HEADERS", None) == "file_header"


def test_parse_section_header_optional_headers():
    assert _parse_section_header("IMAGE_OPTIONAL_HEADERS", None) == "optional_header"


def test_parse_section_header_unknown_returns_current():
    assert _parse_section_header("SOME_OTHER_LINE", "nt_headers") == "nt_headers"
    assert _parse_section_header("random", None) is None


# ---------------------------------------------------------------------------
# _parse_key_value_pair
# ---------------------------------------------------------------------------

def test_parse_key_value_pair_hex_value():
    result = {"nt_headers": {}, "file_header": {}, "optional_header": {}}
    _parse_key_value_pair("Magic: 0x10b", result, "optional_header")
    assert result["optional_header"]["Magic"] == 0x10b


def test_parse_key_value_pair_string_value():
    result = {"nt_headers": {}, "file_header": {}, "optional_header": {}}
    _parse_key_value_pair("Subsystem: Windows GUI", result, "optional_header")
    assert result["optional_header"]["Subsystem"] == "Windows GUI"


def test_parse_key_value_pair_invalid_hex_stays_string():
    result = {"nt_headers": {}, "file_header": {}, "optional_header": {}}
    _parse_key_value_pair("Key: 0xZZZZ", result, "nt_headers")
    assert result["nt_headers"]["Key"] == "0xZZZZ"


# ---------------------------------------------------------------------------
# _parse_elf_headers_text
# ---------------------------------------------------------------------------

def test_parse_elf_headers_text_returns_list():
    text = "type: PT_LOAD\nflags: r-x\noffset: 0x1000\nvaddr: 0x400000\n"
    result = _parse_elf_headers_text(text)
    assert isinstance(result, list)
    assert len(result) > 0


def test_parse_elf_headers_text_empty_input():
    result = _parse_elf_headers_text("")
    assert result == []


def test_parse_elf_headers_text_skips_unknown_keys():
    text = "type: PT_LOAD\nunknown_key: value\n"
    result = _parse_elf_headers_text(text)
    assert any("type" in item for item in result)
    assert not any("unknown_key" in item for item in result)


def test_parse_elf_headers_text_skips_no_colon_lines():
    text = "no colon here\ntype: PT_LOAD\n"
    result = _parse_elf_headers_text(text)
    assert len(result) == 1


# ---------------------------------------------------------------------------
# _select_json_policy
# ---------------------------------------------------------------------------

def test_select_json_policy_analysis_command_returns_analysis_policy():
    from r2inspect.error_handling.presets import R2_ANALYSIS_POLICY
    policy = _select_json_policy("aaa", None)
    assert policy is R2_ANALYSIS_POLICY


def test_select_json_policy_list_default_returns_list_policy():
    from r2inspect.error_handling.presets import R2_JSON_LIST_POLICY
    policy = _select_json_policy("iij", [])
    assert policy is R2_JSON_LIST_POLICY


def test_select_json_policy_dict_default_returns_dict_policy():
    from r2inspect.error_handling.presets import R2_JSON_DICT_POLICY
    policy = _select_json_policy("ij", {})
    assert policy is R2_JSON_DICT_POLICY


def test_select_json_policy_af_command_returns_analysis_policy():
    from r2inspect.error_handling.presets import R2_ANALYSIS_POLICY
    policy = _select_json_policy("af", None)
    assert policy is R2_ANALYSIS_POLICY


# ---------------------------------------------------------------------------
# Minimal fake r2 instances
# ---------------------------------------------------------------------------

class FakeR2:
    """Fake r2pipe-like object returning controlled data."""

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
    """Fake r2pipe that always raises."""

    def cmd(self, command: str) -> str:
        raise RuntimeError("r2 error")

    def cmdj(self, command: str) -> Any:
        raise RuntimeError("r2 json error")


# ---------------------------------------------------------------------------
# safe_cmd
# ---------------------------------------------------------------------------

def test_safe_cmd_returns_text_result():
    r2 = FakeR2(cmd_result="file info text")
    result = safe_cmd(r2, "i")
    assert result == "file info text"


def test_safe_cmd_returns_default_on_error():
    r2 = ErrorR2()
    result = safe_cmd(r2, "i", default="fallback")
    assert result == "fallback"


def test_safe_cmd_default_empty_string():
    r2 = ErrorR2()
    result = safe_cmd(r2, "i")
    assert result == ""


# ---------------------------------------------------------------------------
# safe_cmdj
# ---------------------------------------------------------------------------

def test_safe_cmdj_parses_valid_json():
    import json
    data = {"key": "value"}
    r2 = FakeR2(cmd_result=json.dumps(data))
    result = safe_cmdj(r2, "ij", {})
    assert result == data


def test_safe_cmdj_returns_default_on_empty_string():
    r2 = FakeR2(cmd_result="")
    result = safe_cmdj(r2, "ij", {"default": True})
    assert result == {"default": True}


def test_safe_cmdj_returns_default_on_invalid_json():
    r2 = FakeR2(cmd_result="not json at all")
    result = safe_cmdj(r2, "ij", {"default": True})
    assert result == {"default": True}


def test_safe_cmdj_returns_default_on_exception():
    r2 = ErrorR2()
    result = safe_cmdj(r2, "ij", [])
    assert result == []


# ---------------------------------------------------------------------------
# safe_cmdj_any
# ---------------------------------------------------------------------------

def test_safe_cmdj_any_uses_cmdj_when_available():
    r2 = FakeR2(json_result={"from": "cmdj"})
    result = safe_cmdj_any(r2, "ij", {})
    assert result == {"from": "cmdj"}


def test_safe_cmdj_any_falls_back_to_safe_cmdj_on_error():
    import json
    data = {"fallback": True}
    r2 = FakeR2(cmd_result=json.dumps(data), json_result=None)
    result = safe_cmdj_any(r2, "ij", {})
    assert result == data


def test_safe_cmdj_any_no_cmdj_method():
    import json

    class NoJsonR2:
        def cmd(self, command: str) -> str:
            return '{"key": 1}'

    r2 = NoJsonR2()
    result = safe_cmdj_any(r2, "ij", {})
    assert result == {"key": 1}


# ---------------------------------------------------------------------------
# safe_cmd_list / safe_cmd_dict
# ---------------------------------------------------------------------------

def test_safe_cmd_list_returns_list():
    import json
    r2 = FakeR2(cmd_result=json.dumps([{"name": "func"}]))
    result = safe_cmd_list(r2, "aflj")
    assert isinstance(result, list)
    assert result == [{"name": "func"}]


def test_safe_cmd_list_returns_empty_on_error():
    r2 = ErrorR2()
    result = safe_cmd_list(r2, "aflj")
    assert result == []


def test_safe_cmd_dict_returns_dict():
    import json
    r2 = FakeR2(cmd_result=json.dumps({"format": "PE"}))
    result = safe_cmd_dict(r2, "ij")
    assert isinstance(result, dict)
    assert result == {"format": "PE"}


def test_safe_cmd_dict_returns_empty_on_error():
    r2 = ErrorR2()
    result = safe_cmd_dict(r2, "ij")
    assert result == {}


# ---------------------------------------------------------------------------
# _handle_search
# ---------------------------------------------------------------------------

class FakeAdapterSearch:
    def search_hex_json(self, pattern: str) -> list:
        return [{"addr": 0x1000, "pattern": pattern}]

    def search_text(self, pattern: str) -> list:
        return [pattern]

    def search_hex(self, pattern: str) -> str:
        return f"0x1000 {pattern}"


def test_handle_search_xj_command():
    adapter = FakeAdapterSearch()
    result = _handle_search(adapter, "/xj DEADBEEF")
    assert result is not None
    assert result[0]["pattern"] == "DEADBEEF"


def test_handle_search_c_command():
    adapter = FakeAdapterSearch()
    result = _handle_search(adapter, "/c string_to_find")
    assert result == ["string_to_find"]


def test_handle_search_x_command():
    adapter = FakeAdapterSearch()
    result = _handle_search(adapter, "/x DEADBEEF")
    assert "DEADBEEF" in result


def test_handle_search_unknown_command_returns_none():
    adapter = FakeAdapterSearch()
    result = _handle_search(adapter, "ij")
    assert result is None


def test_handle_search_xj_no_method_returns_none():
    class NoSearchAdapter:
        pass

    result = _handle_search(NoSearchAdapter(), "/xj DEAD")
    assert result is None


# ---------------------------------------------------------------------------
# _handle_simple
# ---------------------------------------------------------------------------

class FakeSimpleAdapter:
    def get_functions(self) -> list:
        return [{"name": "main"}]

    def get_functions_at(self, addr: int) -> list:
        return [{"name": "func_at", "addr": addr}]

    def get_function_info(self, addr: int) -> dict:
        return {"name": "func", "addr": addr}

    def get_imports(self) -> list:
        return [{"name": "printf"}]

    def get_file_info(self) -> dict:
        return {"format": "PE"}

    def get_strings_filtered(self, command: str) -> list:
        return ["filtered_string"]

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

    def get_functions_text(self) -> str:
        return ""


def test_handle_simple_aflj_no_address():
    adapter = FakeSimpleAdapter()
    result = _handle_simple(adapter, "aflj", "aflj", None)
    assert result == [{"name": "main"}]


def test_handle_simple_aflj_with_address():
    adapter = FakeSimpleAdapter()
    result = _handle_simple(adapter, "aflj", "aflj @ 0x1000", 0x1000)
    assert result == [{"name": "func_at", "addr": 0x1000}]


def test_handle_simple_afij_with_address():
    adapter = FakeSimpleAdapter()
    result = _handle_simple(adapter, "afij @ 0x400", "afij @ 0x400", 0x400)
    assert result == {"name": "func", "addr": 0x400}


def test_handle_simple_iz_filtered():
    adapter = FakeSimpleAdapter()
    result = _handle_simple(adapter, "iz~hello", "iz~hello", None)
    assert result == ["filtered_string"]


def test_handle_simple_mapped_command_iij():
    adapter = FakeSimpleAdapter()
    result = _handle_simple(adapter, "iij", "iij", None)
    assert result == [{"name": "printf"}]


def test_handle_simple_mapped_command_ij():
    adapter = FakeSimpleAdapter()
    result = _handle_simple(adapter, "ij", "ij", None)
    assert result == {"format": "PE"}


def test_handle_simple_no_method_returns_none():
    class EmptyAdapter:
        pass

    result = _handle_simple(EmptyAdapter(), "ij", "ij", None)
    assert result is None


def test_handle_simple_unmapped_command_returns_none():
    adapter = FakeSimpleAdapter()
    result = _handle_simple(adapter, "xyz_unknown", "xyz_unknown", None)
    assert result is None


# ---------------------------------------------------------------------------
# _handle_disasm
# ---------------------------------------------------------------------------

class FakeDisasmAdapter:
    def get_disasm(self, address=None, size=None) -> dict:
        return {"ops": [], "address": address}

    def get_disasm_text(self, address=None, size=None) -> str:
        return "push rbp\nmov rbp, rsp"

    def get_cfg(self, address=None) -> dict:
        return {"nodes": []}


def test_handle_disasm_pdfj():
    adapter = FakeDisasmAdapter()
    result = _handle_disasm(adapter, "pdfj", 0x1000)
    assert result == {"ops": [], "address": 0x1000}


def test_handle_disasm_pdj():
    adapter = FakeDisasmAdapter()
    result = _handle_disasm(adapter, "pdj 10", None)
    assert "address" in result


def test_handle_disasm_pi():
    adapter = FakeDisasmAdapter()
    result = _handle_disasm(adapter, "pi 5", 0x1000)
    assert "push" in result


def test_handle_disasm_agj():
    adapter = FakeDisasmAdapter()
    result = _handle_disasm(adapter, "agj", 0x1000)
    assert result == {"nodes": []}


def test_handle_disasm_no_method_returns_none():
    class EmptyAdapter:
        pass

    result = _handle_disasm(EmptyAdapter(), "pdfj", 0x1000)
    assert result is None


def test_handle_disasm_none_adapter_base_returns_none():
    result = _handle_disasm(None, "pdfj", None)
    assert result is None


# ---------------------------------------------------------------------------
# _handle_bytes
# ---------------------------------------------------------------------------

class FakeBytesAdapter:
    def read_bytes_list(self, address: int, size: int) -> list:
        return list(range(size))

    def read_bytes(self, address: int, size: int) -> bytes:
        return bytes(range(size))


def test_handle_bytes_p8j():
    adapter = FakeBytesAdapter()
    result = _handle_bytes(adapter, "p8j 4", 0x1000)
    assert result == [0, 1, 2, 3]


def test_handle_bytes_p8():
    adapter = FakeBytesAdapter()
    result = _handle_bytes(adapter, "p8 4", 0x1000)
    assert isinstance(result, str)


def test_handle_bytes_pxj():
    adapter = FakeBytesAdapter()
    result = _handle_bytes(adapter, "pxj 4", 0x1000)
    assert result == [0, 1, 2, 3]


def test_handle_bytes_no_address_returns_none():
    adapter = FakeBytesAdapter()
    result = _handle_bytes(adapter, "p8j 4", None)
    assert result is None


def test_handle_bytes_p8_no_size_returns_none():
    adapter = FakeBytesAdapter()
    result = _handle_bytes(adapter, "p8", 0x1000)
    assert result is None


def test_handle_bytes_unknown_command_returns_none():
    adapter = FakeBytesAdapter()
    result = _handle_bytes(adapter, "xyz", 0x1000)
    assert result is None


def test_handle_bytes_p8_empty_data_returns_empty_string():
    class EmptyBytesAdapter:
        def read_bytes(self, address, size):
            return b""

    adapter = EmptyBytesAdapter()
    result = _handle_bytes(adapter, "p8 4", 0x1000)
    assert result == ""


# ---------------------------------------------------------------------------
# _maybe_use_adapter
# ---------------------------------------------------------------------------

def test_maybe_use_adapter_none_returns_none():
    result = _maybe_use_adapter(None, "aflj")
    assert result is None


def test_maybe_use_adapter_search_command():
    adapter = FakeAdapterSearch()
    result = _maybe_use_adapter(adapter, "/xj DEAD")
    assert result is not None


def test_maybe_use_adapter_simple_command():
    adapter = FakeSimpleAdapter()
    result = _maybe_use_adapter(adapter, "ij")
    assert result == {"format": "PE"}


def test_maybe_use_adapter_disasm_command():
    adapter = FakeDisasmAdapter()
    result = _maybe_use_adapter(adapter, "pdfj @ 0x1000")
    assert result is not None


def test_maybe_use_adapter_bytes_command():
    adapter = FakeBytesAdapter()
    result = _maybe_use_adapter(adapter, "p8j 4 @ 0x1000")
    assert result == [0, 1, 2, 3]


def test_maybe_use_adapter_unknown_command_returns_none():
    class EmptyAdapter:
        pass

    result = _maybe_use_adapter(EmptyAdapter(), "xyz_unknown_command")
    assert result is None


# ---------------------------------------------------------------------------
# cmd / cmdj / cmd_list
# ---------------------------------------------------------------------------

def test_cmd_uses_adapter_result_when_string():
    adapter = FakeSimpleAdapter()
    result = cmd(adapter, None, "i")
    assert isinstance(result, str)


def test_cmd_falls_back_to_r2_when_adapter_returns_non_string():
    adapter = FakeSimpleAdapter()
    r2 = FakeR2(cmd_result="r2 output")
    result = cmd(adapter, r2, "ij")
    # ij returns dict from adapter, which is not str -> falls back
    # Actually FakeSimpleAdapter.get_file_info returns dict
    # _maybe_use_adapter returns dict -> not str -> fallback
    assert isinstance(result, str)


def test_cmdj_uses_adapter_result_when_not_none():
    adapter = FakeSimpleAdapter()
    result = cmdj(adapter, None, "ij", {})
    assert result == {"format": "PE"}


def test_cmdj_falls_back_to_r2_when_adapter_returns_none():
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


def test_cmd_list_returns_empty_on_non_list():
    adapter = FakeSimpleAdapter()
    # ij returns dict -> cmd_list gets dict -> returns []
    result = cmd_list(adapter, None, "ij")
    assert result == []


# ---------------------------------------------------------------------------
# _cmd_fallback / _cmdj_fallback
# ---------------------------------------------------------------------------

def test_cmd_fallback_none_r2_returns_empty_string():
    result = _cmd_fallback(None, "i")
    assert result == ""


def test_cmd_fallback_r2_without_cmd_returns_empty_string():
    class NoCmd:
        pass

    result = _cmd_fallback(NoCmd(), "i")
    assert result == ""


def test_cmdj_fallback_none_r2_returns_default():
    result = _cmdj_fallback(None, "ij", {"default": True})
    assert result == {"default": True}


# ---------------------------------------------------------------------------
# parse_pe_header_text
# ---------------------------------------------------------------------------

def test_parse_pe_header_text_returns_none_on_empty():
    class EmptyR2:
        def cmd(self, command: str) -> str:
            return ""

    result = parse_pe_header_text(EmptyR2())
    assert result is None


def test_parse_pe_header_text_parses_sections():
    pe_text = (
        "IMAGE_NT_HEADERS\n"
        "Signature: 0x4550\n"
        "IMAGE_FILE_HEADERS\n"
        "Machine: 0x8664\n"
        "IMAGE_OPTIONAL_HEADERS\n"
        "Magic: 0x20b\n"
    )

    class TextR2:
        def cmd(self, command: str) -> str:
            return pe_text

    result = parse_pe_header_text(TextR2())
    assert result is not None
    assert "file_header" in result
    assert "optional_header" in result


# ---------------------------------------------------------------------------
# _get_headers_json
# ---------------------------------------------------------------------------

def test_get_headers_json_via_get_headers_json_method():
    class FakeR2WithMethod:
        def get_headers_json(self) -> list:
            return [{"name": "Signature", "value": 0x4550}]

    result = _get_headers_json(FakeR2WithMethod())
    assert result == [{"name": "Signature", "value": 0x4550}]


def test_get_headers_json_returns_none_on_empty():
    class FakeR2WithMethod:
        def get_headers_json(self) -> list:
            return []

    result = _get_headers_json(FakeR2WithMethod())
    assert result is None


def test_get_headers_json_dict_wrapped_in_list():
    class FakeR2WithMethod:
        def get_headers_json(self) -> dict:
            return {"name": "Signature", "value": 0x4550}

    result = _get_headers_json(FakeR2WithMethod())
    assert isinstance(result, list)
    assert len(result) == 1


# ---------------------------------------------------------------------------
# get_pe_headers
# ---------------------------------------------------------------------------

def test_get_pe_headers_with_valid_headers_list():
    class FakeR2WithHeaders:
        def get_headers_json(self) -> list:
            return [
                {"name": "Machine", "value": 0x8664},
                {"name": "ImageBase", "value": 0x400000},
                {"name": "UnknownField", "value": 42},
            ]

    result = get_pe_headers(FakeR2WithHeaders())
    assert result is not None
    assert "file_header" in result
    assert result["file_header"]["Machine"] == 0x8664
    assert result["optional_header"]["ImageBase"] == 0x400000
    assert result["nt_headers"]["UnknownField"] == 42


def test_get_pe_headers_falls_back_to_text_parse():
    pe_text = "IMAGE_FILE_HEADERS\nMachine: 0x8664\n"

    class FallbackR2:
        def get_headers_json(self) -> list:
            return []

        def cmd(self, command: str) -> str:
            return pe_text

    result = get_pe_headers(FallbackR2())
    # Falls back to text parse which returns dict
    assert result is not None


def test_get_pe_headers_skips_non_dict_items():
    class FakeR2WithBadItems:
        def get_headers_json(self) -> list:
            return ["not_a_dict", None, {"name": "Machine", "value": 0x8664}]

    result = get_pe_headers(FakeR2WithBadItems())
    assert result is not None
    assert result["file_header"]["Machine"] == 0x8664


# ---------------------------------------------------------------------------
# get_elf_headers
# ---------------------------------------------------------------------------

def test_get_elf_headers_with_json_method():
    class FakeR2WithELF:
        def get_headers_json(self) -> list:
            return [{"type": "PT_LOAD", "flags": "r-x"}]

    result = get_elf_headers(FakeR2WithELF())
    assert result is not None
    assert isinstance(result, list)


def test_get_elf_headers_falls_back_to_text():
    class FallbackR2:
        def get_headers_json(self) -> list:
            return []

        def get_header_text(self) -> str:
            return "type: PT_LOAD\nflags: r-x\n"

    result = get_elf_headers(FallbackR2())
    assert isinstance(result, list)


def test_get_elf_headers_returns_empty_on_no_data():
    class EmptyR2:
        def cmd(self, command: str) -> str:
            return ""

    result = get_elf_headers(EmptyR2())
    assert result == [] or result is None


# ---------------------------------------------------------------------------
# get_macho_headers
# ---------------------------------------------------------------------------

def test_get_macho_headers_with_json_method():
    class FakeR2WithMachO:
        def get_headers_json(self) -> list:
            return [{"cmd": "LC_SEGMENT_64", "cmdsize": 72}]

    result = get_macho_headers(FakeR2WithMachO())
    assert result is not None
    assert isinstance(result, list)


def test_get_macho_headers_returns_empty_on_no_data():
    class EmptyR2:
        def cmd(self, command: str) -> str:
            return ""

    result = get_macho_headers(EmptyR2())
    assert result == [] or result is None


# ---------------------------------------------------------------------------
# _run_cmd_with_timeout: invalid env timeout falls back (lines 105-108)
# ---------------------------------------------------------------------------

def test_run_cmd_with_timeout_invalid_env_timeout_uses_default():
    """Cover lines 105-108: R2INSPECT_CMD_TIMEOUT_SECONDS set to non-numeric."""
    import os
    from r2inspect.infrastructure.r2_helpers import _run_cmd_with_timeout

    class FakeR2Cmd:
        def cmd(self, command: str) -> str:
            return '{"result": true}'

    os.environ["R2INSPECT_CMD_TIMEOUT_SECONDS"] = "not_a_number"
    try:
        result = _run_cmd_with_timeout(FakeR2Cmd(), "ij", {})
    finally:
        del os.environ["R2INSPECT_CMD_TIMEOUT_SECONDS"]
    assert result == '{"result": true}'


def test_run_cmd_with_timeout_valid_env_timeout():
    """Cover lines 105-107: R2INSPECT_CMD_TIMEOUT_SECONDS set to valid number."""
    import os
    from r2inspect.infrastructure.r2_helpers import _run_cmd_with_timeout

    class FakeR2Cmd:
        def cmd(self, command: str) -> str:
            return "ok"

    os.environ["R2INSPECT_CMD_TIMEOUT_SECONDS"] = "5.0"
    try:
        result = _run_cmd_with_timeout(FakeR2Cmd(), "i", "default")
    finally:
        del os.environ["R2INSPECT_CMD_TIMEOUT_SECONDS"]
    assert result == "ok"


# ---------------------------------------------------------------------------
# _get_headers_json: non-dict/non-list returns None (line 548)
# ---------------------------------------------------------------------------

def test_get_headers_json_non_dict_non_list_returns_none():
    """Cover line 548: headers is not dict/list -> return None."""
    class R2WithStringHeaders:
        def get_headers_json(self):
            return "some string header"  # truthy but not dict or list

    result = _get_headers_json(R2WithStringHeaders())
    assert result is None


# ---------------------------------------------------------------------------
# get_macho_headers: dict headers returns list (line 588)
# ---------------------------------------------------------------------------

def test_get_macho_headers_with_dict_headers_returns_list():
    """Cover line 588: headers is a dict -> return [headers]."""
    class R2WithDictHeaders:
        def get_headers_json(self):
            return {"cmd": "LC_SEGMENT_64", "cmdsize": 72}  # dict, not list

    result = get_macho_headers(R2WithDictHeaders())
    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["cmd"] == "LC_SEGMENT_64"


# ---------------------------------------------------------------------------
# get_macho_headers: text fallback with non-empty output (line 604)
# ---------------------------------------------------------------------------

def test_get_macho_headers_text_fallback_returns_empty_list():
    """Cover line 604: headers_output is non-empty but Mach-O parsing returns []."""
    class R2WithTextHeaders:
        def get_headers_json(self):
            return None  # falsy -> fallback to text

        def get_header_text(self):
            return "LC_SEGMENT_64: offset=0x1000"  # non-empty text

    result = get_macho_headers(R2WithTextHeaders())
    assert result == []


# ---------------------------------------------------------------------------
# _run_cmd_with_timeout: actual thread timeout (lines 115-116)
# ---------------------------------------------------------------------------

def test_run_cmd_with_timeout_actual_thread_timeout():
    """Cover lines 115-116: thread doesn't complete within timeout."""
    import os
    import time
    from r2inspect.infrastructure.r2_helpers import _run_cmd_with_timeout

    class BlockingR2:
        def cmd(self, command: str) -> str:
            time.sleep(10)  # much longer than test timeout
            return "result"

    # Set env timeout to extremely small value to force timeout
    os.environ["R2INSPECT_CMD_TIMEOUT_SECONDS"] = "0.001"
    try:
        result = _run_cmd_with_timeout(BlockingR2(), "i", "default_value")
    finally:
        del os.environ["R2INSPECT_CMD_TIMEOUT_SECONDS"]
    assert result == "default_value"
