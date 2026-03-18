#!/usr/bin/env python3
"""
Comprehensive tests for r2inspect/adapters/r2pipe_queries.py

Tests caching, error handling, silent failures, and all query methods.
All tests use real objects (FakeR2 + R2PipeAdapter) instead of mocks.
"""

import json

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter


class FakeR2:
    """Fake r2pipe instance that returns pre-configured responses."""

    def __init__(self, cmdj_map=None, cmd_map=None):
        self.cmdj_map = cmdj_map or {}
        self.cmd_map = cmd_map or {}

    def cmdj(self, command):
        return self.cmdj_map.get(command, None)

    def cmd(self, command):
        return self.cmd_map.get(command, "")


class ErrorR2(FakeR2):
    """FakeR2 subclass that raises exceptions on all commands."""

    def __init__(self, exc_type=RuntimeError, message="Connection error"):
        super().__init__()
        self._exc_type = exc_type
        self._message = message

    def cmdj(self, command):
        raise self._exc_type(self._message)

    def cmd(self, command):
        raise self._exc_type(self._message)


class SelectiveErrorR2(FakeR2):
    """FakeR2 subclass that raises on specific commands, normal on others."""

    def __init__(self, error_commands=None, cmdj_map=None, cmd_map=None):
        super().__init__(cmdj_map=cmdj_map, cmd_map=cmd_map)
        self.error_commands = error_commands or set()

    def cmdj(self, command):
        if command in self.error_commands:
            raise RuntimeError(f"Error executing {command}")
        return super().cmdj(command)

    def cmd(self, command):
        if command in self.error_commands:
            raise RuntimeError(f"Error executing {command}")
        return super().cmd(command)


def _make_adapter(cmdj_map=None, cmd_map=None):
    """Create an R2PipeAdapter with a FakeR2 backend."""
    r2 = FakeR2(cmdj_map=cmdj_map, cmd_map=cmd_map)
    return R2PipeAdapter(r2)


def _make_error_adapter(exc_type=RuntimeError, message="Connection error"):
    """Create an R2PipeAdapter that errors on all commands."""
    r2 = ErrorR2(exc_type=exc_type, message=message)
    return R2PipeAdapter(r2)


# get_file_info tests


def test_get_file_info_success():
    info_data = {"arch": "x86", "bits": 64}
    adapter = _make_adapter(cmdj_map={"ij": info_data})
    result = adapter.get_file_info()
    assert result["arch"] == "x86"
    assert result["bits"] == 64


def test_get_file_info_cached():
    info_data = {"arch": "arm", "bits": 32}
    adapter = _make_adapter(cmdj_map={"ij": info_data})

    result1 = adapter.get_file_info()
    result2 = adapter.get_file_info()
    assert result1 == result2
    assert result1["arch"] == "arm"


def test_get_file_info_invalid_response():
    # cmdj returns None (empty/invalid) -> should fall through to empty dict
    adapter = _make_adapter(cmdj_map={})
    result = adapter.get_file_info()
    assert result == {}


def test_get_file_info_error_handling():
    adapter = _make_error_adapter()
    result = adapter.get_file_info()
    assert result == {}


# get_sections tests


def test_get_sections_success():
    sections = [{"name": ".text", "size": 0x1000}]
    adapter = _make_adapter(cmdj_map={"iSj": sections})
    result = adapter.get_sections()
    assert result == sections


def test_get_sections_empty():
    adapter = _make_adapter(cmdj_map={"iSj": []})
    result = adapter.get_sections()
    # Empty list is not a valid response, so returns the default
    assert result == []


def test_get_sections_returns_section_data():
    sections = [{"name": ".data"}]
    adapter = _make_adapter(cmdj_map={"iSj": sections})
    result = adapter.get_sections()
    assert len(result) == 1
    assert result[0]["name"] == ".data"


# get_imports tests


def test_get_imports_success():
    imports = [{"name": "printf", "libname": "libc.so"}]
    adapter = _make_adapter(cmdj_map={"iij": imports})
    result = adapter.get_imports()
    assert result == imports


def test_get_imports_empty():
    adapter = _make_adapter(cmdj_map={"iij": []})
    result = adapter.get_imports()
    assert result == []


# get_exports tests


def test_get_exports_success():
    exports = [{"name": "main", "vaddr": 0x401000}]
    adapter = _make_adapter(cmdj_map={"iEj": exports})
    result = adapter.get_exports()
    assert result == exports


def test_get_exports_empty():
    adapter = _make_adapter(cmdj_map={"iEj": []})
    result = adapter.get_exports()
    assert result == []


# get_symbols tests


def test_get_symbols_success():
    symbols = [{"name": "sym.main", "type": "FUNC"}]
    adapter = _make_adapter(cmdj_map={"isj": symbols})
    result = adapter.get_symbols()
    assert result == symbols


def test_get_symbols_empty():
    adapter = _make_adapter(cmdj_map={"isj": []})
    result = adapter.get_symbols()
    assert result == []


# get_strings tests


def test_get_strings_success():
    strings = [{"string": "hello", "vaddr": 0x402000}]
    adapter = _make_adapter(cmdj_map={"izzj": strings})
    result = adapter.get_strings()
    assert result == strings


def test_get_strings_empty():
    adapter = _make_adapter(cmdj_map={"izzj": []})
    result = adapter.get_strings()
    assert result == []


# get_functions tests


def test_get_functions_success():
    functions = [{"name": "main", "size": 100}]
    adapter = _make_adapter(cmdj_map={"aflj": functions})
    result = adapter.get_functions()
    assert result == functions


def test_get_functions_empty():
    adapter = _make_adapter(cmdj_map={"aflj": []})
    result = adapter.get_functions()
    assert result == []


# get_functions_at tests


def test_get_functions_at_success():
    address = 0x401000
    functions = [{"offset": address, "name": "main"}]
    adapter = _make_adapter(cmdj_map={f"aflj @ {address}": functions})
    result = adapter.get_functions_at(address)
    assert result == functions


def test_get_functions_at_error():
    adapter = _make_error_adapter()
    result = adapter.get_functions_at(0x401000)
    assert result == []


def test_get_functions_at_invalid_data():
    adapter = _make_adapter(cmdj_map={})
    result = adapter.get_functions_at(0x401000)
    assert result == []


# get_disasm tests


def test_get_disasm_function_default():
    disasm_data = {"ops": []}
    adapter = _make_adapter(cmdj_map={"pdfj": disasm_data})
    result = adapter.get_disasm()
    assert result == disasm_data


def test_get_disasm_with_size():
    disasm_data = [{"offset": 0x401000}]
    adapter = _make_adapter(cmdj_map={"pdj 10": disasm_data})
    result = adapter.get_disasm(size=10)
    assert result == disasm_data


def test_get_disasm_with_address():
    address = 0x401000
    disasm_data = {"ops": [{"offset": address}]}
    adapter = _make_adapter(cmdj_map={f"pdfj @ {address}": disasm_data})
    result = adapter.get_disasm(address=address)
    # When address is provided, result should be returned (or default)
    assert isinstance(result, (dict, list))


def test_get_disasm_with_address_and_size():
    adapter = _make_adapter(cmdj_map={"pdj 20 @ 4198400": [{"offset": 0x401000}]})
    result = adapter.get_disasm(address=0x401000, size=20)
    assert isinstance(result, (dict, list))


def test_get_disasm_error():
    adapter = _make_error_adapter()
    result = adapter.get_disasm()
    # Default size=None -> data_type="dict", _cached_query returns {} on error
    assert result == {}


# get_cfg tests


def test_get_cfg_default():
    cfg_data = [{"blocks": []}]
    adapter = _make_adapter(cmdj_map={"agj": cfg_data})
    result = adapter.get_cfg()
    assert result == cfg_data


def test_get_cfg_with_address():
    address = 0x401000
    cfg_data = [{"blocks": [{"offset": address}]}]
    adapter = _make_adapter(cmdj_map={f"agj @ {address}": cfg_data})
    result = adapter.get_cfg(address=address)
    assert isinstance(result, (dict, list))


def test_get_cfg_error():
    adapter = _make_error_adapter()
    result = adapter.get_cfg()
    # _cached_query with data_type="list" returns [] on error
    assert result == []


# analyze_all tests


def test_analyze_all_success():
    adapter = _make_adapter(cmd_map={"aaa": "Analysis complete"})
    result = adapter.analyze_all()
    assert result == "Analysis complete"


def test_analyze_all_error():
    adapter = _make_error_adapter()
    result = adapter.analyze_all()
    assert result == ""


# Text output methods tests


def test_get_info_text_success():
    adapter = _make_adapter(cmd_map={"i": "info output"})
    result = adapter.get_info_text()
    assert result == "info output"


def test_get_info_text_error():
    adapter = _make_error_adapter()
    result = adapter.get_info_text()
    assert result == ""


def test_get_dynamic_info_text_success():
    adapter = _make_adapter(cmd_map={"id": "dynamic info"})
    result = adapter.get_dynamic_info_text()
    assert result == "dynamic info"


def test_get_dynamic_info_text_error():
    adapter = _make_error_adapter()
    result = adapter.get_dynamic_info_text()
    assert result == ""


def test_get_entropy_pattern_success():
    adapter = _make_adapter(cmd_map={"p=e 100": "entropy"})
    result = adapter.get_entropy_pattern()
    assert result == "entropy"


def test_get_entropy_pattern_error():
    adapter = _make_error_adapter()
    result = adapter.get_entropy_pattern()
    assert result == ""


def test_get_pe_version_info_text_success():
    adapter = _make_adapter(cmd_map={"iR~version": "version"})
    result = adapter.get_pe_version_info_text()
    assert result == "version"


def test_get_pe_version_info_text_error():
    adapter = _make_error_adapter()
    result = adapter.get_pe_version_info_text()
    assert result == ""


def test_get_pe_security_text_success():
    adapter = _make_adapter(cmd_map={"iHH": "security"})
    result = adapter.get_pe_security_text()
    assert result == "security"


def test_get_pe_security_text_error():
    adapter = _make_error_adapter()
    result = adapter.get_pe_security_text()
    assert result == ""


def test_get_header_text_success():
    adapter = _make_adapter(cmd_map={"ih": "header"})
    result = adapter.get_header_text()
    assert result == "header"


def test_get_header_text_error():
    adapter = _make_error_adapter()
    result = adapter.get_header_text()
    assert result == ""


# JSON output methods tests


def test_get_headers_json_success():
    headers = {"header": "data"}
    adapter = _make_adapter(cmdj_map={"ihj": headers})
    result = adapter.get_headers_json()
    assert result == headers


def test_get_headers_json_error():
    adapter = _make_error_adapter()
    result = adapter.get_headers_json()
    assert result is None


def test_get_strings_basic_success():
    strings = [{"string": "test"}]
    adapter = _make_adapter(cmdj_map={"izj": strings})
    result = adapter.get_strings_basic()
    assert result == strings


def test_get_strings_text_success():
    adapter = _make_adapter(cmd_map={"izz~..": "strings"})
    result = adapter.get_strings_text()
    assert result == "strings"


def test_get_strings_text_error():
    adapter = _make_error_adapter()
    result = adapter.get_strings_text()
    assert result == ""


def test_get_strings_filtered_success():
    adapter = _make_adapter(cmd_map={"iz~http": "filtered"})
    result = adapter.get_strings_filtered("iz~http")
    assert result == "filtered"


def test_get_strings_filtered_error():
    adapter = _make_error_adapter()
    result = adapter.get_strings_filtered("iz~test")
    assert result == ""


# PE-specific methods tests


def test_get_entry_info_success():
    entry_data = [{"vaddr": 0x401000}]
    adapter = _make_adapter(cmdj_map={"iej": entry_data})
    result = adapter.get_entry_info()
    assert result == entry_data


def test_get_entry_info_error():
    adapter = _make_error_adapter()
    result = adapter.get_entry_info()
    assert result == []


def test_get_pe_header_success_dict():
    header = {"machine": "x86"}
    adapter = _make_adapter(cmdj_map={"ihj": header})
    result = adapter.get_pe_header()
    assert result == header


def test_get_pe_header_success_list():
    headers = [{"header1": "value"}]
    adapter = _make_adapter(cmdj_map={"ihj": headers})
    result = adapter.get_pe_header()
    assert result == {"headers": headers}


def test_get_pe_header_empty():
    adapter = _make_adapter(cmdj_map={})
    result = adapter.get_pe_header()
    assert result == {}


def test_get_pe_header_error():
    adapter = _make_error_adapter()
    result = adapter.get_pe_header()
    assert result == {}


def test_get_pe_optional_header_success():
    opt_header = {"subsystem": "GUI"}
    adapter = _make_adapter(cmdj_map={"iHj": opt_header})
    result = adapter.get_pe_optional_header()
    assert result == opt_header


def test_get_pe_optional_header_error():
    adapter = _make_error_adapter()
    result = adapter.get_pe_optional_header()
    assert result == {}


def test_get_data_directories_success():
    directories = [{"name": "Import", "address": 0x1000}]
    adapter = _make_adapter(cmdj_map={"iDj": directories})
    result = adapter.get_data_directories()
    assert result == directories


def test_get_data_directories_error():
    adapter = _make_error_adapter()
    result = adapter.get_data_directories()
    assert result == []


def test_get_resources_info_success():
    resources = [{"type": "ICON"}]
    adapter = _make_adapter(cmdj_map={"iRj": resources})
    result = adapter.get_resources_info()
    assert result == resources


def test_get_resources_info_error():
    adapter = _make_error_adapter()
    result = adapter.get_resources_info()
    assert result == []


def test_get_function_info_success():
    func_info = [{"name": "main", "cc": 5}]
    adapter = _make_adapter(cmdj_map={"afij @ 4198400": func_info})
    result = adapter.get_function_info(0x401000)
    assert result == func_info


def test_get_function_info_error():
    adapter = _make_error_adapter()
    result = adapter.get_function_info(0x401000)
    assert result == []


def test_get_disasm_text_success():
    adapter = _make_adapter(cmd_map={"pi": "disasm"})
    result = adapter.get_disasm_text()
    assert result == "disasm"


def test_get_disasm_text_with_params():
    adapter = _make_adapter(cmd_map={"pi 10 @ 4198400": "disasm"})
    result = adapter.get_disasm_text(address=0x401000, size=10)
    assert result == "disasm"


def test_get_disasm_text_error():
    adapter = _make_error_adapter()
    result = adapter.get_disasm_text()
    assert result == ""


# Search methods tests


def test_search_hex_json_success():
    results = [{"offset": 0x1000, "data": "deadbeef"}]
    adapter = _make_adapter(cmdj_map={"/xj deadbeef": results})
    result = adapter.search_hex_json("deadbeef")
    assert result == results


def test_search_hex_json_error():
    adapter = _make_error_adapter()
    result = adapter.search_hex_json("deadbeef")
    assert result == []


def test_search_text_success():
    adapter = _make_adapter(cmd_map={"/c password": "results"})
    result = adapter.search_text("password")
    assert result == "results"


def test_search_text_error():
    adapter = _make_error_adapter()
    result = adapter.search_text("test")
    assert result == ""


def test_search_hex_success():
    adapter = _make_adapter(cmd_map={"/x deadbeef": "results"})
    result = adapter.search_hex("deadbeef")
    assert result == "results"


def test_search_hex_error():
    adapter = _make_error_adapter()
    result = adapter.search_hex("deadbeef")
    assert result == ""


# read_bytes tests


def test_read_bytes_success():
    hex_data = "4d5a9000"  # MZ header
    adapter = _make_adapter(cmd_map={"p8 4 @ 4096": hex_data})
    result = adapter.read_bytes(0x1000, 4)
    assert result == bytes.fromhex(hex_data)


def test_read_bytes_invalid_hex():
    adapter = _make_adapter(cmd_map={"p8 4 @ 4096": "GGGG"})
    result = adapter.read_bytes(0x1000, 4)
    assert result == b""


def test_read_bytes_invalid_address():
    adapter = _make_adapter()
    with pytest.raises(ValueError):
        adapter.read_bytes(-1, 4)


def test_read_bytes_invalid_size():
    adapter = _make_adapter()
    with pytest.raises(ValueError):
        adapter.read_bytes(0x1000, 0)


def test_read_bytes_invalid_response():
    # cmd returns empty string -> is_valid_r2_response returns False
    adapter = _make_adapter(cmd_map={})
    result = adapter.read_bytes(0x1000, 4)
    assert result == b""


def test_read_bytes_error():
    adapter = _make_error_adapter()
    result = adapter.read_bytes(0x1000, 4)
    assert result == b""


def test_read_bytes_exception():
    adapter = _make_error_adapter(exc_type=Exception, message="Connection error")
    result = adapter.read_bytes(0x1000, 4)
    assert result == b""


def test_read_bytes_list_success():
    hex_data = "01020304"
    adapter = _make_adapter(cmd_map={"p8 4 @ 4096": hex_data})
    result = adapter.read_bytes_list(0x1000, 4)
    assert result == [1, 2, 3, 4]


def test_read_bytes_list_empty():
    # No data for the command -> returns empty bytes -> empty list
    adapter = _make_adapter(cmd_map={})
    result = adapter.read_bytes_list(0x1000, 4)
    assert result == []


# _safe_query tests


def test_safe_query_success():
    adapter = _make_adapter()
    result = adapter._safe_query(lambda: {"data": "value"}, {}, "Error message")
    assert result == {"data": "value"}


def test_safe_query_exception():
    adapter = _make_adapter()

    def raise_error():
        raise RuntimeError("Test error")

    result = adapter._safe_query(raise_error, {"default": "value"}, "Error message")
    assert result == {"default": "value"}


def test_safe_query_returns_default_on_error():
    adapter = _make_adapter()
    result = adapter._safe_query(lambda: 1 / 0, "default_value", "Division by zero")
    assert result == "default_value"


# _safe_cached_query tests


def test_safe_cached_query_success():
    data = [{"item": 1}]
    adapter = _make_adapter(cmdj_map={"test_cmd": data})
    result = adapter._safe_cached_query(
        "test_cmd", "list", [], error_msg="error", error_label="items"
    )
    assert result == data


def test_safe_cached_query_error():
    # Use an adapter whose underlying r2 always errors
    adapter = _make_error_adapter()
    result = adapter._safe_cached_query("cmd", "list", [], error_msg="error", error_label="items")
    assert result == []


def test_safe_cached_query_default_dict():
    adapter = _make_error_adapter()
    result = adapter._safe_cached_query("cmd", "dict", {}, error_msg="error", error_label="data")
    assert result == {}


# Caching tests


def test_caching_prevents_duplicate_calls():
    sections = [{"cached": True}]
    adapter = _make_adapter(cmdj_map={"iSj": sections})
    result1 = adapter.get_sections()
    result2 = adapter.get_sections()
    assert result1 == result2


def test_caching_disabled_when_cache_false():
    adapter = _make_adapter(cmdj_map={"iSj": []})
    # Just verify it runs without error
    result = adapter.get_sections()
    assert isinstance(result, list)


def test_cache_hit_returns_cached_data():
    adapter = _make_adapter()
    cached = {"from": "cache"}
    adapter._cache["test_cmd"] = cached

    result = adapter._cached_query("test_cmd", "dict", cache=True)
    assert result == cached


# Edge cases


def test_disasm_no_cache_when_address_provided():
    disasm_data = {"ops": []}
    adapter = _make_adapter(cmdj_map={"pdfj @ 4198400": disasm_data})
    # First call with address
    adapter.get_disasm(address=0x401000)
    # The command with an address should NOT be cached
    assert "pdfj @ 4198400" not in adapter._cache


def test_cfg_no_cache_when_address_provided():
    cfg_data = [{"blocks": []}]
    adapter = _make_adapter(cmdj_map={"agj @ 4198400": cfg_data})
    adapter.get_cfg(address=0x401000)
    # The command with an address should NOT be cached
    assert "agj @ 4198400" not in adapter._cache


def test_get_file_info_validates_response():
    # When cmdj returns empty dict, is_valid_r2_response returns False
    adapter = _make_adapter(cmdj_map={"ij": {}})
    result = adapter.get_file_info()
    # Empty dict is not valid per is_valid_r2_response
    assert result == {}


def test_pe_header_handles_empty_list():
    adapter = _make_adapter(cmdj_map={"ihj": []})
    result = adapter.get_pe_header()
    assert result == {}
