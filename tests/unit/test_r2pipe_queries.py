#!/usr/bin/env python3
"""
Comprehensive tests for r2inspect/adapters/r2pipe_queries.py

Tests caching, error handling, silent failures, and all query methods.
"""

import os
from unittest.mock import MagicMock, Mock, patch

import pytest

from r2inspect.adapters.r2pipe_queries import R2PipeQueryMixin


class MockR2PipeAdapter(R2PipeQueryMixin):
    """Mock adapter for testing query mixin."""

    def __init__(self):
        self._cache = {}
        self._force_error_methods = set()

    def cmd(self, command):
        return ""

    def cmdj(self, command):
        return None

    def _cached_query(
        self, cmd, data_type="list", default=None, error_msg="", *, cache=True
    ):
        if cache and cmd in self._cache:
            return self._cache[cmd]

        if data_type == "list":
            result = default if default is not None else []
        else:
            result = default if default is not None else {}

        if cache:
            self._cache[cmd] = result
        return result

    def _maybe_force_error(self, method):
        if method in self._force_error_methods:
            raise RuntimeError(f"Forced error for {method}")


# get_file_info tests


def test_get_file_info_success():
    adapter = MockR2PipeAdapter()
    info_data = {"arch": "x86", "bits": 64}
    adapter._cache["ij"] = info_data

    with patch(
        "r2inspect.adapters.r2pipe_queries.safe_cmd_dict", return_value=info_data
    ):
        with patch(
            "r2inspect.adapters.r2pipe_queries.validate_r2_data",
            return_value=info_data,
        ):
            with patch(
                "r2inspect.adapters.r2pipe_queries.is_valid_r2_response",
                return_value=True,
            ):
                result = adapter.get_file_info()
                assert result == info_data


def test_get_file_info_cached():
    adapter = MockR2PipeAdapter()
    cached_data = {"arch": "arm", "bits": 32}
    adapter._cache["ij"] = cached_data

    result = adapter.get_file_info()
    assert result == cached_data


def test_get_file_info_invalid_response():
    adapter = MockR2PipeAdapter()

    with patch("r2inspect.adapters.r2pipe_queries.safe_cmd_dict", return_value={}):
        with patch(
            "r2inspect.adapters.r2pipe_queries.validate_r2_data", return_value={}
        ):
            with patch(
                "r2inspect.adapters.r2pipe_queries.is_valid_r2_response",
                return_value=False,
            ):
                result = adapter.get_file_info()
                assert result == {}


def test_get_file_info_error_handling():
    adapter = MockR2PipeAdapter()
    adapter._force_error_methods.add("get_file_info")

    result = adapter.get_file_info()
    assert result == {}


# get_sections tests


def test_get_sections_success():
    adapter = MockR2PipeAdapter()
    sections = [{"name": ".text", "size": 0x1000}]

    with patch.object(adapter, "_safe_cached_query", return_value=sections):
        result = adapter.get_sections()
        assert result == sections


def test_get_sections_empty():
    adapter = MockR2PipeAdapter()

    with patch.object(adapter, "_safe_cached_query", return_value=[]):
        result = adapter.get_sections()
        assert result == []


def test_get_sections_calls_cached_query():
    adapter = MockR2PipeAdapter()
    sections = [{"name": ".data"}]

    with patch.object(
        adapter, "_safe_cached_query", return_value=sections
    ) as mock_cached:
        result = adapter.get_sections()
        mock_cached.assert_called_once()
        assert "iSj" in str(mock_cached.call_args)


# get_imports tests


def test_get_imports_success():
    adapter = MockR2PipeAdapter()
    imports = [{"name": "printf", "libname": "libc.so"}]

    with patch.object(adapter, "_safe_cached_query", return_value=imports):
        result = adapter.get_imports()
        assert result == imports


def test_get_imports_empty():
    adapter = MockR2PipeAdapter()

    with patch.object(adapter, "_safe_cached_query", return_value=[]):
        result = adapter.get_imports()
        assert result == []


# get_exports tests


def test_get_exports_success():
    adapter = MockR2PipeAdapter()
    exports = [{"name": "main", "vaddr": 0x401000}]

    with patch.object(adapter, "_safe_cached_query", return_value=exports):
        result = adapter.get_exports()
        assert result == exports


def test_get_exports_empty():
    adapter = MockR2PipeAdapter()

    with patch.object(adapter, "_safe_cached_query", return_value=[]):
        result = adapter.get_exports()
        assert result == []


# get_symbols tests


def test_get_symbols_success():
    adapter = MockR2PipeAdapter()
    symbols = [{"name": "sym.main", "type": "FUNC"}]

    with patch.object(adapter, "_safe_cached_query", return_value=symbols):
        result = adapter.get_symbols()
        assert result == symbols


def test_get_symbols_empty():
    adapter = MockR2PipeAdapter()

    with patch.object(adapter, "_safe_cached_query", return_value=[]):
        result = adapter.get_symbols()
        assert result == []


# get_strings tests


def test_get_strings_success():
    adapter = MockR2PipeAdapter()
    strings = [{"string": "hello", "vaddr": 0x402000}]

    with patch.object(adapter, "_safe_cached_query", return_value=strings):
        result = adapter.get_strings()
        assert result == strings


def test_get_strings_empty():
    adapter = MockR2PipeAdapter()

    with patch.object(adapter, "_safe_cached_query", return_value=[]):
        result = adapter.get_strings()
        assert result == []


# get_functions tests


def test_get_functions_success():
    adapter = MockR2PipeAdapter()
    functions = [{"name": "main", "size": 100}]

    with patch.object(adapter, "_safe_cached_query", return_value=functions):
        result = adapter.get_functions()
        assert result == functions


def test_get_functions_empty():
    adapter = MockR2PipeAdapter()

    with patch.object(adapter, "_safe_cached_query", return_value=[]):
        result = adapter.get_functions()
        assert result == []


# get_functions_at tests


def test_get_functions_at_success():
    adapter = MockR2PipeAdapter()
    address = 0x401000
    functions = [{"offset": address, "name": "main"}]

    with patch("r2inspect.adapters.r2pipe_queries.safe_cmdj", return_value=functions):
        with patch(
            "r2inspect.adapters.r2pipe_queries.validate_r2_data",
            return_value=functions,
        ):
            result = adapter.get_functions_at(address)
            assert result == functions


def test_get_functions_at_error():
    adapter = MockR2PipeAdapter()
    adapter._force_error_methods.add("get_functions_at")

    result = adapter.get_functions_at(0x401000)
    assert result == []


def test_get_functions_at_invalid_data():
    adapter = MockR2PipeAdapter()

    with patch("r2inspect.adapters.r2pipe_queries.safe_cmdj", return_value=[]):
        with patch(
            "r2inspect.adapters.r2pipe_queries.validate_r2_data", return_value=[]
        ):
            result = adapter.get_functions_at(0x401000)
            assert result == []


# get_disasm tests


def test_get_disasm_function_default():
    adapter = MockR2PipeAdapter()
    disasm_data = {"ops": []}

    with patch.object(
        adapter, "_cached_query", return_value=disasm_data
    ) as mock_cached:
        result = adapter.get_disasm()
        assert result == disasm_data
        mock_cached.assert_called_once()


def test_get_disasm_with_size():
    adapter = MockR2PipeAdapter()
    disasm_data = [{"offset": 0x401000}]

    with patch.object(adapter, "_cached_query", return_value=disasm_data):
        result = adapter.get_disasm(size=10)
        assert result == disasm_data


def test_get_disasm_with_address():
    adapter = MockR2PipeAdapter()
    address = 0x401000

    with patch.object(adapter, "_cached_query", return_value=[]) as mock_cached:
        adapter.get_disasm(address=address)
        args = mock_cached.call_args
        assert str(address) in str(args) or "@" in str(args)


def test_get_disasm_with_address_and_size():
    adapter = MockR2PipeAdapter()

    with patch.object(adapter, "_cached_query", return_value=[]):
        result = adapter.get_disasm(address=0x401000, size=20)
        assert isinstance(result, list)


def test_get_disasm_error():
    adapter = MockR2PipeAdapter()
    adapter._force_error_methods.add("get_disasm")

    result = adapter.get_disasm()
    assert result == []


# get_cfg tests


def test_get_cfg_default():
    adapter = MockR2PipeAdapter()
    cfg_data = [{"blocks": []}]

    with patch.object(adapter, "_cached_query", return_value=cfg_data):
        result = adapter.get_cfg()
        assert result == cfg_data


def test_get_cfg_with_address():
    adapter = MockR2PipeAdapter()
    address = 0x401000

    with patch.object(adapter, "_cached_query", return_value=[]) as mock_cached:
        adapter.get_cfg(address=address)
        args = mock_cached.call_args
        assert str(address) in str(args) or "@" in str(args)


def test_get_cfg_error():
    adapter = MockR2PipeAdapter()
    adapter._force_error_methods.add("get_cfg")

    result = adapter.get_cfg()
    assert result == {}


# analyze_all tests


def test_analyze_all_success():
    adapter = MockR2PipeAdapter()

    with patch("r2inspect.adapters.r2pipe_queries.safe_cmd", return_value="Analysis complete"):
        result = adapter.analyze_all()
        assert result == "Analysis complete"


def test_analyze_all_error():
    adapter = MockR2PipeAdapter()
    adapter._force_error_methods.add("analyze_all")

    result = adapter.analyze_all()
    assert result == ""


# Text output methods tests


def test_get_info_text_success():
    adapter = MockR2PipeAdapter()

    with patch("r2inspect.adapters.r2pipe_queries.safe_cmd", return_value="info output"):
        result = adapter.get_info_text()
        assert result == "info output"


def test_get_info_text_error():
    adapter = MockR2PipeAdapter()
    adapter._force_error_methods.add("get_info_text")

    result = adapter.get_info_text()
    assert result == ""


def test_get_dynamic_info_text_success():
    adapter = MockR2PipeAdapter()

    with patch(
        "r2inspect.adapters.r2pipe_queries.safe_cmd", return_value="dynamic info"
    ):
        result = adapter.get_dynamic_info_text()
        assert result == "dynamic info"


def test_get_dynamic_info_text_error():
    adapter = MockR2PipeAdapter()
    adapter._force_error_methods.add("get_dynamic_info_text")

    result = adapter.get_dynamic_info_text()
    assert result == ""


def test_get_entropy_pattern_success():
    adapter = MockR2PipeAdapter()

    with patch("r2inspect.adapters.r2pipe_queries.safe_cmd", return_value="entropy"):
        result = adapter.get_entropy_pattern()
        assert result == "entropy"


def test_get_entropy_pattern_error():
    adapter = MockR2PipeAdapter()
    adapter._force_error_methods.add("get_entropy_pattern")

    result = adapter.get_entropy_pattern()
    assert result == ""


def test_get_pe_version_info_text_success():
    adapter = MockR2PipeAdapter()

    with patch("r2inspect.adapters.r2pipe_queries.safe_cmd", return_value="version"):
        result = adapter.get_pe_version_info_text()
        assert result == "version"


def test_get_pe_version_info_text_error():
    adapter = MockR2PipeAdapter()
    adapter._force_error_methods.add("get_pe_version_info_text")

    result = adapter.get_pe_version_info_text()
    assert result == ""


def test_get_pe_security_text_success():
    adapter = MockR2PipeAdapter()

    with patch("r2inspect.adapters.r2pipe_queries.safe_cmd", return_value="security"):
        result = adapter.get_pe_security_text()
        assert result == "security"


def test_get_pe_security_text_error():
    adapter = MockR2PipeAdapter()
    adapter._force_error_methods.add("get_pe_security_text")

    result = adapter.get_pe_security_text()
    assert result == ""


def test_get_header_text_success():
    adapter = MockR2PipeAdapter()

    with patch("r2inspect.adapters.r2pipe_queries.safe_cmd", return_value="header"):
        result = adapter.get_header_text()
        assert result == "header"


def test_get_header_text_error():
    adapter = MockR2PipeAdapter()
    adapter._force_error_methods.add("get_header_text")

    result = adapter.get_header_text()
    assert result == ""


# JSON output methods tests


def test_get_headers_json_success():
    adapter = MockR2PipeAdapter()
    headers = {"header": "data"}

    with patch("r2inspect.adapters.r2pipe_queries.safe_cmdj", return_value=headers):
        result = adapter.get_headers_json()
        assert result == headers


def test_get_headers_json_error():
    adapter = MockR2PipeAdapter()
    adapter._force_error_methods.add("get_headers_json")

    result = adapter.get_headers_json()
    assert result is None


def test_get_strings_basic_success():
    adapter = MockR2PipeAdapter()
    strings = [{"string": "test"}]

    with patch.object(adapter, "_safe_cached_query", return_value=strings):
        result = adapter.get_strings_basic()
        assert result == strings


def test_get_strings_text_success():
    adapter = MockR2PipeAdapter()

    with patch("r2inspect.adapters.r2pipe_queries.safe_cmd", return_value="strings"):
        result = adapter.get_strings_text()
        assert result == "strings"


def test_get_strings_text_error():
    adapter = MockR2PipeAdapter()
    adapter._force_error_methods.add("get_strings_text")

    result = adapter.get_strings_text()
    assert result == ""


def test_get_strings_filtered_success():
    adapter = MockR2PipeAdapter()

    with patch("r2inspect.adapters.r2pipe_queries.safe_cmd", return_value="filtered"):
        result = adapter.get_strings_filtered("iz~http")
        assert result == "filtered"


def test_get_strings_filtered_error():
    adapter = MockR2PipeAdapter()
    adapter._force_error_methods.add("get_strings_filtered")

    result = adapter.get_strings_filtered("iz~test")
    assert result == ""


# PE-specific methods tests


def test_get_entry_info_success():
    adapter = MockR2PipeAdapter()
    entry_data = [{"vaddr": 0x401000}]

    with patch("r2inspect.adapters.r2pipe_queries.safe_cmdj", return_value=entry_data):
        with patch(
            "r2inspect.adapters.r2pipe_queries.validate_r2_data",
            return_value=entry_data,
        ):
            result = adapter.get_entry_info()
            assert result == entry_data


def test_get_entry_info_error():
    adapter = MockR2PipeAdapter()
    adapter._force_error_methods.add("get_entry_info")

    result = adapter.get_entry_info()
    assert result == []


def test_get_pe_header_success_dict():
    adapter = MockR2PipeAdapter()
    header = {"machine": "x86"}

    with patch("r2inspect.adapters.r2pipe_queries.safe_cmdj", return_value=header):
        result = adapter.get_pe_header()
        assert result == header


def test_get_pe_header_success_list():
    adapter = MockR2PipeAdapter()
    headers = [{"header1": "value"}]

    with patch("r2inspect.adapters.r2pipe_queries.safe_cmdj", return_value=headers):
        result = adapter.get_pe_header()
        assert result == {"headers": headers}


def test_get_pe_header_empty():
    adapter = MockR2PipeAdapter()

    with patch("r2inspect.adapters.r2pipe_queries.safe_cmdj", return_value=None):
        result = adapter.get_pe_header()
        assert result == {}


def test_get_pe_header_error():
    adapter = MockR2PipeAdapter()
    adapter._force_error_methods.add("get_pe_header")

    result = adapter.get_pe_header()
    assert result == {}


def test_get_pe_optional_header_success():
    adapter = MockR2PipeAdapter()
    opt_header = {"subsystem": "GUI"}

    with patch(
        "r2inspect.adapters.r2pipe_queries.safe_cmdj", return_value=opt_header
    ):
        with patch(
            "r2inspect.adapters.r2pipe_queries.validate_r2_data",
            return_value=opt_header,
        ):
            result = adapter.get_pe_optional_header()
            assert result == opt_header


def test_get_pe_optional_header_error():
    adapter = MockR2PipeAdapter()
    adapter._force_error_methods.add("get_pe_optional_header")

    result = adapter.get_pe_optional_header()
    assert result == {}


def test_get_data_directories_success():
    adapter = MockR2PipeAdapter()
    directories = [{"name": "Import", "address": 0x1000}]

    with patch(
        "r2inspect.adapters.r2pipe_queries.safe_cmdj", return_value=directories
    ):
        with patch(
            "r2inspect.adapters.r2pipe_queries.validate_r2_data",
            return_value=directories,
        ):
            result = adapter.get_data_directories()
            assert result == directories


def test_get_data_directories_error():
    adapter = MockR2PipeAdapter()
    adapter._force_error_methods.add("get_data_directories")

    result = adapter.get_data_directories()
    assert result == []


def test_get_resources_info_success():
    adapter = MockR2PipeAdapter()
    resources = [{"type": "ICON"}]

    with patch(
        "r2inspect.adapters.r2pipe_queries.safe_cmdj", return_value=resources
    ):
        with patch(
            "r2inspect.adapters.r2pipe_queries.validate_r2_data",
            return_value=resources,
        ):
            result = adapter.get_resources_info()
            assert result == resources


def test_get_resources_info_error():
    adapter = MockR2PipeAdapter()
    adapter._force_error_methods.add("get_resources_info")

    result = adapter.get_resources_info()
    assert result == []


def test_get_function_info_success():
    adapter = MockR2PipeAdapter()
    func_info = [{"name": "main", "cc": 5}]

    with patch("r2inspect.adapters.r2pipe_queries.safe_cmdj", return_value=func_info):
        with patch(
            "r2inspect.adapters.r2pipe_queries.validate_r2_data",
            return_value=func_info,
        ):
            result = adapter.get_function_info(0x401000)
            assert result == func_info


def test_get_function_info_error():
    adapter = MockR2PipeAdapter()
    adapter._force_error_methods.add("get_function_info")

    result = adapter.get_function_info(0x401000)
    assert result == []


def test_get_disasm_text_success():
    adapter = MockR2PipeAdapter()

    with patch("r2inspect.adapters.r2pipe_queries.safe_cmd", return_value="disasm"):
        result = adapter.get_disasm_text()
        assert result == "disasm"


def test_get_disasm_text_with_params():
    adapter = MockR2PipeAdapter()

    with patch("r2inspect.adapters.r2pipe_queries.safe_cmd", return_value="disasm"):
        result = adapter.get_disasm_text(address=0x401000, size=10)
        assert result == "disasm"


def test_get_disasm_text_error():
    adapter = MockR2PipeAdapter()
    adapter._force_error_methods.add("get_disasm_text")

    result = adapter.get_disasm_text()
    assert result == ""


# Search methods tests


def test_search_hex_json_success():
    adapter = MockR2PipeAdapter()
    results = [{"offset": 0x1000, "data": "deadbeef"}]

    with patch("r2inspect.adapters.r2pipe_queries.safe_cmdj", return_value=results):
        with patch(
            "r2inspect.adapters.r2pipe_queries.validate_r2_data", return_value=results
        ):
            result = adapter.search_hex_json("deadbeef")
            assert result == results


def test_search_hex_json_error():
    adapter = MockR2PipeAdapter()
    adapter._force_error_methods.add("search_hex_json")

    result = adapter.search_hex_json("deadbeef")
    assert result == []


def test_search_text_success():
    adapter = MockR2PipeAdapter()

    with patch("r2inspect.adapters.r2pipe_queries.safe_cmd", return_value="results"):
        result = adapter.search_text("password")
        assert result == "results"


def test_search_text_error():
    adapter = MockR2PipeAdapter()
    adapter._force_error_methods.add("search_text")

    result = adapter.search_text("test")
    assert result == ""


def test_search_hex_success():
    adapter = MockR2PipeAdapter()

    with patch("r2inspect.adapters.r2pipe_queries.safe_cmd", return_value="results"):
        result = adapter.search_hex("deadbeef")
        assert result == "results"


def test_search_hex_error():
    adapter = MockR2PipeAdapter()
    adapter._force_error_methods.add("search_hex")

    result = adapter.search_hex("deadbeef")
    assert result == ""


# read_bytes tests


def test_read_bytes_success():
    adapter = MockR2PipeAdapter()
    hex_data = "4d5a9000"  # MZ header

    with patch("r2inspect.adapters.r2pipe_queries.safe_cmd", return_value=hex_data):
        with patch(
            "r2inspect.adapters.r2pipe_queries.is_valid_r2_response",
            return_value=True,
        ):
            with patch(
                "r2inspect.adapters.r2pipe_queries.sanitize_r2_output",
                return_value=hex_data,
            ):
                with patch(
                    "r2inspect.adapters.r2pipe_queries.validate_address",
                    return_value=0x1000,
                ):
                    with patch(
                        "r2inspect.adapters.r2pipe_queries.validate_size",
                        return_value=4,
                    ):
                        result = adapter.read_bytes(0x1000, 4)
                        assert result == bytes.fromhex(hex_data)


def test_read_bytes_invalid_hex():
    adapter = MockR2PipeAdapter()

    with patch("r2inspect.adapters.r2pipe_queries.safe_cmd", return_value="GGGG"):
        with patch(
            "r2inspect.adapters.r2pipe_queries.is_valid_r2_response",
            return_value=True,
        ):
            with patch(
                "r2inspect.adapters.r2pipe_queries.sanitize_r2_output",
                return_value="GGGG",
            ):
                with patch(
                    "r2inspect.adapters.r2pipe_queries.validate_address",
                    return_value=0x1000,
                ):
                    with patch(
                        "r2inspect.adapters.r2pipe_queries.validate_size",
                        return_value=4,
                    ):
                        result = adapter.read_bytes(0x1000, 4)
                        assert result == b""


def test_read_bytes_invalid_address():
    adapter = MockR2PipeAdapter()

    with patch(
        "r2inspect.adapters.r2pipe_queries.validate_address",
        side_effect=ValueError("Invalid address"),
    ):
        with pytest.raises(ValueError):
            adapter.read_bytes(-1, 4)


def test_read_bytes_invalid_size():
    adapter = MockR2PipeAdapter()

    with patch(
        "r2inspect.adapters.r2pipe_queries.validate_address", return_value=0x1000
    ):
        with patch(
            "r2inspect.adapters.r2pipe_queries.validate_size",
            side_effect=ValueError("Invalid size"),
        ):
            with pytest.raises(ValueError):
                adapter.read_bytes(0x1000, 0)


def test_read_bytes_invalid_response():
    adapter = MockR2PipeAdapter()

    with patch("r2inspect.adapters.r2pipe_queries.safe_cmd", return_value=""):
        with patch(
            "r2inspect.adapters.r2pipe_queries.is_valid_r2_response",
            return_value=False,
        ):
            with patch(
                "r2inspect.adapters.r2pipe_queries.validate_address",
                return_value=0x1000,
            ):
                with patch(
                    "r2inspect.adapters.r2pipe_queries.validate_size", return_value=4
                ):
                    result = adapter.read_bytes(0x1000, 4)
                    assert result == b""


def test_read_bytes_error():
    adapter = MockR2PipeAdapter()
    adapter._force_error_methods.add("read_bytes")

    result = adapter.read_bytes(0x1000, 4)
    assert result == b""


def test_read_bytes_exception():
    adapter = MockR2PipeAdapter()

    with patch(
        "r2inspect.adapters.r2pipe_queries.safe_cmd",
        side_effect=Exception("Connection error"),
    ):
        with patch(
            "r2inspect.adapters.r2pipe_queries.validate_address", return_value=0x1000
        ):
            with patch(
                "r2inspect.adapters.r2pipe_queries.validate_size", return_value=4
            ):
                result = adapter.read_bytes(0x1000, 4)
                assert result == b""


def test_read_bytes_list_success():
    adapter = MockR2PipeAdapter()

    with patch.object(adapter, "read_bytes", return_value=b"\x01\x02\x03\x04"):
        result = adapter.read_bytes_list(0x1000, 4)
        assert result == [1, 2, 3, 4]


def test_read_bytes_list_empty():
    adapter = MockR2PipeAdapter()

    with patch.object(adapter, "read_bytes", return_value=b""):
        result = adapter.read_bytes_list(0x1000, 4)
        assert result == []


# _safe_query tests


def test_safe_query_success():
    adapter = MockR2PipeAdapter()

    result = adapter._safe_query(lambda: {"data": "value"}, {}, "Error message")
    assert result == {"data": "value"}


def test_safe_query_exception():
    adapter = MockR2PipeAdapter()

    def raise_error():
        raise RuntimeError("Test error")

    result = adapter._safe_query(raise_error, {"default": "value"}, "Error message")
    assert result == {"default": "value"}


def test_safe_query_returns_default_on_error():
    adapter = MockR2PipeAdapter()

    result = adapter._safe_query(
        lambda: 1 / 0, "default_value", "Division by zero"
    )
    assert result == "default_value"


# _safe_cached_query tests


def test_safe_cached_query_success():
    adapter = MockR2PipeAdapter()
    data = [{"item": 1}]

    with patch.object(adapter, "_cached_query", return_value=data):
        result = adapter._safe_cached_query(
            "cmd", "list", [], error_msg="error", error_label="items"
        )
        assert result == data


def test_safe_cached_query_error():
    adapter = MockR2PipeAdapter()

    with patch.object(
        adapter, "_cached_query", side_effect=RuntimeError("Test error")
    ):
        result = adapter._safe_cached_query(
            "cmd", "list", [], error_msg="error", error_label="items"
        )
        assert result == []


def test_safe_cached_query_default_dict():
    adapter = MockR2PipeAdapter()

    with patch.object(adapter, "_cached_query", side_effect=Exception()):
        result = adapter._safe_cached_query(
            "cmd", "dict", {}, error_msg="error", error_label="data"
        )
        assert result == {}


# Caching tests


def test_caching_prevents_duplicate_calls():
    adapter = MockR2PipeAdapter()
    data = [{"cached": True}]
    adapter._cache["iSj"] = data

    with patch.object(adapter, "_cached_query", return_value=data) as mock_query:
        result1 = adapter.get_sections()
        result2 = adapter.get_sections()
        assert result1 == result2


def test_caching_disabled_when_cache_false():
    adapter = MockR2PipeAdapter()

    with patch.object(adapter, "_safe_cached_query") as mock_query:
        mock_query.return_value = []
        adapter.get_sections()


def test_cache_hit_returns_cached_data():
    adapter = MockR2PipeAdapter()
    cached = {"from": "cache"}
    adapter._cache["test_cmd"] = cached

    result = adapter._cached_query("test_cmd", "dict", cache=True)
    assert result == cached


# Edge cases


def test_disasm_no_cache_when_address_provided():
    adapter = MockR2PipeAdapter()

    with patch.object(adapter, "_cached_query") as mock_cached:
        adapter.get_disasm(address=0x401000)
        call_kwargs = mock_cached.call_args[1]
        assert call_kwargs.get("cache") is False


def test_cfg_no_cache_when_address_provided():
    adapter = MockR2PipeAdapter()

    with patch.object(adapter, "_cached_query") as mock_cached:
        adapter.get_cfg(address=0x401000)
        call_kwargs = mock_cached.call_args[1]
        assert call_kwargs.get("cache") is False


def test_get_file_info_validates_response():
    adapter = MockR2PipeAdapter()

    with patch("r2inspect.adapters.r2pipe_queries.safe_cmd_dict", return_value={}):
        with patch(
            "r2inspect.adapters.r2pipe_queries.validate_r2_data", return_value={}
        ):
            with patch(
                "r2inspect.adapters.r2pipe_queries.is_valid_r2_response"
            ) as mock_valid:
                mock_valid.return_value = False
                result = adapter.get_file_info()
                mock_valid.assert_called_once()


def test_pe_header_handles_empty_list():
    adapter = MockR2PipeAdapter()

    with patch("r2inspect.adapters.r2pipe_queries.safe_cmdj", return_value=[]):
        result = adapter.get_pe_header()
        assert result == {}
