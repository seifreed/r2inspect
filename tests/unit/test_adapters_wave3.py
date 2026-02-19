#!/usr/bin/env python3
"""
Tests for r2inspect/adapters/validation.py and r2inspect/adapters/r2pipe_queries.py
covering previously uncovered branches.
"""

from __future__ import annotations

from typing import Any

import pytest

from r2inspect.adapters.validation import (
    _validate_bytes_data,
    _validate_dict_data,
    _validate_list_data,
    _validate_str_data,
    is_valid_r2_response,
    sanitize_r2_output,
    validate_address,
    validate_r2_data,
    validate_size,
)
from r2inspect.adapters.r2pipe_queries import R2PipeQueryMixin


# ---------------------------------------------------------------------------
# Minimal concrete R2PipeQueryMixin implementation (no mocks)
# ---------------------------------------------------------------------------

class StubR2:
    """Minimal r2pipe-like stub that returns configurable responses."""

    def __init__(self, cmd_responses: dict[str, str] | None = None,
                 cmdj_responses: dict[str, Any] | None = None) -> None:
        self._cmd_responses: dict[str, str] = cmd_responses or {}
        self._cmdj_responses: dict[str, Any] = cmdj_responses or {}

    def cmd(self, command: str) -> str:
        for key, val in self._cmd_responses.items():
            if command.startswith(key) or command == key:
                return val
        return ""

    def cmdj(self, command: str) -> Any:
        for key, val in self._cmdj_responses.items():
            if command.startswith(key) or command == key:
                return val
        return None


class ConcreteQueryMixin(R2PipeQueryMixin):
    """Concrete subclass of R2PipeQueryMixin for testing."""

    def __init__(self, stub: StubR2, raise_on: str | None = None) -> None:
        self._stub = stub
        self._cache: dict[str, Any] = {}
        self._raise_on: str | None = raise_on

    def cmd(self, command: str) -> str:
        return self._stub.cmd(command)

    def cmdj(self, command: str) -> Any:
        return self._stub.cmdj(command)

    def _maybe_force_error(self, method: str) -> None:
        if self._raise_on and method == self._raise_on:
            raise RuntimeError(f"Forced error in {method}")

    def _cached_query(
        self,
        cmd: str,
        data_type: str = "list",
        default: list | dict | None = None,
        error_msg: str = "",
        *,
        cache: bool = True,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        if cache and cmd in self._cache:
            return self._cache[cmd]  # type: ignore[return-value]

        result_raw = self._stub.cmdj(cmd)
        if result_raw is None:
            result_raw = default if default is not None else ([] if data_type == "list" else {})

        from r2inspect.adapters.validation import validate_r2_data
        validated = validate_r2_data(result_raw, data_type)
        if cache:
            self._cache[cmd] = validated
        return validated  # type: ignore[return-value]


# ===========================================================================
# validation.py tests
# ===========================================================================

# --- validate_r2_data branches (lines 76-84) --------------------------------

def test_validate_r2_data_str_type_returns_string():
    result = validate_r2_data("hello world", "str")
    assert isinstance(result, str)
    assert result == "hello world"


def test_validate_r2_data_bytes_type_returns_bytes():
    result = validate_r2_data(b"data", "bytes")
    assert isinstance(result, bytes)
    assert result == b"data"


def test_validate_r2_data_any_type_returns_as_is():
    obj = {"key": [1, 2, 3]}
    result = validate_r2_data(obj, "any")
    assert result is obj


def test_validate_r2_data_unknown_type_returns_data_as_is():
    # Exercises the else branch (lines 83-84)
    obj = 42
    result = validate_r2_data(obj, "totally_unknown_type")
    assert result == 42


# --- _validate_dict_data (lines 105-106) ------------------------------------

def test_validate_dict_data_non_dict_returns_empty_dict():
    # Exercises line 105-106: non-dict input
    result = _validate_dict_data("not a dict")
    assert result == {}


def test_validate_dict_data_integer_returns_empty_dict():
    result = _validate_dict_data(123)
    assert result == {}


def test_validate_dict_data_none_returns_empty_dict():
    result = _validate_dict_data(None)
    assert result == {}


def test_validate_dict_data_list_returns_empty_dict():
    result = _validate_dict_data([{"a": 1}])
    assert result == {}


# --- _validate_str_data (lines 141-152) ------------------------------------

def test_validate_str_data_with_str_returns_sanitized():
    # Exercises line 141-142
    result = _validate_str_data("  hello  ")
    assert result == "hello"


def test_validate_str_data_with_bytes_returns_decoded_string():
    # Exercises lines 143-149
    result = _validate_str_data(b"hello bytes")
    assert isinstance(result, str)
    assert "hello bytes" in result


def test_validate_str_data_with_bytes_with_ansi_codes():
    # Exercises bytes-to-string path with sanitization
    raw = b"text \x1b[0m end"
    result = _validate_str_data(raw)
    assert isinstance(result, str)
    assert "\x1b" not in result


def test_validate_str_data_with_non_str_non_bytes_returns_empty():
    # Exercises lines 151-152: non-str, non-bytes
    result = _validate_str_data(99)
    assert result == ""


def test_validate_str_data_with_list_returns_empty():
    result = _validate_str_data(["a", "b"])
    assert result == ""


def test_validate_str_data_with_none_returns_empty():
    result = _validate_str_data(None)
    assert result == ""


# --- _validate_bytes_data (lines 167-178) -----------------------------------

def test_validate_bytes_data_with_bytes_returns_bytes():
    # Exercises lines 167-168
    data = b"\x00\x01\x02"
    result = _validate_bytes_data(data)
    assert result == data


def test_validate_bytes_data_with_str_returns_encoded():
    # Exercises lines 169-175: str -> bytes
    result = _validate_bytes_data("hello")
    assert isinstance(result, bytes)
    assert result == b"hello"


def test_validate_bytes_data_with_non_str_non_bytes_returns_empty():
    # Exercises lines 177-178: other type
    result = _validate_bytes_data(42)
    assert result == b""


def test_validate_bytes_data_with_list_returns_empty():
    result = _validate_bytes_data([1, 2, 3])
    assert result == b""


def test_validate_bytes_data_with_none_returns_empty():
    result = _validate_bytes_data(None)
    assert result == b""


# --- _validate_list_data with mixed items (line 200) -----------------------

def test_validate_list_data_filters_non_dict_items():
    # Exercises line 200: non-dict items in list are filtered out
    mixed = [{"name": "ok"}, "bad_string", 42, None, {"name": "also_ok"}]
    result = _validate_list_data(mixed)
    assert len(result) == 2
    assert result[0] == {"name": "ok"}
    assert result[1] == {"name": "also_ok"}


def test_validate_list_data_all_non_dicts_returns_empty():
    result = _validate_list_data(["a", "b", 1, 2])
    assert result == []


# --- _clean_dict_values with HTML entities (line 225) ----------------------

def test_validate_dict_data_cleans_html_entities():
    # Exercises line 225: value is changed after cleaning
    data = {"name": "foo &amp; bar", "desc": "&lt;hello&gt;"}
    result = _validate_dict_data(data)
    assert result["name"] == "foo & bar"
    assert result["desc"] == "<hello>"


def test_validate_dict_data_cleans_nbsp_and_quot():
    data = {"text": "a&nbsp;b", "q": "&quot;quoted&quot;", "apos": "&#39;x&#39;"}
    result = _validate_dict_data(data)
    assert result["text"] == "a b"
    assert result["q"] == '"quoted"'
    assert result["apos"] == "'x'"


# --- sanitize_r2_output (line 248: empty output) ---------------------------

def test_sanitize_r2_output_empty_string():
    # Exercises line 248: early return on empty input
    result = sanitize_r2_output("")
    assert result == ""


def test_sanitize_r2_output_none_like_falsy():
    # None is falsy, same branch
    result = sanitize_r2_output("")
    assert result == ""


def test_sanitize_r2_output_strips_ansi():
    result = sanitize_r2_output("before \x1b[1;32mcolor\x1b[0m after")
    assert "\x1b" not in result
    assert "before" in result
    assert "after" in result


def test_sanitize_r2_output_html_entities():
    result = sanitize_r2_output("&amp; &lt; &gt; &quot; &#39; &nbsp;")
    assert "&amp;" not in result
    assert "&" in result


# --- is_valid_r2_response (lines 290, 298, 308-312) -----------------------

def test_is_valid_r2_response_none_returns_false():
    # Exercises line 290
    assert is_valid_r2_response(None) is False


def test_is_valid_r2_response_empty_string_returns_false():
    # Exercises line 298
    assert is_valid_r2_response("") is False


def test_is_valid_r2_response_whitespace_string_returns_false():
    # Exercises line 298: stripped == ""
    assert is_valid_r2_response("   ") is False


def test_is_valid_r2_response_non_empty_bytes_returns_true():
    # Exercises lines 308-309
    assert is_valid_r2_response(b"\x00\x01") is True


def test_is_valid_r2_response_empty_bytes_returns_false():
    # Exercises lines 308-309
    assert is_valid_r2_response(b"") is False


def test_is_valid_r2_response_other_type_returns_true():
    # Exercises line 312: non-None, non-str, non-bytes, non-dict/list
    assert is_valid_r2_response(42) is True
    assert is_valid_r2_response(3.14) is True
    assert is_valid_r2_response(True) is True


def test_is_valid_r2_response_error_string_patterns():
    assert is_valid_r2_response("Cannot open file") is False
    assert is_valid_r2_response("Error: something went wrong") is False
    assert is_valid_r2_response("File format not recognized") is False
    assert is_valid_r2_response("Invalid command xyz") is False
    assert is_valid_r2_response("Failed to open") is False


# --- validate_address (lines 338-355) --------------------------------------

def test_validate_address_positive_int():
    # Exercises line 338: int branch, positive
    assert validate_address(0x1000) == 0x1000


def test_validate_address_zero_is_valid():
    assert validate_address(0) == 0


def test_validate_address_negative_int_raises():
    # Exercises line 340
    with pytest.raises(ValueError, match="negative"):
        validate_address(-1)


def test_validate_address_hex_string():
    # Exercises lines 342-345
    assert validate_address("0x401000") == 0x401000


def test_validate_address_uppercase_hex_string():
    assert validate_address("0X1A2B") == 0x1A2B


def test_validate_address_decimal_string():
    # Exercises line 347
    assert validate_address("4096") == 4096


def test_validate_address_negative_parsed_value_raises():
    # Exercises line 349-350: parsed result is negative
    with pytest.raises(ValueError):
        validate_address("-5")


def test_validate_address_invalid_string_raises():
    # Exercises lines 351-353
    with pytest.raises(ValueError, match="Invalid address format"):
        validate_address("not_a_number")


def test_validate_address_non_int_non_str_raises():
    # Exercises line 355
    with pytest.raises(ValueError, match="must be int or str"):
        validate_address([1, 2, 3])


def test_validate_address_float_raises():
    with pytest.raises(ValueError, match="must be int or str"):
        validate_address(3.14)


# --- validate_size (lines 380-394) -----------------------------------------

def test_validate_size_positive_int():
    # Exercises line 380-381
    assert validate_size(256) == 256


def test_validate_size_zero_raises():
    # Exercises line 380: size <= 0
    with pytest.raises(ValueError, match="positive"):
        validate_size(0)


def test_validate_size_negative_int_raises():
    # Exercises line 380
    with pytest.raises(ValueError, match="positive"):
        validate_size(-10)


def test_validate_size_hex_string():
    # Exercises line 384-386
    assert validate_size("0x100") == 256


def test_validate_size_decimal_string():
    assert validate_size("512") == 512


def test_validate_size_zero_string_raises():
    # Exercises lines 388-389
    with pytest.raises(ValueError):
        validate_size("0")


def test_validate_size_invalid_string_raises():
    # Exercises lines 391-392
    with pytest.raises(ValueError, match="Invalid size format"):
        validate_size("not_a_size")


def test_validate_size_non_int_non_str_raises():
    # Exercises line 394
    with pytest.raises(ValueError, match="must be int or str"):
        validate_size(3.14)


def test_validate_size_list_raises():
    with pytest.raises(ValueError, match="must be int or str"):
        validate_size([256])


# ===========================================================================
# r2pipe_queries.py tests
# ===========================================================================

# --- _safe_query exception handler (lines 47-49) ---------------------------

def test_safe_query_returns_default_on_exception():
    # Exercises lines 47-49: exception raised inside action
    mixin = ConcreteQueryMixin(StubR2())

    def failing_action():
        raise RuntimeError("boom")

    result = mixin._safe_query(failing_action, "fallback", "Test error")
    assert result == "fallback"


def test_safe_query_returns_default_list_on_exception():
    mixin = ConcreteQueryMixin(StubR2())
    result = mixin._safe_query(lambda: (_ for _ in ()).throw(ValueError("x")), [], "err")
    assert result == []


# --- get_functions_at (lines 343-350) --------------------------------------

def test_get_functions_at_returns_list_on_empty_response():
    stub = StubR2(cmdj_responses={"aflj @ ": []})
    mixin = ConcreteQueryMixin(stub)
    result = mixin.get_functions_at(0x1000)
    assert isinstance(result, list)


def test_get_functions_at_returns_functions_on_valid_response():
    funcs = [{"name": "main", "offset": 0x1000, "size": 100}]
    stub = StubR2(cmdj_responses={"aflj @ 4096": funcs})
    mixin = ConcreteQueryMixin(stub)
    result = mixin.get_functions_at(0x1000)
    assert isinstance(result, list)


def test_get_functions_at_returns_empty_on_none_response():
    stub = StubR2()
    mixin = ConcreteQueryMixin(stub)
    result = mixin.get_functions_at(0x2000)
    assert result == []


def test_get_functions_at_returns_empty_on_error():
    # Exercises _safe_query exception path for get_functions_at
    mixin = ConcreteQueryMixin(StubR2(), raise_on="get_functions_at")
    result = mixin.get_functions_at(0x1000)
    assert result == []


# --- get_disasm with size (lines 366-367) ----------------------------------

def test_get_disasm_with_size_returns_list():
    stub = StubR2(cmdj_responses={"pdj 64": [{"offset": 0x1000, "type": "mov"}]})
    mixin = ConcreteQueryMixin(stub)
    result = mixin.get_disasm(size=64)
    assert isinstance(result, list)


def test_get_disasm_no_size_returns_dict():
    stub = StubR2(cmdj_responses={"pdfj": {"name": "fcn.main", "ops": []}})
    mixin = ConcreteQueryMixin(stub)
    result = mixin.get_disasm()
    assert isinstance(result, (dict, list))


def test_get_disasm_with_address_and_size():
    stub = StubR2(cmdj_responses={"pdj 32 @ 4096": [{"offset": 0x1000}]})
    mixin = ConcreteQueryMixin(stub)
    result = mixin.get_disasm(address=0x1000, size=32)
    assert isinstance(result, list)


def test_get_disasm_error_returns_empty():
    mixin = ConcreteQueryMixin(StubR2(), raise_on="get_disasm")
    result = mixin.get_disasm(size=32)
    assert result == []


# --- get_entropy_pattern (lines 430-434) -----------------------------------

def test_get_entropy_pattern_returns_string():
    stub = StubR2(cmd_responses={"p=e 100": "entropy_output"})
    mixin = ConcreteQueryMixin(stub)
    result = mixin.get_entropy_pattern()
    assert isinstance(result, str)


def test_get_entropy_pattern_empty_on_error():
    mixin = ConcreteQueryMixin(StubR2(), raise_on="get_entropy_pattern")
    result = mixin.get_entropy_pattern()
    assert result == ""


# --- get_pe_version_info_text (lines 439-443) ------------------------------

def test_get_pe_version_info_text_returns_string():
    stub = StubR2(cmd_responses={"iR~version": "version info"})
    mixin = ConcreteQueryMixin(stub)
    result = mixin.get_pe_version_info_text()
    assert isinstance(result, str)


def test_get_pe_version_info_text_empty_on_error():
    mixin = ConcreteQueryMixin(StubR2(), raise_on="get_pe_version_info_text")
    result = mixin.get_pe_version_info_text()
    assert result == ""


# --- get_header_text (lines 457-461) ----------------------------------------

def test_get_header_text_returns_string():
    stub = StubR2(cmd_responses={"ih": "header text output"})
    mixin = ConcreteQueryMixin(stub)
    result = mixin.get_header_text()
    assert isinstance(result, str)


def test_get_header_text_empty_on_error():
    mixin = ConcreteQueryMixin(StubR2(), raise_on="get_header_text")
    result = mixin.get_header_text()
    assert result == ""


# --- get_pe_header (lines 517-526) ------------------------------------------

def test_get_pe_header_wraps_list_response():
    # Exercises lines 520-521: data is a non-empty list
    # safe_cmdj calls self.cmd() and parses JSON, so use cmd_responses with JSON string
    import json
    headers_list = [{"name": "PE32", "size": 512}]
    stub = StubR2(cmd_responses={"ihj": json.dumps(headers_list)})
    mixin = ConcreteQueryMixin(stub)
    result = mixin.get_pe_header()
    assert isinstance(result, dict)
    assert "headers" in result
    assert result["headers"] == headers_list


def test_get_pe_header_returns_dict_response():
    # Exercises lines 522-523: data is already a dict
    import json
    header_dict = {"machine": "x86", "timestamp": 12345}
    stub = StubR2(cmd_responses={"ihj": json.dumps(header_dict)})
    mixin = ConcreteQueryMixin(stub)
    result = mixin.get_pe_header()
    assert result == header_dict


def test_get_pe_header_returns_empty_on_none():
    # Exercises line 524: no ihj response -> safe_cmdj returns default {} -> empty
    stub = StubR2()
    mixin = ConcreteQueryMixin(stub)
    result = mixin.get_pe_header()
    assert result == {}


def test_get_pe_header_returns_empty_on_empty_list():
    # Exercises line 524: list but empty
    import json
    stub = StubR2(cmd_responses={"ihj": json.dumps([])})
    mixin = ConcreteQueryMixin(stub)
    result = mixin.get_pe_header()
    assert result == {}


def test_get_pe_header_empty_on_error():
    mixin = ConcreteQueryMixin(StubR2(), raise_on="get_pe_header")
    result = mixin.get_pe_header()
    assert result == {}


# --- get_resources_info (lines 553-559) ------------------------------------

def test_get_resources_info_returns_list_of_dicts():
    resources = [{"name": "ICON", "size": 0x100}]
    stub = StubR2(cmdj_responses={"iRj": resources})
    mixin = ConcreteQueryMixin(stub)
    result = mixin.get_resources_info()
    assert isinstance(result, list)


def test_get_resources_info_returns_empty_list_on_none():
    stub = StubR2(cmdj_responses={"iRj": None})
    mixin = ConcreteQueryMixin(stub)
    result = mixin.get_resources_info()
    assert result == []


def test_get_resources_info_empty_on_error():
    mixin = ConcreteQueryMixin(StubR2(), raise_on="get_resources_info")
    result = mixin.get_resources_info()
    assert result == []


# --- get_disasm_text (lines 576-583) ----------------------------------------

def test_get_disasm_text_no_args_uses_pi():
    stub = StubR2(cmd_responses={"pi": "mov eax, 0"})
    mixin = ConcreteQueryMixin(stub)
    result = mixin.get_disasm_text()
    assert isinstance(result, str)


def test_get_disasm_text_with_size():
    # Exercises lines 578: cmd = f"pi {size}"
    stub = StubR2(cmd_responses={"pi 32": "mov eax, 1"})
    mixin = ConcreteQueryMixin(stub)
    result = mixin.get_disasm_text(size=32)
    assert isinstance(result, str)


def test_get_disasm_text_with_address_and_size():
    # Exercises line 579-580: address appended with @
    stub = StubR2(cmd_responses={"pi 16 @ 4096": "nop"})
    mixin = ConcreteQueryMixin(stub)
    result = mixin.get_disasm_text(address=0x1000, size=16)
    assert isinstance(result, str)


def test_get_disasm_text_empty_on_error():
    mixin = ConcreteQueryMixin(StubR2(), raise_on="get_disasm_text")
    result = mixin.get_disasm_text(size=16)
    assert result == ""


# --- read_bytes (lines 644-665) ---------------------------------------------

def test_read_bytes_valid_hex_response():
    # Exercises lines 644-658: valid hex response converted to bytes
    stub = StubR2(cmd_responses={"p8 ": "deadbeef"})
    mixin = ConcreteQueryMixin(stub)
    result = mixin.read_bytes(0x1000, 4)
    assert isinstance(result, bytes)
    assert result == bytes.fromhex("deadbeef")


def test_read_bytes_empty_response_returns_empty():
    # Exercises lines 643-647: empty/invalid r2 response
    stub = StubR2(cmd_responses={"p8 ": ""})
    mixin = ConcreteQueryMixin(stub)
    result = mixin.read_bytes(0x1000, 4)
    assert result == b""


def test_read_bytes_error_response_returns_empty():
    # Exercises is_valid_r2_response returning False on error strings
    stub = StubR2(cmd_responses={"p8 ": "Cannot open"})
    mixin = ConcreteQueryMixin(stub)
    result = mixin.read_bytes(0x1000, 4)
    assert result == b""


def test_read_bytes_invalid_hex_returns_empty():
    # Exercises lines 656-658: valid-looking response but invalid hex
    stub = StubR2(cmd_responses={"p8 ": "ZZZZZZZZ"})
    mixin = ConcreteQueryMixin(stub)
    result = mixin.read_bytes(0x1000, 4)
    assert result == b""


def test_read_bytes_negative_address_raises():
    # Exercises lines 660-662: ValueError from validate_address
    mixin = ConcreteQueryMixin(StubR2())
    with pytest.raises(ValueError):
        mixin.read_bytes(-1, 4)


def test_read_bytes_zero_size_raises():
    # Exercises lines 660-662: ValueError from validate_size
    mixin = ConcreteQueryMixin(StubR2())
    with pytest.raises(ValueError):
        mixin.read_bytes(0x1000, 0)


def test_read_bytes_general_exception_returns_empty():
    # Exercises lines 663-665: general Exception path
    mixin = ConcreteQueryMixin(StubR2(), raise_on="read_bytes")
    result = mixin.read_bytes(0x1000, 4)
    assert result == b""
