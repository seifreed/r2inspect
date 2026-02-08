from __future__ import annotations

import pytest

from r2inspect.adapters.validation import (
    is_valid_r2_response,
    sanitize_r2_output,
    validate_address,
    validate_r2_data,
    validate_size,
)


def test_validate_r2_data_dict_and_list_cleaning():
    data = {"k": "&lt;tag&gt; &amp; text"}
    cleaned = validate_r2_data(data, "dict")
    assert cleaned["k"] == "<tag> & text"

    items = [{"v": "&quot;ok&quot;"}, "bad", 123]
    cleaned_list = validate_r2_data(items, "list")
    assert cleaned_list == [{"v": '"ok"'}]


def test_validate_r2_data_str_and_bytes():
    assert validate_r2_data("", "str") == ""
    assert validate_r2_data(b"hello", "str") == "hello"
    assert validate_r2_data("hi", "bytes") == b"hi"


def test_validate_r2_data_unknown_type():
    obj = object()
    assert validate_r2_data(obj, "unknown") is obj


def test_sanitize_r2_output():
    raw = "Section .text\x1b[0m\n  Size:&nbsp;0x1000 &amp; more"
    clean = sanitize_r2_output(raw)
    assert "\x1b" not in clean
    assert "&nbsp;" not in clean
    assert "&" in clean


def test_is_valid_r2_response():
    assert is_valid_r2_response({"a": 1}) is True
    assert is_valid_r2_response([]) is False
    assert is_valid_r2_response("") is False
    assert is_valid_r2_response("Error: bad") is False
    assert is_valid_r2_response(b"abc") is True


def test_validate_address():
    assert validate_address("0x10") == 16
    assert validate_address("32") == 32
    assert validate_address(5) == 5
    with pytest.raises(ValueError):
        validate_address("-1")
    with pytest.raises(ValueError):
        validate_address(-1)
    with pytest.raises(ValueError):
        validate_address("bad")
    with pytest.raises(ValueError):
        validate_address(None)


def test_validate_size():
    assert validate_size("0x10") == 16
    assert validate_size("32") == 32
    assert validate_size(5) == 5
    with pytest.raises(ValueError):
        validate_size("0")
    with pytest.raises(ValueError):
        validate_size(0)
    with pytest.raises(ValueError):
        validate_size("bad")
    with pytest.raises(ValueError):
        validate_size(None)
