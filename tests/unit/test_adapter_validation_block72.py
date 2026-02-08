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
    data = {"k": "&lt;tag&gt;"}
    cleaned = validate_r2_data(data, "dict")
    assert cleaned["k"] == "<tag>"

    items = ["bad", {"v": "&amp;"}, 1]
    cleaned_list = validate_r2_data(items, "list")
    assert cleaned_list == [{"v": "&"}]


def test_validate_r2_data_str_bytes_any():
    raw = "Section\x1b[0m &quot;X&quot;"
    assert sanitize_r2_output(raw) == 'Section "X"'
    assert validate_r2_data(raw, "str") == 'Section "X"'

    assert validate_r2_data(b"ABC", "str") == "ABC"
    assert validate_r2_data(b"ABC", "bytes") == b"ABC"
    assert validate_r2_data("ABC", "bytes") == b"ABC"

    marker = object()
    assert validate_r2_data(marker, "any") is marker


def test_validate_r2_data_unknown_type():
    assert validate_r2_data(123, "unknown") == 123


def test_is_valid_r2_response():
    assert is_valid_r2_response({"a": 1}) is True
    assert is_valid_r2_response([]) is False
    assert is_valid_r2_response("") is False
    assert is_valid_r2_response("Cannot open file") is False
    assert is_valid_r2_response(b"x") is True


def test_validate_address_and_size():
    assert validate_address("0x10") == 16
    assert validate_address("32") == 32
    assert validate_address(5) == 5

    with pytest.raises(ValueError):
        validate_address(-1)
    with pytest.raises(ValueError):
        validate_address("-1")
    with pytest.raises(ValueError):
        validate_address(object())

    assert validate_size("0x10") == 16
    assert validate_size("32") == 32
    assert validate_size(8) == 8

    with pytest.raises(ValueError):
        validate_size(0)
    with pytest.raises(ValueError):
        validate_size("-1")
    with pytest.raises(ValueError):
        validate_size(object())
