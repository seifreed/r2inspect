import pytest

from r2inspect.adapters.validation import (
    is_valid_r2_response,
    sanitize_r2_output,
    validate_address,
    validate_r2_data,
    validate_size,
)


def test_validate_r2_data_types():
    assert validate_r2_data({"a": 1}, "dict") == {"a": 1}
    assert validate_r2_data([{"name": "x"}], "list") == [{"name": "x"}]
    assert validate_r2_data("text", "str") == "text"
    assert validate_r2_data(b"bytes", "str") == "bytes"
    assert validate_r2_data("x", "bytes") == b"x"


def test_sanitize_r2_output_removes_ansi_and_entities():
    raw = "Section \x1b[0m &amp; test"
    cleaned = sanitize_r2_output(raw)
    assert "\x1b" not in cleaned
    assert "&" in cleaned


def test_is_valid_r2_response():
    assert is_valid_r2_response({"a": 1}) is True
    assert is_valid_r2_response([]) is False
    assert is_valid_r2_response("Cannot open file") is False
    assert is_valid_r2_response("ok") is True


def test_validate_address_and_size():
    assert validate_address("0x10") == 16
    assert validate_address(16) == 16
    with pytest.raises(ValueError):
        validate_address(-1)

    assert validate_size("0x10") == 16
    assert validate_size(16) == 16
    with pytest.raises(ValueError):
        validate_size(0)
