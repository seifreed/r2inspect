from __future__ import annotations

from r2inspect.adapters import validation as v


def test_validate_dict_and_list_debug_paths() -> None:
    assert v._validate_dict_data({"ok": True}) == {"ok": True}
    assert v._validate_dict_data("nope") == {}
    assert v._validate_list_data([{"a": 1}]) == [{"a": 1}]
    assert v._validate_list_data("nope") == []
    assert v.validate_r2_data({"a": 1}, "dict") == {"a": 1}
    assert v.validate_r2_data([{"a": 1}], "list") == [{"a": 1}]
    assert v.validate_r2_data("ok", "str") == "ok"
    assert v.validate_r2_data(b"ok", "bytes") == b"ok"
    assert v.validate_r2_data({"a": 1}, "any") == {"a": 1}
    assert v.validate_r2_data("noop", "unknown") == "noop"


def test_validate_str_and_bytes_error_paths() -> None:
    class BadBytes(bytes):
        def decode(self, *args, **kwargs):  # type: ignore[override]
            raise UnicodeError("boom")

    class BadStr(str):
        def encode(self, *args, **kwargs):  # type: ignore[override]
            raise UnicodeError("boom")

    assert v._validate_str_data(BadBytes(b"bad")) == ""
    assert v._validate_str_data(123) == ""
    assert v._validate_str_data("ok") == "ok"
    assert v._validate_bytes_data(BadStr("bad")) == b""
    assert v._validate_bytes_data(123) == b""
    assert v._validate_bytes_data(b"ok") == b"ok"


def test_is_valid_response_none_and_other() -> None:
    assert v.is_valid_r2_response(None) is False

    class Custom:
        pass

    assert v.is_valid_r2_response(Custom()) is True


def test_clean_dict_values_and_sanitize_output() -> None:
    data = {"name": "a&nbsp;b&amp;c", "plain": "ok"}
    v._clean_dict_values(data)
    assert data["name"] == "a b&c"
    assert data["plain"] == "ok"
    assert v._clean_list_items([{"name": "x"}, "bad"]) == [{"name": "x"}]

    raw = "Section\x1b[0m\n\tSize:&nbsp;0x1000"
    cleaned = v.sanitize_r2_output(raw)
    assert "\x1b" not in cleaned
    assert "&nbsp;" not in cleaned
    assert cleaned.startswith("Section")
    assert v.sanitize_r2_output("") == ""


def test_is_valid_response_types() -> None:
    assert v.is_valid_r2_response({}) is False
    assert v.is_valid_r2_response({"a": 1}) is True
    assert v.is_valid_r2_response([]) is False
    assert v.is_valid_r2_response([{"a": 1}]) is True
    assert v.is_valid_r2_response("") is False
    assert v.is_valid_r2_response(" ") is False
    assert v.is_valid_r2_response("Error: bad") is False
    assert v.is_valid_r2_response("ok") is True
    assert v.is_valid_r2_response(b"") is False
    assert v.is_valid_r2_response(b"ok") is True


def test_validate_address_and_size() -> None:
    assert v.validate_address(10) == 10
    assert v.validate_address("0x10") == 16
    assert v.validate_address("20") == 20

    try:
        v.validate_address(-1)
    except ValueError:
        pass

    try:
        v.validate_address("bad")
    except ValueError:
        pass

    try:
        v.validate_address("-1")
    except ValueError:
        pass

    try:
        v.validate_address(object())
    except ValueError:
        pass

    assert v.validate_size(1) == 1
    assert v.validate_size("0x10") == 16
    assert v.validate_size("20") == 20

    try:
        v.validate_size(0)
    except ValueError:
        pass

    try:
        v.validate_size("bad")
    except ValueError:
        pass

    try:
        v.validate_size("-1")
    except ValueError:
        pass

    try:
        v.validate_size(object())
    except ValueError:
        pass
