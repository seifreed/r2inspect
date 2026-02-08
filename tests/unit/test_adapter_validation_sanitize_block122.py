from __future__ import annotations

from r2inspect.adapters.validation import is_valid_r2_response, sanitize_r2_output, validate_r2_data


def test_validate_r2_data_dict_and_list_cleaning():
    data = {"name": "foo&nbsp;bar", "other": "A&amp;B"}
    cleaned = validate_r2_data(data, "dict")
    assert cleaned["name"] == "foo bar"
    assert cleaned["other"] == "A&B"

    list_data = [
        {"name": "a&amp;b"},
        "bad",
        123,
        {"name": "ok"},
    ]
    cleaned_list = validate_r2_data(list_data, "list")
    assert len(cleaned_list) == 2
    assert cleaned_list[0]["name"] == "a&b"


def test_sanitize_r2_output_and_valid_response():
    raw = "Section .text\x1b[0m\n  Size: 0x1000 &lt;ok&gt;"
    cleaned = sanitize_r2_output(raw)
    assert "\x1b" not in cleaned
    assert "<ok>" in cleaned

    assert is_valid_r2_response({"a": 1}) is True
    assert is_valid_r2_response([]) is False
    assert is_valid_r2_response("") is False
    assert is_valid_r2_response("Error: Failed to open") is False
