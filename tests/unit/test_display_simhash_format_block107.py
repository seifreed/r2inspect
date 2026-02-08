from __future__ import annotations

from r2inspect.cli.display import _format_simhash_hex


def test_format_simhash_hex_splits_long_value():
    value = "a" * 40
    formatted = _format_simhash_hex(value)
    assert "\n" in formatted
    left, right = formatted.split("\n", 1)
    assert left == value[:32]
    assert right == value[32:]


def test_format_simhash_hex_short_value():
    value = "b" * 12
    assert _format_simhash_hex(value) == value
