#!/usr/bin/env python3
"""coerce_int must preserve zero-padded decimal strings.

base-0 int() parsing auto-detects 0x/0b prefixes but raises on a leading-zero
decimal like "010" or "08", which previously fell through to the default and
silently lost the value.
"""

from __future__ import annotations

import pytest

from r2inspect.abstractions.coercion_support import coerce_int


@pytest.mark.unit
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("010", 10),
        ("08", 8),
        ("09", 9),
        ("0x10", 16),
        ("0b101", 5),
        ("123", 123),
        (42, 42),
        (None, 0),
        ("nope", 0),
    ],
)
def test_coerce_int_parses_padded_and_prefixed(value: object, expected: int) -> None:
    assert coerce_int(value) == expected


@pytest.mark.unit
def test_coerce_int_uses_default_on_garbage() -> None:
    assert coerce_int("nope", default=7) == 7
