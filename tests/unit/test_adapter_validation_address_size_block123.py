from __future__ import annotations

import pytest

from r2inspect.adapters.validation import validate_address, validate_size


def test_validate_address_parsing():
    assert validate_address("0x10") == 16
    assert validate_address("32") == 32
    assert validate_address(64) == 64

    with pytest.raises(ValueError):
        validate_address("-1")
    with pytest.raises(ValueError):
        validate_address(-5)
    with pytest.raises(ValueError):
        validate_address("notanumber")


def test_validate_size_parsing():
    assert validate_size("0x20") == 32
    assert validate_size("16") == 16
    assert validate_size(8) == 8

    with pytest.raises(ValueError):
        validate_size(0)
    with pytest.raises(ValueError):
        validate_size("-1")
    with pytest.raises(ValueError):
        validate_size("bad")
