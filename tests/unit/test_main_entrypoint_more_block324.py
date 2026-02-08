from __future__ import annotations

import sys

import pytest

from r2inspect import __main__ as main_module


@pytest.mark.unit
def test_main_returns_nonzero_on_validation_error() -> None:
    original_argv = sys.argv
    try:
        sys.argv = ["r2inspect"]
        exit_code = main_module.main()
        assert exit_code == 1
    finally:
        sys.argv = original_argv
