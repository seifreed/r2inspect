from __future__ import annotations

import sys

from r2inspect import __main__ as r2_main


def test_main_entrypoint_help() -> None:
    original = sys.argv[:]
    try:
        sys.argv = ["r2inspect", "--help"]
        code = r2_main.main()
        assert isinstance(code, int)
        assert code == 0
    finally:
        sys.argv = original
