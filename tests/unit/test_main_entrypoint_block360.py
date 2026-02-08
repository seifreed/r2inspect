from __future__ import annotations

import sys

from r2inspect import __main__


def test_main_entrypoint_help() -> None:
    argv = sys.argv[:]
    try:
        sys.argv = ["r2inspect", "--help"]
        assert __main__.main() == 0
    finally:
        sys.argv = argv
