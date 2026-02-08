from __future__ import annotations

import sys

from r2inspect import __main__


def test_main_entrypoint_handles_system_exit() -> None:
    original_argv = sys.argv[:]
    try:
        sys.argv = ["r2inspect", "--help"]
        assert __main__.main() == 0
    finally:
        sys.argv = original_argv
