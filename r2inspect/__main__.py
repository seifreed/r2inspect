#!/usr/bin/env python3
"""
r2inspect package main entry point
"""

import sys

# Import click CLI entry point for proper argument parsing
from r2inspect.cli_main import cli


def main(argv: list[str] | None = None) -> int:
    """Execute the CLI entry point and return an exit code.

    ``argv`` defaults to ``None``, which lets click read ``sys.argv`` exactly
    as before; tests pass an explicit list instead of mutating ``sys.argv``.
    """
    args = sys.argv[1:] if argv is None else argv
    try:
        if args[:1] == ["rules"]:
            from r2inspect.cli.rules_cli import rules_cli

            rules_cli(args=args[1:], prog_name="r2inspect rules")
        else:
            cli(args=args)
    except SystemExit as exc:
        code = exc.code
        return int(code) if code is not None else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
