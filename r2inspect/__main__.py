#!/usr/bin/env python3
"""
r2inspect package main entry point
"""

# Import click CLI entry point for proper argument parsing
from r2inspect.cli_main import cli


def main(argv: list[str] | None = None) -> int:
    """Execute the CLI entry point and return an exit code.

    ``argv`` defaults to ``None``, which lets click read ``sys.argv`` exactly
    as before; tests pass an explicit list instead of mutating ``sys.argv``.
    """
    try:
        cli(args=argv)
    except SystemExit as exc:
        code = exc.code
        return int(code) if code is not None else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
