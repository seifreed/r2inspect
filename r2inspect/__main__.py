#!/usr/bin/env python3
"""
r2inspect package main entry point
"""

# Import click CLI entry point for proper argument parsing
from r2inspect.cli_main import cli


def main() -> int:
    """Execute the CLI entry point and return an exit code."""
    try:
        cli()
    except SystemExit as exc:
        code = exc.code
        return int(code) if code is not None else 0
    return 0  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(main())
