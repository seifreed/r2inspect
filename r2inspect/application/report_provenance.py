"""Runtime provenance helpers for report/v1."""

from __future__ import annotations

import os
from functools import cache
from pathlib import Path

from ..infrastructure.command_runner import run_command


@cache
def command_output(command: tuple[str, ...], cwd: str | None = None) -> str | None:
    try:
        completed = run_command(command, cwd=cwd, timeout=2)
    except (OSError, TimeoutError, ValueError):
        return None
    output = completed.stdout.strip()
    return output.splitlines()[0] if completed.returncode == 0 and output else None


def tool_commit() -> str | None:
    return os.getenv("R2INSPECT_COMMIT") or command_output(
        ("git", "rev-parse", "HEAD"), str(Path(__file__).resolve().parents[2])
    )


def radare2_version() -> str | None:
    return os.getenv("R2INSPECT_RADARE2_VERSION") or command_output(("r2", "-v"))
