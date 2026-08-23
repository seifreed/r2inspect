"""Constrained external command execution."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path


def run_command(
    command: Sequence[str], *, cwd: str | None = None, timeout: float
) -> subprocess.CompletedProcess[str]:
    """Run an argv-only command after resolving its executable."""
    if not command:
        raise ValueError("command must not be empty")
    executable = shutil.which(command[0])
    if executable is None:
        raise FileNotFoundError(command[0])
    try:
        return subprocess.run(
            [str(Path(executable).resolve()), *command[1:]],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(f"command timed out after {timeout:g} seconds") from exc
