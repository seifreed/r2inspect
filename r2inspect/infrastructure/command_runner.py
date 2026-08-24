"""Constrained external command execution."""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path


def resolve_timeout(timeout: float) -> float:
    """Apply the process-wide command timeout override when it is valid."""
    override = os.environ.get("R2INSPECT_CMD_TIMEOUT_SECONDS")
    if override:
        try:
            value = float(override)
        except ValueError:
            pass
        else:
            if value >= 0:
                return value
    return timeout


def run_command(
    command: Sequence[str], *, cwd: str | None = None, timeout: float
) -> subprocess.CompletedProcess[str]:
    """Run an argv-only command after resolving its executable."""
    if not command:
        raise ValueError("command must not be empty")
    executable = shutil.which(command[0])
    if executable is None:
        raise FileNotFoundError(command[0])
    effective_timeout = resolve_timeout(timeout)
    try:
        return subprocess.run(
            [str(Path(executable).resolve()), *command[1:]],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
            timeout=effective_timeout,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(f"command timed out after {effective_timeout:g} seconds") from exc
