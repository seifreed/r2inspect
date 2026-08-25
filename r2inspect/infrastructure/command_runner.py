"""Constrained external command execution."""

from __future__ import annotations

import contextlib
import os
import signal
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
    argv = [str(Path(executable).resolve()), *command[1:]]
    kwargs: dict[str, object] = {
        "cwd": cwd,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "shell": False,
    }
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    process = subprocess.Popen(argv, **kwargs)
    try:
        stdout, stderr = process.communicate(timeout=effective_timeout)
    except subprocess.TimeoutExpired as exc:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                capture_output=True,
                check=False,
            )
        else:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
        process.kill()
        process.communicate()
        raise TimeoutError(f"command timed out after {effective_timeout:g} seconds") from exc
    return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)
