"""Constrained external command execution."""

from __future__ import annotations

import contextlib
import os
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psutil

_CAPTURE_BYTES = 4 * 1024 * 1024
_SPOOL_BYTES = 256 * 1024 * 1024
_MEMORY_MB = 1024
_MAX_PROCESSES = 32


@dataclass(frozen=True)
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    stdout_path: str | None = None
    stderr_path: str | None = None

    @property
    def output_truncated(self) -> bool:
        return self.stdout_path is not None or self.stderr_path is not None


class CommandTimeout(TimeoutError):
    def __init__(self, message: str, result: CommandResult) -> None:
        super().__init__(message)
        self.result = result


class CommandResourceError(RuntimeError):
    def __init__(self, message: str, result: CommandResult) -> None:
        super().__init__(message)
        self.result = result


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


def _env_int(name: str, default: int) -> int:
    try:
        return max(int(os.environ.get(name, default)), 1)
    except ValueError:
        return default


def _argv(command: Sequence[str]) -> list[str]:
    executable = shutil.which(command[0])
    if executable is None:
        raise FileNotFoundError(command[0])
    argv = [str(Path(executable).resolve()), *command[1:]]
    prefix = os.environ.get("R2INSPECT_CMD_SANDBOX_PREFIX")
    if not prefix:
        return argv
    wrapper = shlex.split(prefix)
    if not wrapper:
        raise ValueError("R2INSPECT_CMD_SANDBOX_PREFIX is empty")
    resolved_wrapper = shutil.which(wrapper[0])
    if resolved_wrapper is None:
        raise FileNotFoundError(wrapper[0])
    return [str(Path(resolved_wrapper).resolve()), *wrapper[1:], *argv]


def _terminate(process: subprocess.Popen[Any]) -> None:
    if os.name == "nt":
        taskkill = shutil.which("taskkill")
        if taskkill:
            subprocess.run(
                [taskkill, "/PID", str(process.pid), "/T", "/F"],
                capture_output=True,
                check=False,
            )
    else:
        with contextlib.suppress(ProcessLookupError):
            getattr(os, "killpg")(process.pid, getattr(signal, "SIGKILL"))
    with contextlib.suppress(ProcessLookupError):
        process.kill()
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=1)


def _resource_violation(process: subprocess.Popen[Any], stdout: Path, stderr: Path) -> str | None:
    max_spool = _env_int("R2INSPECT_CMD_MAX_SPOOL_BYTES", _SPOOL_BYTES)
    if stdout.stat().st_size > max_spool or stderr.stat().st_size > max_spool:
        return f"external command output exceeded {max_spool} bytes"
    try:
        root = psutil.Process(process.pid)
        processes = [root, *root.children(recursive=True)]
        if len(processes) > _env_int("R2INSPECT_CMD_MAX_PROCESSES", _MAX_PROCESSES):
            return "external command process limit exceeded"
        memory = sum(item.memory_info().rss for item in processes)
        max_memory = _env_int("R2INSPECT_CMD_MAX_MEMORY_MB", _MEMORY_MB) * 1024 * 1024
        if memory > max_memory:
            return f"external command memory limit exceeded ({memory} > {max_memory})"
        cpu = sum(sum(item.cpu_times()[:2]) for item in processes)
        max_cpu = _env_int("R2INSPECT_CMD_CPU_SECONDS", 120)
        if cpu > max_cpu:
            return f"external command CPU limit exceeded ({cpu:.2f} > {max_cpu})"
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        pass
    return None


def _read_output(path: Path, capture_bytes: int) -> tuple[str, str | None]:
    size = path.stat().st_size
    with path.open("rb") as handle:
        preview = handle.read(capture_bytes)
    if size > capture_bytes:
        return preview.decode("utf-8", errors="replace"), str(path)
    path.unlink(missing_ok=True)
    return preview.decode("utf-8", errors="replace"), None


def _result(
    argv: list[str], returncode: int, stdout_path: Path, stderr_path: Path
) -> CommandResult:
    capture_bytes = _env_int("R2INSPECT_CMD_MAX_OUTPUT_BYTES", _CAPTURE_BYTES)
    stdout, stdout_spill = _read_output(stdout_path, capture_bytes)
    stderr, stderr_spill = _read_output(stderr_path, capture_bytes)
    return CommandResult(argv, returncode, stdout, stderr, stdout_spill, stderr_spill)


def _finish(
    argv: list[str],
    returncode: int,
    stdout_path: Path,
    stderr_path: Path,
    stdout_handle: Any,
    stderr_handle: Any,
) -> CommandResult:
    stdout_handle.close()
    stderr_handle.close()
    return _result(argv, returncode, stdout_path, stderr_path)


def cleanup_command_output(result: Any) -> None:
    for attribute in ("stdout_path", "stderr_path"):
        raw_path = getattr(result, attribute, None)
        if isinstance(raw_path, str):
            Path(raw_path).unlink(missing_ok=True)


@contextlib.contextmanager
def _output_files(directory: str | None) -> Iterator[tuple[Any, Any, Path, Path]]:
    with (
        tempfile.NamedTemporaryFile(dir=directory, delete=False) as stdout_handle,
        tempfile.NamedTemporaryFile(dir=directory, delete=False) as stderr_handle,
    ):
        yield stdout_handle, stderr_handle, Path(stdout_handle.name), Path(stderr_handle.name)


def _run_process(
    argv: list[str],
    cwd: str | None,
    timeout: float,
    stdout_handle: Any,
    stderr_handle: Any,
    stdout_path: Path,
    stderr_path: Path,
) -> CommandResult:
    kwargs: dict[str, Any] = {
        "cwd": cwd,
        "stdout": stdout_handle,
        "stderr": stderr_handle,
        "shell": False,
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kwargs["start_new_session"] = True
    try:
        process = subprocess.Popen(argv, **kwargs)
        started = time.monotonic()
        while process.poll() is None:
            if time.monotonic() - started > timeout:
                _terminate(process)
                result = _finish(
                    argv,
                    process.returncode or -1,
                    stdout_path,
                    stderr_path,
                    stdout_handle,
                    stderr_handle,
                )
                raise CommandTimeout(f"command timed out after {timeout:g} seconds", result)
            violation = _resource_violation(process, stdout_path, stderr_path)
            if violation:
                _terminate(process)
                result = _finish(
                    argv,
                    process.returncode or -1,
                    stdout_path,
                    stderr_path,
                    stdout_handle,
                    stderr_handle,
                )
                raise CommandResourceError(violation, result)
            time.sleep(0.05)
        violation = _resource_violation(process, stdout_path, stderr_path)
        if violation:
            result = _finish(
                argv,
                process.returncode,
                stdout_path,
                stderr_path,
                stdout_handle,
                stderr_handle,
            )
            raise CommandResourceError(violation, result)
        return _finish(
            argv,
            process.returncode,
            stdout_path,
            stderr_path,
            stdout_handle,
            stderr_handle,
        )
    finally:
        stdout_handle.close()
        stderr_handle.close()
        if "process" not in locals():
            stdout_path.unlink(missing_ok=True)
            stderr_path.unlink(missing_ok=True)


def run_command(command: Sequence[str], *, cwd: str | None = None, timeout: float) -> CommandResult:
    """Run an argv-only command with bounded capture and resource limits."""
    if not command:
        raise ValueError("command must not be empty")
    argv = _argv(command)
    effective_timeout = resolve_timeout(timeout)
    output_dir = os.environ.get("R2INSPECT_CMD_OUTPUT_DIR")
    with _output_files(output_dir) as output_files:
        stdout_handle, stderr_handle, stdout_path, stderr_path = output_files
        return _run_process(
            argv,
            cwd,
            effective_timeout,
            stdout_handle,
            stderr_handle,
            stdout_path,
            stderr_path,
        )


__all__ = [
    "CommandResourceError",
    "CommandResult",
    "CommandTimeout",
    "cleanup_command_output",
    "resolve_timeout",
    "run_command",
]
