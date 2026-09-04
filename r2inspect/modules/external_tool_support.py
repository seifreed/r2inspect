"""Provenance and output helpers for external analyzers."""

from __future__ import annotations

import hashlib
import json
import os
from functools import cache
from pathlib import Path
from typing import Any

from ..infrastructure.command_runner import cleanup_command_output, run_command


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _path_digest(path: Path) -> str | None:
    try:
        if path.is_file():
            return _file_digest(path)
        if not path.is_dir():
            return None
        digest = hashlib.sha256()
        for item in sorted(candidate for candidate in path.rglob("*") if candidate.is_file()):
            resolved = item.resolve(strict=False)
            if not resolved.is_relative_to(path.resolve()):
                continue
            digest.update(item.relative_to(path).as_posix().encode())
            digest.update(bytes.fromhex(_file_digest(item)))
        return digest.hexdigest()
    except OSError:
        return None


@cache
def _tool_identity(executable: str, name: str) -> dict[str, Any]:
    path = Path(executable).resolve()
    version: str | None = None
    try:
        version_timeout = 0.2 if os.getenv("R2INSPECT_TEST_MODE") == "1" else 5
        completed = run_command([str(path), "--version"], timeout=version_timeout)
        output = (completed.stdout or completed.stderr).strip()
        version = output.splitlines()[0] if output else None
        cleanup_command_output(completed)
    except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
        cleanup_command_output(getattr(exc, "result", None))
    return {
        "name": name,
        "path": str(path),
        "version": version,
        "sha256": _path_digest(path),
    }


def tool_provenance(executable: str, name: str) -> dict[str, Any]:
    return {**_tool_identity(executable, name), "rules": rules_provenance(name)}


def rules_provenance(name: str) -> dict[str, Any] | None:
    configured = os.environ.get(f"R2INSPECT_{name.upper()}_RULES")
    if not configured:
        return {"source": "tool-default", "digest": None} if name == "capa" else None
    path = Path(configured).expanduser().resolve()
    return {"source": str(path), "digest": _path_digest(path)}


def load_json_output(completed: Any) -> Any:
    path = getattr(completed, "stdout_path", None)
    if isinstance(path, str):
        with Path(path).open(encoding="utf-8") as handle:
            return json.load(handle)
    return json.loads(completed.stdout)


def native_output(command: list[str], completed: Any) -> dict[str, Any]:
    return {
        "command": list(getattr(completed, "args", command)),
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "stdout_path": getattr(completed, "stdout_path", None),
        "stderr_path": getattr(completed, "stderr_path", None),
        "truncated": bool(getattr(completed, "output_truncated", False)),
    }


__all__ = [
    "cleanup_command_output",
    "load_json_output",
    "native_output",
    "rules_provenance",
    "tool_provenance",
]
