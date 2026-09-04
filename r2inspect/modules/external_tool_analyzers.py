"""Optional capa and FLOSS command-line integrations."""

from __future__ import annotations

import json
import os
import shutil
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, ClassVar

from ..abstractions import BaseAnalyzer
from ..infrastructure.command_runner import resolve_timeout, run_command
from .external_tool_support import (
    cleanup_command_output,
    load_json_output,
    native_output,
    tool_provenance,
)

_EXTERNAL_TOOL_TIMEOUT_SECONDS = 120.0
_TEST_EXTERNAL_TOOL_TIMEOUT_SECONDS = 0.2


class ExternalJsonAnalyzer(BaseAnalyzer):
    executable: ClassVar[str]
    command_args: ClassVar[tuple[str, ...]] = ("-j",)

    def __init__(
        self,
        adapter: Any = None,
        config: Any = None,
        filepath: str | None = None,
        filename: str | None = None,
        *,
        executable_lookup: Callable[[str], str | None] = shutil.which,
    ) -> None:
        super().__init__(adapter=adapter, config=config, filepath=filepath or filename)
        self._executable_lookup = executable_lookup

    def get_category(self) -> str:
        return "detection"

    def analyze(self, forensic: bool = False) -> dict[str, Any]:
        started = time.monotonic()
        executable = self._executable_lookup(self.executable)
        if not executable:
            return {
                "available": False,
                "library_available": False,
                "error": f"dependency unavailable: {self.executable}",
                "execution_time": time.monotonic() - started,
            }
        if self.filepath is None:
            return {
                "available": True,
                "error": "sample path unavailable",
                "execution_time": time.monotonic() - started,
            }
        provenance = tool_provenance(executable, self.executable)
        completed: Any = None
        try:
            default_timeout = (
                _TEST_EXTERNAL_TOOL_TIMEOUT_SECONDS
                if os.getenv("R2INSPECT_TEST_MODE") == "1"
                else _EXTERNAL_TOOL_TIMEOUT_SECONDS
            )
            timeout = resolve_timeout(default_timeout)
            command_args = self.command_args
            if forensic and self.executable == "floss":
                command_args = ("-j",)
            capa_rules = os.getenv("R2INSPECT_CAPA_RULES")
            if self.executable == "capa" and capa_rules:
                command_args = (*command_args, "-r", str(Path(capa_rules).expanduser().resolve()))
            command = [executable, *command_args, str(Path(self.filepath))]
            completed = run_command(command, timeout=timeout)
            if completed.returncode != 0:
                raise RuntimeError(completed.stderr.strip() or f"exit code {completed.returncode}")
            payload = load_json_output(completed)
            if not isinstance(payload, dict):
                raise ValueError("JSON output must be an object")
            result = {
                "available": True,
                "result": payload,
                "execution_time": time.monotonic() - started,
            }
        except TimeoutError as exc:
            completed = getattr(exc, "result", completed)
            result = {
                "available": True,
                "error": str(exc),
                "execution_time": time.monotonic() - started,
            }
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
            completed = getattr(exc, "result", completed)
            result = {
                "available": True,
                "error": str(exc),
                "execution_time": time.monotonic() - started,
            }
        result["tool"] = provenance
        if completed is not None:
            if forensic:
                result["native_output"] = native_output(command, completed)
            else:
                cleanup_command_output(completed)
        return result


class CapaAnalyzer(ExternalJsonAnalyzer):
    executable = "capa"

    def get_name(self) -> str:
        return "capa"


class FlossAnalyzer(ExternalJsonAnalyzer):
    executable = "floss"
    command_args = ("--only", "static", "-j")

    def get_name(self) -> str:
        return "floss"


__all__ = ["CapaAnalyzer", "FlossAnalyzer"]
