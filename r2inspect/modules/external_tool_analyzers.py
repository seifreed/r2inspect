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

_EXTERNAL_TOOL_TIMEOUT_SECONDS = 120.0
_TEST_EXTERNAL_TOOL_TIMEOUT_SECONDS = 0.2


class ExternalJsonAnalyzer(BaseAnalyzer):
    executable: ClassVar[str]

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

    def analyze(self) -> dict[str, Any]:
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
        try:
            default_timeout = (
                _TEST_EXTERNAL_TOOL_TIMEOUT_SECONDS
                if os.getenv("R2INSPECT_TEST_MODE") == "1"
                else _EXTERNAL_TOOL_TIMEOUT_SECONDS
            )
            timeout = resolve_timeout(default_timeout)
            completed = run_command(
                [executable, "-j", str(Path(self.filepath))],
                timeout=timeout,
            )
            if completed.returncode != 0:
                raise RuntimeError(completed.stderr.strip() or f"exit code {completed.returncode}")
            payload = json.loads(completed.stdout)
            if not isinstance(payload, dict):
                raise ValueError("JSON output must be an object")
            return {
                "available": True,
                "result": payload,
                "execution_time": time.monotonic() - started,
            }
        except TimeoutError as exc:
            return {
                "available": True,
                "error": str(exc),
                "execution_time": time.monotonic() - started,
            }
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
            return {
                "available": True,
                "error": str(exc),
                "execution_time": time.monotonic() - started,
            }


class CapaAnalyzer(ExternalJsonAnalyzer):
    executable = "capa"

    def get_name(self) -> str:
        return "capa"


class FlossAnalyzer(ExternalJsonAnalyzer):
    executable = "floss"

    def get_name(self) -> str:
        return "floss"


__all__ = ["CapaAnalyzer", "FlossAnalyzer"]
