"""Canonical FakeR2 test double for unit tests.

Import this instead of redefining FakeR2 in every test file::

    from r2inspect.testing.fake_r2 import FakeR2
"""

from __future__ import annotations

from typing import Any


class FakeR2:
    """Fake r2pipe instance returning predetermined responses by command."""

    def __init__(
        self,
        cmdj_map: dict[str, Any] | None = None,
        cmd_map: dict[str, str] | None = None,
    ):
        self.cmdj_map: dict[str, Any] = cmdj_map or {}
        self.cmd_map: dict[str, str] = cmd_map or {}

    def cmdj(self, command: str) -> Any:
        if command in self.cmdj_map:
            value = self.cmdj_map[command]
            if isinstance(value, Exception):
                raise value
            return value
        for key, value in self.cmdj_map.items():
            if key in command:
                if isinstance(value, Exception):
                    raise value
                return value
        return None

    def cmd(self, command: str) -> str:
        if command in self.cmd_map:
            value = self.cmd_map[command]
            if isinstance(value, Exception):
                raise value
            return value
        for key, value in self.cmd_map.items():
            if key in command:
                if isinstance(value, Exception):
                    raise value
                return value
        return ""
