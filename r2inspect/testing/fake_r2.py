"""Canonical FakeR2 test double for unit tests.

Import this instead of redefining FakeR2 in every test file::

    from r2inspect.testing.fake_r2 import FakeR2
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

CmdHandler = Callable[[str], str]
CmdjHandler = Callable[[str], Any]


class FakeR2:
    """Fake r2pipe instance returning predetermined responses by command.

    Three resolution strategies are tried for each ``cmd``/``cmdj`` call, in order:

    1. Exact match in the static ``cmd_map`` / ``cmdj_map``.
    2. Substring match against any key in those maps (first hit wins).
    3. Callable fallback (``cmd_fn`` / ``cmdj_fn``) — useful for commands whose
       argument is dynamic (e.g. ``p8 SIZE @ ADDR`` for arbitrary addresses).

    When none of those produce a value, ``cmd`` returns ``""`` and ``cmdj``
    returns ``None``. Stored ``Exception`` values are raised when consumed.
    """

    def __init__(
        self,
        cmdj_map: dict[str, Any] | None = None,
        cmd_map: dict[str, str | Exception] | None = None,
        *,
        cmd_fn: CmdHandler | None = None,
        cmdj_fn: CmdjHandler | None = None,
    ):
        self.cmdj_map: dict[str, Any] = cmdj_map or {}
        self.cmd_map: dict[str, str | Exception] = cmd_map or {}
        self._cmd_fn: CmdHandler | None = cmd_fn
        self._cmdj_fn: CmdjHandler | None = cmdj_fn

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
        if self._cmdj_fn is not None:
            return self._cmdj_fn(command)
        return None

    def quit(self) -> None:
        """No-op quit for r2session compatibility."""

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
        if self._cmd_fn is not None:
            return self._cmd_fn(command)
        return ""
