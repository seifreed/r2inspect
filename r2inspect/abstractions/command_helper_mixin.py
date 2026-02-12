#!/usr/bin/env python3
"""Shared command helper mixin for analyzer classes."""

from __future__ import annotations

from typing import Any

from ..utils.command_helpers import cmd as cmd_helper
from ..utils.command_helpers import cmd_list as cmd_list_helper
from ..utils.command_helpers import cmdj as cmdj_helper


class CommandHelperMixin:
    """Provide standardized command helper wrappers for adapters/r2 instances."""

    adapter: Any
    r2: Any

    def _cmd(self, command: str) -> str:
        return cmd_helper(self.adapter, self.r2, command)

    def _cmdj(self, command: str, default: Any | None = None) -> Any:
        return cmdj_helper(self.adapter, self.r2, command, default)

    def _cmd_list(self, command: str) -> list[Any]:
        return cmd_list_helper(self.adapter, self.r2, command)
