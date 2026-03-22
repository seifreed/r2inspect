#!/usr/bin/env python3
"""Shared command helper mixin for analyzer classes."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any, TypeVar, cast

from ..infrastructure.command_helpers import cmd as cmd_helper
from ..infrastructure.command_helpers import cmd_list as cmd_list_helper
from ..infrastructure.command_helpers import cmdj as cmdj_helper

_log = logging.getLogger(__name__)

T = TypeVar("T")


class CommandHelperMixin:
    """Provide standardized command helper wrappers for adapters/r2 instances."""

    adapter: Any

    def _cmd(self, command: str) -> str:
        return str(cmd_helper(self.adapter, self.adapter, command))

    def _cmdj(self, command: str, default: Any | None = None) -> Any:
        return cmdj_helper(self.adapter, self.adapter, command, default)

    def _cmd_list(self, command: str) -> list[Any]:
        return cast(list[Any], cmd_list_helper(self.adapter, self.adapter, command))

    @staticmethod
    def _coerce_dict_list(value: Any) -> list[dict[str, Any]]:
        """Coerce a value to a list of dicts, returning [] for non-list inputs."""
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            return [value]
        return []

    def _get_via_adapter(
        self,
        method_name: str,
        fallback_cmd: str | None = None,
        *,
        as_dict: bool = False,
    ) -> Any:
        """Return data from an adapter method when available, else via r2 command.

        Eliminates the recurring ``if self.adapter and hasattr(self.adapter, X)``
        boilerplate in every analyzer.

        - Pass ``fallback_cmd=None`` (default) when there is no r2 command fallback;
          an empty list (or dict if ``as_dict=True``) is returned instead.
        - Pass ``as_dict=True`` to use ``_cmdj`` (returns a dict) instead of
          ``_cmd_list`` (returns a list) as the command fallback.
        """
        if self.adapter is not None and hasattr(self.adapter, method_name):
            return getattr(self.adapter, method_name)()
        if fallback_cmd is None:
            return {} if as_dict else []
        return (
            cast(dict[str, Any], self._cmdj(fallback_cmd, {}))
            if as_dict
            else self._cmd_list(fallback_cmd)
        )

    def _safe_call(
        self,
        fn: Callable[[], T],
        default: T,
        error_msg: str,
    ) -> T:
        """Call *fn* and return its result; log *error_msg* and return *default* on any exception.

        Replaces the repetitive ``try: return X() except Exception as e: logger.error(...)``
        pattern spread across analyzer private methods.
        """
        try:
            return fn()
        except Exception as exc:
            _log.error("%s: %s", error_msg, exc)
            return default
