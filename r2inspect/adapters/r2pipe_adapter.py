#!/usr/bin/env python3
"""R2Pipe adapter implementation."""

import os
from typing import Any, cast

from ..interfaces import BinaryAnalyzerInterface
from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmd_dict, safe_cmd_list
from ..utils.r2_suppress import silent_cmdj
from .r2pipe_queries import R2PipeQueryMixin
from .validation import is_valid_r2_response, validate_r2_data

logger = get_logger(__name__)

CommandOutput = str | dict[str, Any] | list[Any] | None


class R2PipeAdapter(R2PipeQueryMixin):
    """Adapter for radare2/r2pipe backend implementing BinaryAnalyzerInterface."""

    thread_safe = False

    def __init__(self, r2_instance: Any) -> None:
        """
        Initialize the R2Pipe adapter.

        Args:
            r2_instance: An r2pipe instance connected to a binary file.
                Must support cmd() and cmdj() methods.

        Raises:
            ValueError: If r2_instance is None or invalid

        Example:
            >>> import r2pipe
            >>> r2 = r2pipe.open("/bin/ls")
            >>> adapter = R2PipeAdapter(r2)
        """
        if r2_instance is None:
            raise ValueError("r2_instance cannot be None")

        self._r2 = r2_instance
        self._cache: dict[str, CommandOutput] = {}
        logger.debug("R2PipeAdapter initialized successfully")

    def cmd(self, command: str) -> str:
        result = self._r2.cmd(command)
        return result if isinstance(result, str) else str(result)

    def cmdj(self, command: str) -> Any:
        return silent_cmdj(self._r2, command, None)

    def _cached_query(
        self,
        cmd: str,
        data_type: str = "list",
        default: list | dict | None = None,
        error_msg: str = "",
        *,
        cache: bool = True,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """
        Execute r2 command with caching and validation.

        This helper method encapsulates the common pattern of:
        1. Checking cache for existing results
        2. Executing the r2 command if not cached
        3. Validating the response
        4. Caching and returning valid results

        Args:
            cmd: The radare2 command to execute (e.g., 'iSj', 'iij')
            data_type: Expected response type ('list' or 'dict')
            default: Default value to return on error (None uses [] for list, {} for dict)
            error_msg: Optional debug message to log on invalid response

        Returns:
            Validated response data, or default value if invalid/error

        Example:
            >>> sections = self._cached_query("iSj", "list",
            ...     error_msg="No sections found")
        """
        self._maybe_force_error("_cached_query")
        if cache and cmd in self._cache:
            cached = self._cache[cmd]
            if data_type == "list":
                return cast(list[dict[str, Any]], cached)
            return cast(dict[str, Any], cached)

        result: Any
        default_value: Any
        if data_type == "list":
            result = safe_cmd_list(self, cmd)
            default_value = default if default is not None else []
        else:
            result = safe_cmd_dict(self, cmd)
            default_value = default if default is not None else {}

        validated = validate_r2_data(result, data_type)
        if not is_valid_r2_response(validated):
            if error_msg:
                logger.debug(error_msg)
            if data_type == "list":
                return cast(list[dict[str, Any]], default_value)
            return cast(dict[str, Any], default_value)

        if cache:
            self._cache[cmd] = validated
        if data_type == "list":
            return cast(list[dict[str, Any]], validated)
        return cast(dict[str, Any], validated)

    def __repr__(self) -> str:
        """Return string representation of the adapter."""
        return f"R2PipeAdapter(r2_instance={self._r2})"

    def __str__(self) -> str:
        """Return human-readable string representation."""
        return "R2PipeAdapter for radare2 binary analysis"

    def _maybe_force_error(self, method: str) -> None:
        forced = os.environ.get("R2INSPECT_FORCE_ADAPTER_ERROR", "")
        if not forced:
            return
        lowered = forced.strip().lower()
        if lowered in {"1", "true", "yes", "all", "*"}:
            raise RuntimeError("Forced adapter error")
        methods = {item.strip() for item in forced.split(",") if item.strip()}
        if method in methods:
            raise RuntimeError("Forced adapter error")
