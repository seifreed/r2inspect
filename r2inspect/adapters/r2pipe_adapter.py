#!/usr/bin/env python3
"""R2Pipe adapter implementation."""

import threading
from typing import Any, Literal, cast

from ..interfaces import BinaryAnalyzerInterface
from ..infrastructure.logging import get_logger
from ..infrastructure.r2_helpers import safe_cmd_dict, safe_cmd_list
from ..infrastructure.r2_suppress import silent_cmdj
from .r2pipe_queries import R2PipeQueryMixin
from .validation import is_valid_r2_response, validate_r2_data

logger = get_logger(__name__)

CommandOutput = str | dict[str, Any] | list[Any] | None


class R2PipeAdapter(R2PipeQueryMixin):
    """Adapter for radare2/r2pipe backend implementing BinaryAnalyzerInterface."""

    thread_safe = False

    def __init__(self, r2_instance: Any, *, fault_injector: Any = None) -> None:
        """
        Initialize the R2Pipe adapter.

        Args:
            r2_instance: An r2pipe instance connected to a binary file.
                Must support cmd() and cmdj() methods.
            fault_injector: Optional callable(method: str) used by tests to
                inject faults.  Production callers leave this as ``None``.

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
        self._cache_lock = threading.Lock()
        self._fault_injector = fault_injector
        logger.debug("R2PipeAdapter initialized successfully")

    def cmd(self, command: str) -> str:
        result = self._r2.cmd(command)
        return result if isinstance(result, str) else str(result)

    def cmdj(self, command: str) -> Any:
        return silent_cmdj(self._r2, command, None)

    @property
    def r2(self) -> Any:
        """Backward-compatible accessor for underlying r2 instance."""
        return self._r2

    def execute_command(self, command: str) -> Any | None:
        """Backward-compatible generic command execution helper."""
        cmd_text = command.strip()
        if not cmd_text:
            return None

        # Prefer JSON path for commands that conventionally return JSON.
        if cmd_text.endswith("j"):
            result = self.cmdj(cmd_text)
            list_commands = {"iSj", "iij", "iEj", "isj", "aflj", "izj", "izzj", "iDj", "agj"}
            if cmd_text in list_commands:
                return result if isinstance(result, list) else []
            return result if isinstance(result, dict | list) else {}

        text = self.cmd(cmd_text)
        return text

    def _cached_query(
        self,
        cmd: str,
        data_type: Literal["list", "dict"] = "list",
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
        if cache:
            with self._cache_lock:
                if cmd in self._cache:
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
            with self._cache_lock:
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
        if self._fault_injector is not None:
            self._fault_injector(method)
