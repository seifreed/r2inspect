#!/usr/bin/env python3
"""R2Pipe adapter implementation."""

import os
import threading
from collections.abc import Iterable
from typing import Any, Literal, cast

from ..domain.constants import DISASM_CACHE_MAX_ENTRIES, DISASM_CACHE_MAX_FUNCS
from ..interfaces import BinaryAnalyzerInterface
from ..infrastructure.logging import get_logger
from ..infrastructure.r2_command_timeout import is_wedged
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
        # Separate bounded cache for per-address disasm (pdfj/agj @ addr) so the
        # similarity analyzers share one disassembly pass; kept apart from the
        # unbounded _cache so it can be size-gated and cleared independently.
        self._disasm_cache: dict[str, CommandOutput] = {}
        self._disasm_cache_enabled: bool | None = None
        self._cache_lock = threading.Lock()
        self._fault_injector = fault_injector
        # Memoizes the one-time `aaa` full-analysis pass: every similarity
        # analyzer (binbloom, binlex, bindiff, function extraction) requests it,
        # but the r2 session state is shared, so a single pass suffices.
        self._analysis_result: str | None = None
        # Memoizes the file-backed io-map starts used to scope /x hex searches
        # away from the (potentially ~1 GB) anonymous BSS map; resolved once on
        # first search. See R2PipeTextQueryMixin._get_file_backed_map_starts.
        self._file_backed_map_starts: list[int] | None = None
        # Executable file-backed map starts, used to scope /aa assembly searches:
        # instructions can only live in r-x maps, so disassembling data maps is
        # both wasted work and a source of false opcode matches.
        self._executable_map_starts: list[int] | None = None
        self._file_backed_maps_resolved: bool = False
        logger.debug("R2PipeAdapter initialized successfully")

    def cmd(self, command: str) -> str:
        # A prior command that timed out abandoned a worker thread still blocked
        # in this synchronous pipe; any further command would queue behind it and
        # hang forever. Fast-fail once the instance is marked wedged.
        if is_wedged(self):
            return ""
        result = self._r2.cmd(command)
        return result if isinstance(result, str) else str(result)

    def cmdj(self, command: str) -> Any:
        if is_wedged(self):
            return None
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

        # JSON-ness is decided by the base command token, before any
        # "@ <address>" suffix: "aflj @ 0x401000" is still a JSON command even
        # though the full string ends in a digit.
        base = cmd_text.split("@", 1)[0].strip()
        if base.endswith("j"):
            result = self.cmdj(cmd_text)
            list_commands = {
                "iSj",
                "iSSj",
                "iij",
                "iEj",
                "isj",
                "aflj",
                "izj",
                "izzj",
                "iDj",
                "agj",
            }
            if base in list_commands:
                if isinstance(result, list):
                    return result
                if isinstance(result, (dict, str, bytes)) or not isinstance(result, Iterable):
                    return []
                return list(result)
            return result if isinstance(result, dict | list) else {}

        text = self.cmd(cmd_text)
        return text

    @staticmethod
    def _env_int(name: str, fallback: int) -> int:
        raw = os.environ.get(name)
        if not raw:
            return fallback
        try:
            return int(raw)
        except ValueError:
            return fallback

    def _disasm_cache_active(self) -> bool:
        """Whether per-address disasm caching is enabled for this binary.

        Decided once: a function-heavy binary (more functions than the gate)
        would accumulate too much cached disasm, so caching stays off and we
        keep the current per-call behavior. Any failure to count disables it.
        """
        if self._disasm_cache_enabled is None:
            max_funcs = self._env_int("R2INSPECT_DISASM_CACHE_MAX_FUNCS", DISASM_CACHE_MAX_FUNCS)
            # get_functions() never raises (it returns [] on any error), so the
            # count is always available here.
            self._disasm_cache_enabled = len(self.get_functions()) <= max_funcs
        return self._disasm_cache_enabled

    def clear_disasm_cache(self) -> None:
        with self._cache_lock:
            self._disasm_cache.clear()

    def _cached_query(
        self,
        cmd: str,
        data_type: Literal["list", "dict"] = "list",
        default: list | dict | None = None,
        error_msg: str = "",
        *,
        cache: bool = True,
        bounded: bool = False,
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
                    return self._as_typed(self._cache[cmd], data_type)
        if bounded:
            with self._cache_lock:
                if cmd in self._disasm_cache:
                    return self._as_typed(self._disasm_cache[cmd], data_type)

        result, default_value = self._fetch_and_default(cmd, data_type, default)

        validated = validate_r2_data(result, data_type)
        if not is_valid_r2_response(validated):
            if error_msg:
                logger.debug(error_msg)
            return self._as_typed(default_value, data_type)

        if cache:
            with self._cache_lock:
                self._cache[cmd] = validated
        elif bounded and self._disasm_cache_active():
            max_entries = self._env_int(
                "R2INSPECT_DISASM_CACHE_MAX_ENTRIES", DISASM_CACHE_MAX_ENTRIES
            )
            with self._cache_lock:
                # Stop-at-cap (no eviction): LRU would thrash on the fill-then-
                # drain access pattern where one analyzer fills and the next reads.
                if len(self._disasm_cache) < max_entries:
                    self._disasm_cache[cmd] = validated
        return self._as_typed(validated, data_type)

    @staticmethod
    def _as_typed(
        value: Any, data_type: Literal["list", "dict"]
    ) -> list[dict[str, Any]] | dict[str, Any]:
        if data_type == "list":
            return cast(list[dict[str, Any]], value)
        return cast(dict[str, Any], value)

    def _fetch_and_default(
        self, cmd: str, data_type: Literal["list", "dict"], default: list | dict | None
    ) -> tuple[Any, Any]:
        if data_type == "list":
            return safe_cmd_list(self, cmd), (default if default is not None else [])
        return safe_cmd_dict(self, cmd), (default if default is not None else {})

    def __repr__(self) -> str:
        """Return string representation of the adapter."""
        return f"R2PipeAdapter(r2_instance={self._r2})"

    def __str__(self) -> str:
        """Return human-readable string representation."""
        return "R2PipeAdapter for radare2 binary analysis"

    def _maybe_force_error(self, method: str) -> None:
        if self._fault_injector is not None:
            self._fault_injector(method)


__all__ = [
    "BinaryAnalyzerInterface",
]
