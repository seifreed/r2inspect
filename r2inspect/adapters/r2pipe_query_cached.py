"""Cached/query-oriented mixin methods for r2pipe adapters."""

from __future__ import annotations

import os
import sys
import threading
from typing import TYPE_CHECKING, Any, Literal, cast

if TYPE_CHECKING:
    from ..interfaces.core import R2CommandInterface

from ..domain.constants import MNEMONIC_CACHE_MAX_ENTRIES, OVERLAY_STRING_SCAN_THRESHOLD_MB
from ..domain.services.function_analysis import extract_mnemonics_from_ops
from ..infrastructure.logging import get_logger

logger = get_logger(__name__)


class R2PipeCachedQueryMixin:
    """Methods that primarily rely on cached JSON queries."""

    _safe_query: Any  # provided by host class
    _maybe_force_error: Any  # provided by host class
    _cache: dict[str, Any]  # provided by host class
    _safe_cached_query: Any  # provided by host class
    _cached_query: Any  # provided by host class
    _overlay_strings_skipped_logged: bool  # provided by host class
    _mnemonic_cache: dict[int, tuple[str, ...]]  # provided by host class
    _cache_lock: threading.Lock  # provided by host class
    _env_int: Any  # provided by host class

    @property
    def _r2_iface(self) -> R2CommandInterface:
        return cast("R2CommandInterface", self)

    def _json_query(
        self,
        cmd: str,
        data_type: Literal["list", "dict"],
        default: Any,
        method_name: str,
        error_msg: str,
    ) -> Any:
        """Execute a JSON query with validation, replacing duplicated closures.

        Handles the common pattern: force error check -> safe_cmdj -> validate -> return.
        """
        from . import r2pipe_queries as facade

        def _execute() -> Any:
            self._maybe_force_error(method_name)
            data = facade.safe_cmdj(self._r2_iface, cmd, default)
            validated = facade.validate_r2_data(data, data_type)
            return validated if validated else default

        return self._safe_query(_execute, default, error_msg)

    def get_file_info(self) -> dict[str, Any]:
        from . import r2pipe_queries as facade

        try:
            self._maybe_force_error("get_file_info")
            if "ij" in self._cache:
                return cast(dict[str, Any], self._cache["ij"])
            info = facade.safe_cmd_dict(self._r2_iface, "ij")
            validated = facade.validate_r2_data(info, "dict")

            if not facade.is_valid_r2_response(validated):
                facade.logger.warning("Invalid or empty response from 'ij' command")
                return {}

            self._cache["ij"] = validated
            return cast(dict[str, Any], validated)
        except Exception as exc:
            facade.logger.exception("Error retrieving file info: %s", exc)
            return {}

    def get_sections(self) -> list[dict[str, Any]]:
        return cast(
            list[dict[str, Any]],
            self._safe_cached_query(
                "iSj",
                "list",
                [],
                error_msg="No sections found or invalid response from 'iSj'",
                error_label="sections",
            ),
        )

    def get_imports(self) -> list[dict[str, Any]]:
        return cast(
            list[dict[str, Any]],
            self._safe_cached_query(
                "iij",
                "list",
                [],
                error_msg="No imports found or invalid response from 'iij'",
                error_label="imports",
            ),
        )

    def get_exports(self) -> list[dict[str, Any]]:
        return cast(
            list[dict[str, Any]],
            self._safe_cached_query(
                "iEj",
                "list",
                [],
                error_msg="No exports found or invalid response from 'iEj'",
                error_label="exports",
            ),
        )

    def get_symbols(self) -> list[dict[str, Any]]:
        return cast(
            list[dict[str, Any]],
            self._safe_cached_query(
                "isj",
                "list",
                [],
                error_msg="No symbols found or invalid response from 'isj'",
                error_label="symbols",
            ),
        )

    def _overlay_string_scan_threshold_mb(self) -> float:
        env = os.environ.get("R2INSPECT_STRING_SCAN_THRESHOLD_MB")
        if env:
            try:
                return float(env)
            except ValueError:
                pass
        return float(OVERLAY_STRING_SCAN_THRESHOLD_MB)

    def _string_scan_uses_sections(self) -> bool:
        """Whether to scan only sections (izj) instead of the whole file (izzj).

        Above the threshold the whole-file scan over a large overlay returns
        hundreds of MB of strings and balloons RAM; fall back to the bounded
        sections-only scan. File size proxies overlay-heaviness here.
        """
        core = self.get_file_info().get("core", {})
        size = core.get("size") if isinstance(core, dict) else None
        if not isinstance(size, int) or size <= 0:
            return False
        return size / (1024 * 1024) > self._overlay_string_scan_threshold_mb()

    def get_strings(self) -> list[dict[str, Any]]:
        if self._string_scan_uses_sections():
            if not self._overlay_strings_skipped_logged:
                self._overlay_strings_skipped_logged = True
                logger.warning(
                    "Binary exceeds the %.0f MB string-scan threshold; using "
                    "sections-only strings (izj) instead of the whole-file scan "
                    "(izzj) to bound memory. Overlay strings are excluded from "
                    "compiler/simhash/bindiff analysis.",
                    self._overlay_string_scan_threshold_mb(),
                )
            return self.get_strings_basic()
        return cast(
            list[dict[str, Any]],
            self._safe_cached_query(
                "izzj",
                "list",
                [],
                error_msg="No strings found or invalid response from 'izzj'",
                error_label="strings",
            ),
        )

    def get_functions(self) -> list[dict[str, Any]]:
        return cast(
            list[dict[str, Any]],
            self._safe_cached_query(
                "aflj",
                "list",
                [],
                error_msg=(
                    "No functions found or invalid response from 'aflj'. "
                    "Analysis may not have been performed."
                ),
                error_label="functions",
            ),
        )

    def get_functions_at(self, address: int) -> list[dict[str, Any]]:
        return cast(
            list[dict[str, Any]],
            self._json_query(
                f"aflj @ {address}",
                "list",
                [],
                "get_functions_at",
                f"Error retrieving functions at {hex(address)}",
            ),
        )

    def get_disasm(self, address: int | None = None, size: int | None = None) -> Any:
        cmd = "pdfj" if size is None else f"pdj {size}"
        try:
            self._maybe_force_error("get_disasm")
            data_type = "dict" if size is None else "list"
            if address is not None:
                cmd = f"{cmd} @ {address}"
            return self._cached_query(
                cmd,
                data_type,
                error_msg=f"No disassembly found for '{cmd}'",
                cache=address is None,
                bounded=address is not None,
            )
        except Exception as exc:
            logger.exception("Error retrieving disassembly for '%s': %s", cmd, exc)
            return {} if size is None else []

    def get_cfg(self, address: int | None = None) -> Any:
        cmd = "agj"
        try:
            self._maybe_force_error("get_cfg")
            if address is not None:
                cmd = f"{cmd} @ {address}"
            return self._cached_query(
                cmd,
                "list",
                error_msg=f"No CFG data found for '{cmd}'",
                cache=address is None,
                bounded=address is not None,
            )
        except Exception as exc:
            logger.exception("Error retrieving CFG for '%s': %s", cmd, exc)
            return []

    def get_function_mnemonics(self, address: int) -> tuple[str, ...]:
        """Raw ordered mnemonics for the function at ``address`` from one ``pdfj``
        pass, cached compactly so the similarity analyzers share a single
        disassembly. Returns an empty tuple when pdfj yields no ops, so the
        caller falls back to its own pdj/pi chain (byte-identical there)."""
        with self._cache_lock:
            cached = self._mnemonic_cache.get(address)
        if cached is not None:
            return cached
        disasm = self.get_disasm(address=address)
        ops = disasm.get("ops", []) if isinstance(disasm, dict) else []
        mnemonics = tuple(sys.intern(m) for m in extract_mnemonics_from_ops(ops))
        with self._cache_lock:
            if address not in self._mnemonic_cache:
                max_entries = self._env_int(
                    "R2INSPECT_MNEMONIC_CACHE_MAX_ENTRIES", MNEMONIC_CACHE_MAX_ENTRIES
                )
                if len(self._mnemonic_cache) < max_entries:
                    self._mnemonic_cache[address] = mnemonics
        return mnemonics

    def get_strings_basic(self) -> list[dict[str, Any]]:
        return cast(
            list[dict[str, Any]],
            self._safe_cached_query(
                "izj",
                "list",
                [],
                error_msg="No strings found or invalid response from 'izj'",
                error_label="basic strings",
            ),
        )

    def get_entry_info(self) -> list[dict[str, Any]]:
        return cast(
            list[dict[str, Any]],
            self._json_query("iej", "list", [], "get_entry_info", "Error retrieving entry info"),
        )

    def get_pe_header(self) -> dict[str, Any]:
        from . import r2pipe_queries as facade

        try:
            self._maybe_force_error("get_pe_header")
            data = facade.safe_cmdj(self._r2_iface, "ihj", {})
            if isinstance(data, list) and data:
                return {"headers": data}
            if isinstance(data, dict):
                return data
            return {}
        except Exception as exc:
            facade.logger.exception("Error retrieving PE header: %s", exc)
            return {}

    def get_pe_optional_header(self) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            self._json_query(
                "iHj", "dict", {}, "get_pe_optional_header", "Error retrieving PE optional header"
            ),
        )

    def get_data_directories(self) -> list[dict[str, Any]]:
        return cast(
            list[dict[str, Any]],
            self._json_query(
                "iDj", "list", [], "get_data_directories", "Error retrieving data directories"
            ),
        )

    def get_resources_info(self) -> list[dict[str, Any]]:
        return cast(
            list[dict[str, Any]],
            self._json_query(
                "iRj", "list", [], "get_resources_info", "Error retrieving resources info"
            ),
        )

    def get_function_info(self, address: int) -> list[dict[str, Any]]:
        return cast(
            list[dict[str, Any]],
            self._json_query(
                f"afij @ {address}",
                "list",
                [],
                "get_function_info",
                "Error retrieving function info",
            ),
        )

    def search_hex_json(self, pattern: str) -> list[dict[str, Any]]:
        return cast(
            list[dict[str, Any]],
            self._json_query(
                f"/xj {pattern}",
                "list",
                [],
                "search_hex_json",
                "Error searching hex pattern JSON",
            ),
        )
