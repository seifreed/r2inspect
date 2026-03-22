"""Cached/query-oriented mixin methods for r2pipe adapters."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal, cast

if TYPE_CHECKING:
    from ..interfaces.core import R2CommandInterface


class R2PipeCachedQueryMixin:
    """Methods that primarily rely on cached JSON queries."""

    _safe_query: Any  # provided by host class
    _maybe_force_error: Any  # provided by host class
    _cache: dict[str, Any]  # provided by host class
    _safe_cached_query: Any  # provided by host class
    _cached_query: Any  # provided by host class

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

        self._maybe_force_error("get_file_info")
        try:
            if "ij" in self._cache:
                return cast(dict[str, Any], self._cache["ij"])
            info = facade.safe_cmd_dict(self._r2_iface, "ij")
            validated = facade.validate_r2_data(info, "dict")

            if not facade.is_valid_r2_response(validated):
                facade.logger.warning("Invalid or empty response from 'ij' command")
                return {}

            self._cache["ij"] = validated
            return cast(dict[str, Any], validated)
        except Exception:
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

    def get_strings(self) -> list[dict[str, Any]]:
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
        self._maybe_force_error("get_disasm")
        try:
            if size is None:
                cmd = "pdfj"
                data_type = "dict"
            else:
                cmd = f"pdj {size}"
                data_type = "list"
            if address is not None:
                cmd = f"{cmd} @ {address}"
            return self._cached_query(
                cmd,
                data_type,
                error_msg=f"No disassembly found for '{cmd}'",
                cache=address is None,
            )
        except Exception:
            return {} if size is None else []

    def get_cfg(self, address: int | None = None) -> Any:
        self._maybe_force_error("get_cfg")
        try:
            cmd = "agj"
            if address is not None:
                cmd = f"{cmd} @ {address}"
            return self._cached_query(
                cmd,
                "list",
                error_msg=f"No CFG data found for '{cmd}'",
                cache=address is None,
            )
        except Exception:
            return []

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

        self._maybe_force_error("get_pe_header")
        try:
            data = facade.safe_cmdj(self._r2_iface, "ihj", {})
            if isinstance(data, list) and data:
                return {"headers": data}
            if isinstance(data, dict):
                return data
            return {}
        except Exception:
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
