"""Text-oriented query mixin methods for r2pipe adapters."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from ..interfaces.core import R2CommandInterface


class R2PipeTextQueryMixin:
    """Methods that wrap textual r2 commands."""

    _safe_query: Any  # provided by host class
    _maybe_force_error: Any  # provided by host class

    @property
    def _r2_iface(self) -> R2CommandInterface:
        return cast("R2CommandInterface", self)

    def analyze_all(self) -> str:
        from . import r2pipe_queries as facade

        def _execute() -> str:
            self._maybe_force_error("analyze_all")
            return facade.safe_cmd(self._r2_iface, "aaa", "")

        return cast(str, self._safe_query(_execute, "", "Error running analysis"))

    def get_info_text(self) -> str:
        from . import r2pipe_queries as facade

        def _execute() -> str:
            self._maybe_force_error("get_info_text")
            return facade.safe_cmd(self._r2_iface, "i", "")

        return cast(str, self._safe_query(_execute, "", "Error retrieving info text"))

    def get_dynamic_info_text(self) -> str:
        from . import r2pipe_queries as facade

        def _execute() -> str:
            self._maybe_force_error("get_dynamic_info_text")
            return facade.safe_cmd(self._r2_iface, "id", "")

        return cast(str, self._safe_query(_execute, "", "Error retrieving dynamic info text"))

    def get_entropy_pattern(self) -> str:
        from . import r2pipe_queries as facade

        def _execute() -> str:
            self._maybe_force_error("get_entropy_pattern")
            return facade.safe_cmd(self._r2_iface, "p=e 100", "")

        return cast(str, self._safe_query(_execute, "", "Error retrieving entropy pattern"))

    def get_pe_version_info_text(self) -> str:
        from . import r2pipe_queries as facade

        def _execute() -> str:
            self._maybe_force_error("get_pe_version_info_text")
            return facade.safe_cmd(self._r2_iface, "iR~version", "")

        return cast(str, self._safe_query(_execute, "", "Error retrieving PE version info text"))

    def get_pe_security_text(self) -> str:
        from . import r2pipe_queries as facade

        def _execute() -> str:
            self._maybe_force_error("get_pe_security_text")
            return facade.safe_cmd(self._r2_iface, "iHH", "")

        return cast(str, self._safe_query(_execute, "", "Error retrieving PE security text"))

    def get_header_text(self) -> str:
        from . import r2pipe_queries as facade

        def _execute() -> str:
            self._maybe_force_error("get_header_text")
            return facade.safe_cmd(self._r2_iface, "ih", "")

        return cast(str, self._safe_query(_execute, "", "Error retrieving header text"))

    def get_headers_json(self) -> Any:
        from . import r2pipe_queries as facade

        def _execute() -> Any:
            self._maybe_force_error("get_headers_json")
            return facade.safe_cmdj(self._r2_iface, "ihj", None)

        return self._safe_query(_execute, None, "Error retrieving header JSON")

    def get_strings_text(self) -> str:
        from . import r2pipe_queries as facade

        def _execute() -> str:
            self._maybe_force_error("get_strings_text")
            return facade.safe_cmd(self._r2_iface, "izz~..", "")

        return cast(str, self._safe_query(_execute, "", "Error retrieving strings text"))

    def get_strings_filtered(self, command: str) -> str:
        from . import r2pipe_queries as facade

        def _execute() -> str:
            self._maybe_force_error("get_strings_filtered")
            return facade.safe_cmd(self._r2_iface, command, "")

        return cast(str, self._safe_query(_execute, "", "Error retrieving filtered strings"))

    def get_disasm_text(self, address: int | None = None, size: int | None = None) -> str:
        from . import r2pipe_queries as facade

        def _execute() -> str:
            self._maybe_force_error("get_disasm_text")
            cmd = "pi" if size is None else f"pi {size}"
            if address is not None:
                cmd = f"{cmd} @ {address}"
            return facade.safe_cmd(self._r2_iface, cmd, "")

        return cast(str, self._safe_query(_execute, "", "Error retrieving disasm text"))

    def search_text(self, pattern: str) -> str:
        from . import r2pipe_queries as facade

        def _execute() -> str:
            self._maybe_force_error("search_text")
            return facade.safe_cmd(self._r2_iface, f"/c {pattern}")

        return cast(str, self._safe_query(_execute, "", "Error searching text pattern"))

    def search_hex(self, hex_pattern: str) -> str:
        from . import r2pipe_queries as facade

        def _execute() -> str:
            self._maybe_force_error("search_hex")
            return facade.safe_cmd(self._r2_iface, f"/x {hex_pattern}")

        return cast(str, self._safe_query(_execute, "", "Error searching hex pattern"))
