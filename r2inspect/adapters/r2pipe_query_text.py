"""Text-oriented query mixin methods for r2pipe adapters."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from ..interfaces.core import R2CommandInterface


class R2PipeTextQueryMixin:
    """Methods that wrap textual r2 commands."""

    _safe_query: Any  # provided by host class
    _maybe_force_error: Any  # provided by host class
    _analysis_result: str | None  # provided by host class
    _file_backed_map_starts: list[int] | None  # provided by host class
    _file_backed_maps_resolved: bool  # provided by host class

    @property
    def _r2_iface(self) -> R2CommandInterface:
        return cast("R2CommandInterface", self)

    def analyze_all(self) -> str:
        from . import r2pipe_queries as facade

        if self._analysis_result is not None:
            return self._analysis_result

        def _execute() -> str:
            self._maybe_force_error("analyze_all")
            return facade.safe_cmd(self._r2_iface, "aaa", "")

        result = cast(str, self._safe_query(_execute, "", "Error running analysis"))
        self._analysis_result = result
        return result

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
            # /aa = linear case-insensitive assembly search. r2's /c means
            # "search for crypto materials" and returns its help text for an
            # arbitrary argument, which every opcode detector then mistook for a
            # positive match.
            return facade.safe_cmd(self._r2_iface, f"/aa {pattern}")

        return cast(str, self._safe_query(_execute, "", "Error searching text pattern"))

    def search_hex(self, hex_pattern: str) -> str:
        from . import r2pipe_queries as facade

        def _execute() -> str:
            self._maybe_force_error("search_hex")
            starts = self._get_file_backed_map_starts()
            if not starts:
                return facade.safe_cmd(self._r2_iface, f"/x {hex_pattern}")
            outputs = [
                facade.safe_cmd(
                    self._r2_iface,
                    f"/x {hex_pattern} @e:search.in=io.map @ {start:#x}",
                )
                for start in starts
            ]
            return "\n".join(output for output in outputs if output)

        return cast(str, self._safe_query(_execute, "", "Error searching hex pattern"))

    def _resolve_file_size(self) -> int | None:
        from . import r2pipe_queries as facade

        info = facade.safe_cmdj(self._r2_iface, "ij")
        if not isinstance(info, dict):
            return None
        core = info.get("core")
        if not isinstance(core, dict):
            return None
        size = core.get("size")
        return size if isinstance(size, int) and size > 0 else None

    def _get_file_backed_map_starts(self) -> list[int]:
        """Vaddr starts of the file-backed io maps, for scoped ``/x`` searches.

        r2's default ``search.in=io.maps`` spans the anonymous, zero-filled BSS
        map, which for statically-linked binaries can reach ~1 GB and makes
        every ``/x`` scan take seconds. Byte signatures only ever live in
        file-backed regions, so the hex search restricts itself to those maps
        (one ``@e:search.in=io.map`` pass each). Returns an empty list when the
        maps or file size can't be resolved, so the caller falls back to a plain
        whole-binary ``/x``.
        """
        if self._file_backed_maps_resolved:
            return self._file_backed_map_starts or []
        self._file_backed_maps_resolved = True
        starts = self._compute_file_backed_map_starts()
        self._file_backed_map_starts = starts
        return starts

    def _compute_file_backed_map_starts(self) -> list[int]:
        from . import r2pipe_queries as facade

        file_size = self._resolve_file_size()
        if not file_size:
            return []
        maps = facade.safe_cmdj(self._r2_iface, "omj")
        if not isinstance(maps, list):
            return []
        starts: list[int] = []
        for entry in maps:
            if not isinstance(entry, dict):
                continue
            start = entry.get("from")
            end = entry.get("to")
            delta = entry.get("delta", 0)
            if not (isinstance(start, int) and isinstance(end, int) and isinstance(delta, int)):
                continue
            length = end - start + 1
            if length <= 0:
                continue
            # A map whose physical backing fits inside the file is real content;
            # the oversized anonymous BSS map (delta+length far past EOF) is not.
            if delta + length <= file_size:
                starts.append(start)
        return starts
