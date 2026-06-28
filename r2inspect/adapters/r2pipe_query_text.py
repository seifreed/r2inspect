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
    _executable_map_starts: list[int] | None  # provided by host class
    _file_backed_map_regions: list[tuple[int, int]] | None  # provided by host class
    _file_backed_maps_resolved: bool  # provided by host class
    _map_bytes_resolved: bool  # provided by host class
    _map_bytes: list[tuple[int, bytes]] | None  # provided by host class
    read_bytes: Any  # provided by host class

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
        # /aa = linear case-insensitive assembly search. r2's /c means
        # "search for crypto materials" and returns its help text for an
        # arbitrary argument, which every opcode detector then mistook for a
        # positive match.
        def _execute() -> str:
            self._maybe_force_error("search_text")
            return self._scoped_search("/aa", pattern)

        return cast(str, self._safe_query(_execute, "", "Error searching text pattern"))

    def search_hex(self, hex_pattern: str) -> str:
        def _execute() -> str:
            self._maybe_force_error("search_hex")
            in_memory = self._search_hex_in_memory(hex_pattern)
            if in_memory is not None:
                return in_memory
            return self._scoped_search("/x", hex_pattern)

        return cast(str, self._safe_query(_execute, "", "Error searching hex pattern"))

    def _search_hex_in_memory(self, hex_pattern: str) -> str | None:
        """Find a byte pattern across the file-backed maps without re-scanning.

        r2's ``/x`` walks the whole search space once per pattern, so on a large
        binary dozens of constant/signature probes each re-scan hundreds of MB.
        Instead read every file-backed map's bytes once (via the same r2 IO view
        ``/x`` searches, so addresses match exactly) and locate all patterns in
        memory. Returns ``None`` -- so the caller falls back to ``/x`` -- when the
        maps or their bytes can't be resolved, or the pattern isn't plain hex
        (r2 wildcards/masks aren't supported here).
        """
        try:
            needle = bytes.fromhex(hex_pattern)
        except ValueError:
            return None
        if not needle:
            return None
        map_bytes = self._get_map_bytes()
        if map_bytes is None:
            return None
        lines: list[str] = []
        step = len(needle)
        for base, buf in map_bytes:
            offset = buf.find(needle)
            while offset != -1:
                lines.append(f"{base + offset:#x}")
                # r2's /x steps past each hit by the pattern length, so a run of
                # repeated bytes yields non-overlapping matches; mirror that here
                # instead of advancing one byte (which over-reports overlaps).
                offset = buf.find(needle, offset + step)
        return "\n".join(lines)

    def _get_map_bytes(self) -> list[tuple[int, bytes]] | None:
        if self._map_bytes_resolved:
            return self._map_bytes
        self._map_bytes_resolved = True
        self._map_bytes = self._read_file_backed_map_bytes()
        return self._map_bytes

    def _read_file_backed_map_bytes(self) -> list[tuple[int, bytes]] | None:
        regions = self._get_file_backed_map_regions()
        if not regions:
            return None
        chunk = 8 * 1024 * 1024
        cached: list[tuple[int, bytes]] = []
        for base, length in regions:
            buffer = bytearray()
            offset = 0
            while offset < length:
                size = min(chunk, length - offset)
                data = self.read_bytes(base + offset, size)
                if len(data) != size:
                    # A short read means the in-memory view is incomplete, so
                    # results could miss hits; fall back to /x for correctness.
                    return None
                buffer.extend(data)
                offset += size
            cached.append((base, bytes(buffer)))
        return cached

    def _scoped_search(self, search_cmd: str, pattern: str) -> str:
        """Run an r2 search restricted to file-backed io maps.

        r2's default ``search.in=io.maps`` spans the anonymous, zero-filled BSS
        map (up to ~1 GB for statically-linked binaries), so an unscoped ``/x``
        or ``/aa`` wastes seconds scanning zeros. Search each scoped map in turn
        instead, falling back to a plain whole-binary search when the maps can't
        be resolved. ``/aa`` disassembles, so it is restricted to executable maps
        (instructions only live in r-x regions); ``/x`` byte searches span every
        file-backed map (constants live in data sections too). Results are
        unchanged.
        """
        from . import r2pipe_queries as facade

        starts = (
            self._get_executable_map_starts()
            if search_cmd == "/aa"
            else self._get_file_backed_map_starts()
        )
        if not starts:
            return facade.safe_cmd(self._r2_iface, f"{search_cmd} {pattern}")
        outputs = [
            facade.safe_cmd(
                self._r2_iface,
                f"{search_cmd} {pattern} @e:search.in=io.map @ {start:#x}",
            )
            for start in starts
        ]
        return "\n".join(output for output in outputs if output)

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
        self._ensure_map_starts_resolved()
        return self._file_backed_map_starts or []

    def _get_executable_map_starts(self) -> list[int]:
        """Vaddr starts of the executable file-backed io maps, for ``/aa`` scans.

        ``/aa`` disassembles the search region, so only ``r-x`` maps can hold
        real instructions. Returns an empty list when no executable map resolves,
        so the caller falls back to a plain whole-binary ``/aa``.
        """
        self._ensure_map_starts_resolved()
        return self._executable_map_starts or []

    def _ensure_map_starts_resolved(self) -> None:
        if self._file_backed_maps_resolved:
            return
        self._file_backed_maps_resolved = True
        file_backed, executable, regions = self._compute_map_starts()
        self._file_backed_map_starts = file_backed
        self._executable_map_starts = executable
        self._file_backed_map_regions = regions

    def _compute_map_starts(self) -> tuple[list[int], list[int], list[tuple[int, int]]]:
        from . import r2pipe_queries as facade

        file_size = self._resolve_file_size()
        if not file_size:
            return [], [], []
        maps = facade.safe_cmdj(self._r2_iface, "omj")
        if not isinstance(maps, list):
            return [], [], []
        file_backed: list[int] = []
        executable: list[int] = []
        regions: list[tuple[int, int]] = []
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
                file_backed.append(start)
                regions.append((start, length))
                perm = entry.get("perm")
                if isinstance(perm, str) and "x" in perm:
                    executable.append(start)
        return file_backed, executable, regions

    def _get_file_backed_map_regions(self) -> list[tuple[int, int]]:
        """(vaddr_start, length) of each file-backed io map."""
        self._ensure_map_starts_resolved()
        return self._file_backed_map_regions or []
