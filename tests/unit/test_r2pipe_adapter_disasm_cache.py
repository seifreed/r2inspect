"""Bounded per-function disasm cache: dedup, gating, and safety.

binlex / function_analyzer / simhash all issue the identical ``pdfj @ <addr>``
per function on one shared adapter; the bounded cache serves the repeats so the
disassembly happens once. It is gated by function count and capped, and never
caches empty/wedged results.
"""

from __future__ import annotations

from typing import Any

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.infrastructure.r2_command_timeout import mark_wedged
from tests.helpers.env import env_vars


class _CountingR2:
    """Counts cmdj calls per command; aflj sized by ``func_count``."""

    def __init__(self, func_count: int = 1, *, pdfj: Any = None) -> None:
        self.calls: dict[str, int] = {}
        self._functions = [{"offset": i, "name": f"fcn{i}"} for i in range(func_count)]
        self._pdfj = pdfj if pdfj is not None else {"ops": [{"opcode": "mov eax, 1"}]}

    def cmdj(self, command: str) -> Any:
        self.calls[command] = self.calls.get(command, 0) + 1
        if command == "aflj":
            return self._functions
        if command.startswith("pdfj @"):
            return self._pdfj
        if command.startswith("agj @"):
            return [{"blocks": [{"ops": []}]}]
        return None

    def cmd(self, command: str) -> str:
        return ""


def test_pdfj_same_address_fetched_once() -> None:
    backend = _CountingR2()
    adapter = R2PipeAdapter(backend)

    first = adapter.get_disasm(address=4096)
    second = adapter.get_disasm(address=4096)

    assert first == second
    assert backend.calls["pdfj @ 4096"] == 1


def test_agj_same_address_fetched_once() -> None:
    backend = _CountingR2()
    adapter = R2PipeAdapter(backend)

    adapter.get_cfg(address=4096)
    adapter.get_cfg(address=4096)

    assert backend.calls["agj @ 4096"] == 1


def test_distinct_addresses_cached_separately() -> None:
    backend = _CountingR2(func_count=2)
    adapter = R2PipeAdapter(backend)

    adapter.get_disasm(address=4096)
    adapter.get_disasm(address=8192)
    adapter.get_disasm(address=4096)
    adapter.get_disasm(address=8192)

    assert backend.calls["pdfj @ 4096"] == 1
    assert backend.calls["pdfj @ 8192"] == 1


def test_function_count_gate_disables_caching() -> None:
    backend = _CountingR2(func_count=2)
    adapter = R2PipeAdapter(backend)

    with env_vars(R2INSPECT_DISASM_CACHE_MAX_FUNCS="1"):
        adapter.get_disasm(address=4096)
        adapter.get_disasm(address=4096)

    # 2 functions > gate of 1 -> caching off -> each call re-fetches.
    assert backend.calls["pdfj @ 4096"] == 2


def test_entry_cap_stops_without_eviction() -> None:
    backend = _CountingR2(func_count=1)
    adapter = R2PipeAdapter(backend)

    with env_vars(R2INSPECT_DISASM_CACHE_MAX_ENTRIES="1"):
        adapter.get_disasm(address=4096)  # cached (cache now full)
        adapter.get_disasm(address=8192)  # cache full -> not cached
        adapter.get_disasm(address=8192)  # still not cached -> re-fetch
        adapter.get_disasm(address=4096)  # retained (stop-at-cap, no eviction)

    assert backend.calls["pdfj @ 4096"] == 1
    assert backend.calls["pdfj @ 8192"] == 2


def test_non_integer_env_override_falls_back_to_default() -> None:
    backend = _CountingR2()
    adapter = R2PipeAdapter(backend)

    with env_vars(
        R2INSPECT_DISASM_CACHE_MAX_FUNCS="notanint",
        R2INSPECT_DISASM_CACHE_MAX_ENTRIES="alsobad",
    ):
        adapter.get_disasm(address=4096)
        adapter.get_disasm(address=4096)

    # Garbage env values fall back to the defaults, so caching stays on.
    assert backend.calls["pdfj @ 4096"] == 1


def test_wedged_pipe_result_not_cached() -> None:
    backend = _CountingR2()
    adapter = R2PipeAdapter(backend)
    mark_wedged(adapter)

    result = adapter.get_disasm(address=4096)

    assert result == {}
    assert adapter._disasm_cache == {}


def test_empty_result_not_cached() -> None:
    backend = _CountingR2(pdfj={})
    adapter = R2PipeAdapter(backend)

    adapter.get_disasm(address=4096)
    adapter.get_disasm(address=4096)

    # An empty/invalid disasm result is never stored, so it is fetched each time.
    assert adapter._disasm_cache == {}
    assert backend.calls["pdfj @ 4096"] == 2


def test_clear_disasm_cache_leaves_global_cache() -> None:
    backend = _CountingR2()
    adapter = R2PipeAdapter(backend)

    adapter.get_functions()  # populates the global _cache (aflj)
    adapter.get_disasm(address=4096)  # populates the bounded _disasm_cache
    assert adapter._disasm_cache
    assert "aflj" in adapter._cache

    adapter.clear_disasm_cache()

    assert adapter._disasm_cache == {}
    assert "aflj" in adapter._cache


def test_concurrent_same_address_is_safe() -> None:
    import threading

    backend = _CountingR2()
    adapter = R2PipeAdapter(backend)
    barrier = threading.Barrier(4)

    def worker() -> None:
        barrier.wait()
        adapter.get_disasm(address=4096)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    # No crash; the cache holds exactly one entry for the address.
    assert "pdfj @ 4096" in adapter._disasm_cache
