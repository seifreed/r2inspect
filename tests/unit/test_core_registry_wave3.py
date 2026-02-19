"""Wave-3 coverage tests.

Covers missing lines in:
  r2inspect/core/r2_session.py
  r2inspect/cli/batch_processing.py
  r2inspect/registry/registry_queries.py
  r2inspect/utils/memory_manager.py
  r2inspect/modules/import_domain.py
  r2inspect/modules/rich_header_search.py
"""

from __future__ import annotations

import os
import struct
import subprocess
import sys
from typing import Any

import psutil
import pytest


# ---------------------------------------------------------------------------
# r2inspect/core/r2_session.py  -- lines 4,6,8-22
# Importing the shim module exercises all re-export lines.
# ---------------------------------------------------------------------------


def test_r2_session_shim_exports_all_symbols():
    import r2inspect.core.r2_session as shim

    assert shim.R2Session is not None
    assert shim.r2pipe is not None
    assert shim.psutil is not None
    assert shim.platform is not None
    assert isinstance(shim.HUGE_FILE_THRESHOLD_MB, (int, float))
    assert isinstance(shim.LARGE_FILE_THRESHOLD_MB, (int, float))
    assert isinstance(shim.MIN_INFO_RESPONSE_LENGTH, int)
    assert isinstance(shim.TEST_HUGE_FILE_THRESHOLD_MB, (int, float))
    assert isinstance(shim.TEST_LARGE_FILE_THRESHOLD_MB, (int, float))
    assert isinstance(shim.TEST_R2_ANALYSIS_TIMEOUT, (int, float))
    assert isinstance(shim.TEST_R2_CMD_TIMEOUT, (int, float))
    assert isinstance(shim.TEST_R2_OPEN_TIMEOUT, (int, float))


def test_r2_session_shim_all_in_all():
    import r2inspect.core.r2_session as shim

    expected = [
        "R2Session",
        "r2pipe",
        "psutil",
        "platform",
        "HUGE_FILE_THRESHOLD_MB",
        "LARGE_FILE_THRESHOLD_MB",
        "MIN_INFO_RESPONSE_LENGTH",
        "TEST_HUGE_FILE_THRESHOLD_MB",
        "TEST_LARGE_FILE_THRESHOLD_MB",
        "TEST_R2_ANALYSIS_TIMEOUT",
        "TEST_R2_CMD_TIMEOUT",
        "TEST_R2_OPEN_TIMEOUT",
    ]
    for name in expected:
        assert name in shim.__all__, f"{name} missing from __all__"


# ---------------------------------------------------------------------------
# r2inspect/cli/batch_processing.py
# ---------------------------------------------------------------------------


# -- lines 68-69: magic import failure path via module reload ---------------

def test_magic_import_failure_sets_magic_none():
    """Cover except/None branch of the magic import guard."""
    import importlib
    import r2inspect.cli.batch_processing as bp

    original_magic = sys.modules.get("magic", "__NOT_PRESENT__")
    # Block the magic import so the except branch fires on reload
    sys.modules["magic"] = None  # type: ignore[assignment]
    try:
        importlib.reload(bp)
        assert bp.magic is None
    finally:
        if original_magic == "__NOT_PRESENT__":
            sys.modules.pop("magic", None)
        else:
            sys.modules["magic"] = original_magic
        importlib.reload(bp)


# -- line 188: os._exit path in _safe_exit ----------------------------------

def test_safe_exit_raises_system_exit_with_env_var():
    """Cover the SystemExit branch of _safe_exit (env var set)."""
    from r2inspect.cli.batch_processing import _safe_exit

    old = os.environ.get("R2INSPECT_TEST_SAFE_EXIT")
    os.environ["R2INSPECT_TEST_SAFE_EXIT"] = "1"
    try:
        with pytest.raises(SystemExit) as exc_info:
            _safe_exit(42)
        assert exc_info.value.code == 42
    finally:
        if old is None:
            os.environ.pop("R2INSPECT_TEST_SAFE_EXIT", None)
        else:
            os.environ["R2INSPECT_TEST_SAFE_EXIT"] = old


def test_safe_exit_calls_os_exit_without_env_var():
    """Cover line 188: os._exit is invoked when env var is absent."""
    script = (
        "import os, sys\n"
        "os.environ.pop('R2INSPECT_TEST_SAFE_EXIT', None)\n"
        "sys.path.insert(0, sys.argv[1])\n"
        "from r2inspect.cli.batch_processing import _safe_exit\n"
        "_safe_exit(7)\n"
    )
    repo_root = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    result = subprocess.run(
        [sys.executable, "-c", script, repo_root],
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 7


# -- line 250/270: _flush_coverage_data with dummy coverage -----------------

def test_flush_coverage_data_with_dummy_coverage_object():
    """Cover lines 246-255 and 270 (save via dummy coverage)."""
    from r2inspect.cli.batch_processing import _flush_coverage_data

    saved_keys = {
        k: os.environ.get(k)
        for k in (
            "R2INSPECT_TEST_COVERAGE_IMPORT_ERROR",
            "R2INSPECT_TEST_COVERAGE_CURRENT_ERROR",
            "R2INSPECT_TEST_COVERAGE_DUMMY",
            "R2INSPECT_TEST_COVERAGE_NONE",
            "R2INSPECT_TEST_COVERAGE_SAVE_ERROR",
        )
    }
    for k in saved_keys:
        os.environ.pop(k, None)

    os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"] = "1"
    try:
        # Should not raise; save() on the dummy object is a no-op
        _flush_coverage_data()
    finally:
        for k, v in saved_keys.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_flush_coverage_data_import_error_returns_early():
    """Cover the early-return path when coverage import fails."""
    from r2inspect.cli.batch_processing import _flush_coverage_data

    old = os.environ.get("R2INSPECT_TEST_COVERAGE_IMPORT_ERROR")
    os.environ["R2INSPECT_TEST_COVERAGE_IMPORT_ERROR"] = "1"
    try:
        _flush_coverage_data()  # must not raise
    finally:
        if old is None:
            os.environ.pop("R2INSPECT_TEST_COVERAGE_IMPORT_ERROR", None)
        else:
            os.environ["R2INSPECT_TEST_COVERAGE_IMPORT_ERROR"] = old


# -- lines 279-287: _pytest_running branches --------------------------------

def test_pytest_running_returns_true_for_r2inspect_test_mode():
    """Cover line 277-278: R2INSPECT_TEST_MODE branch."""
    from r2inspect.cli.batch_processing import _pytest_running

    old = os.environ.get("R2INSPECT_TEST_MODE")
    os.environ["R2INSPECT_TEST_MODE"] = "1"
    try:
        assert _pytest_running() is True
    finally:
        if old is None:
            os.environ.pop("R2INSPECT_TEST_MODE", None)
        else:
            os.environ["R2INSPECT_TEST_MODE"] = old


def test_pytest_running_returns_true_for_safe_exit_env():
    """Cover line 279-280: R2INSPECT_TEST_SAFE_EXIT branch."""
    from r2inspect.cli.batch_processing import _pytest_running

    saved_mode = os.environ.pop("R2INSPECT_TEST_MODE", None)
    old_safe = os.environ.get("R2INSPECT_TEST_SAFE_EXIT")
    os.environ["R2INSPECT_TEST_SAFE_EXIT"] = "1"
    try:
        assert _pytest_running() is True
    finally:
        if saved_mode is not None:
            os.environ["R2INSPECT_TEST_MODE"] = saved_mode
        if old_safe is None:
            os.environ.pop("R2INSPECT_TEST_SAFE_EXIT", None)
        else:
            os.environ["R2INSPECT_TEST_SAFE_EXIT"] = old_safe


def test_pytest_running_returns_true_for_pytest_current_test():
    """Cover line 281-282: PYTEST_CURRENT_TEST branch."""
    from r2inspect.cli.batch_processing import _pytest_running

    saved_mode = os.environ.pop("R2INSPECT_TEST_MODE", None)
    saved_safe = os.environ.pop("R2INSPECT_TEST_SAFE_EXIT", None)
    old = os.environ.get("PYTEST_CURRENT_TEST")
    os.environ["PYTEST_CURRENT_TEST"] = "test_something"
    try:
        assert _pytest_running() is True
    finally:
        if saved_mode is not None:
            os.environ["R2INSPECT_TEST_MODE"] = saved_mode
        if saved_safe is not None:
            os.environ["R2INSPECT_TEST_SAFE_EXIT"] = saved_safe
        if old is None:
            os.environ.pop("PYTEST_CURRENT_TEST", None)
        else:
            os.environ["PYTEST_CURRENT_TEST"] = old


def test_pytest_running_returns_true_for_coverage_env_key():
    """Cover line 283-284: R2INSPECT_TEST_COVERAGE_* branch."""
    from r2inspect.cli.batch_processing import _pytest_running

    saved_mode = os.environ.pop("R2INSPECT_TEST_MODE", None)
    saved_safe = os.environ.pop("R2INSPECT_TEST_SAFE_EXIT", None)
    saved_cur = os.environ.pop("PYTEST_CURRENT_TEST", None)
    marker_key = "R2INSPECT_TEST_COVERAGE_WAVE3_PROBE"
    os.environ[marker_key] = "1"
    try:
        assert _pytest_running() is True
    finally:
        os.environ.pop(marker_key, None)
        if saved_mode is not None:
            os.environ["R2INSPECT_TEST_MODE"] = saved_mode
        if saved_safe is not None:
            os.environ["R2INSPECT_TEST_SAFE_EXIT"] = saved_safe
        if saved_cur is not None:
            os.environ["PYTEST_CURRENT_TEST"] = saved_cur


def test_pytest_running_returns_true_via_sys_modules():
    """Cover line 287: fallback 'pytest' in sys.modules (always true in pytest run)."""
    from r2inspect.cli.batch_processing import _pytest_running

    # Remove all R2INSPECT/PYTEST env sentinels so only sys.modules path remains
    saved: dict[str, str] = {}
    to_remove = [k for k in os.environ if k.startswith("R2INSPECT_TEST") or k == "PYTEST_CURRENT_TEST"]
    for k in to_remove:
        saved[k] = os.environ.pop(k)
    try:
        # pytest is in sys.modules, so must return True
        assert _pytest_running() is True
    finally:
        os.environ.update(saved)


# -- ensure_batch_shutdown exercised ----------------------------------------

def test_ensure_batch_shutdown_returns_cleanly_no_stray_threads():
    """Cover ensure_batch_shutdown when no lingering non-daemon threads remain."""
    from r2inspect.cli.batch_processing import ensure_batch_shutdown

    old = os.environ.get("R2INSPECT_TEST_SAFE_EXIT")
    os.environ["R2INSPECT_TEST_SAFE_EXIT"] = "1"
    try:
        ensure_batch_shutdown(timeout=0.05)
    finally:
        if old is None:
            os.environ.pop("R2INSPECT_TEST_SAFE_EXIT", None)
        else:
            os.environ["R2INSPECT_TEST_SAFE_EXIT"] = old


# ---------------------------------------------------------------------------
# r2inspect/registry/registry_queries.py
# ---------------------------------------------------------------------------

from r2inspect.registry.analyzer_registry import AnalyzerRegistry
from r2inspect.registry.categories import AnalyzerCategory


class _DummyA:
    pass


class _DummyB:
    pass


class _DummyC:
    pass


def _make_registry() -> AnalyzerRegistry:
    r = AnalyzerRegistry(lazy_loading=False)
    r.register("alpha", _DummyA, AnalyzerCategory.FORMAT, file_formats={"PE"}, required=True, description="alpha")
    r.register("beta", _DummyB, AnalyzerCategory.HASHING, file_formats={"ELF"}, required=False, description="beta")
    r.register("gamma", _DummyC, AnalyzerCategory.DETECTION, file_formats={"PE", "ELF"}, required=False, description="gamma")
    return r


# -- lines 71-73: get_analyzers_for_format ----------------------------------

def test_get_analyzers_for_format_returns_matching():
    r = _make_registry()
    pe_analyzers = r.get_analyzers_for_format("PE")
    assert "alpha" in pe_analyzers
    assert "gamma" in pe_analyzers
    assert "beta" not in pe_analyzers


def test_get_analyzers_for_format_empty_when_no_match():
    r = _make_registry()
    result = r.get_analyzers_for_format("MACHO")
    assert result == {}


# -- line 87: get_by_category TypeError -------------------------------------

def test_get_by_category_raises_type_error_for_non_category():
    r = _make_registry()
    with pytest.raises(TypeError, match="AnalyzerCategory"):
        r.get_by_category("format")  # type: ignore[arg-type]


def test_get_by_category_returns_matching_analyzers():
    r = _make_registry()
    result = r.get_by_category(AnalyzerCategory.FORMAT)
    assert "alpha" in result
    assert "beta" not in result


# -- lines 104-106: get_required_analyzers ----------------------------------

def test_get_required_analyzers_returns_only_required():
    r = _make_registry()
    required = r.get_required_analyzers()
    assert "alpha" in required
    assert "beta" not in required
    assert "gamma" not in required


# -- line 114: get_optional_analyzers ---------------------------------------

def test_get_optional_analyzers_returns_non_required():
    r = _make_registry()
    optional = r.get_optional_analyzers()
    assert "alpha" not in optional
    assert "beta" in optional
    assert "gamma" in optional


# -- line 122: list_analyzers -----------------------------------------------

def test_list_analyzers_returns_all_metadata_dicts():
    r = _make_registry()
    items = r.list_analyzers()
    assert len(items) == 3
    names = {d["name"] for d in items}
    assert names == {"alpha", "beta", "gamma"}


# -- line 143: circular dependency detection --------------------------------

def test_resolve_execution_order_raises_on_circular_dependency():
    r = AnalyzerRegistry(lazy_loading=False)
    r.register("X", _DummyA, AnalyzerCategory.FORMAT, dependencies={"Y"})
    r.register("Y", _DummyB, AnalyzerCategory.FORMAT, dependencies={"X"})
    with pytest.raises(ValueError, match="[Cc]ircular"):
        r.resolve_execution_order(["X", "Y"])


# -- line 154: KeyError on unknown analyzer in _build_dependency_graph ------

def test_resolve_execution_order_raises_for_unknown_analyzer():
    r = _make_registry()
    with pytest.raises(KeyError, match="[Uu]nknown"):
        r.resolve_execution_order(["alpha", "no_such_analyzer"])


# -- line 169: _calculate_in_degrees with actual deps -----------------------

def test_resolve_execution_order_respects_dependencies():
    r = AnalyzerRegistry(lazy_loading=False)
    r.register("dep", _DummyA, AnalyzerCategory.FORMAT)
    r.register("main", _DummyB, AnalyzerCategory.FORMAT, dependencies={"dep"})
    order = r.resolve_execution_order(["dep", "main"])
    assert order.index("dep") < order.index("main")


# -- line 194: clear() -------------------------------------------------------

def test_clear_removes_all_analyzers():
    r = _make_registry()
    assert len(r) == 3
    r.clear()
    assert len(r) == 0


# -- line 202: __contains__ --------------------------------------------------

def test_contains_returns_true_for_registered_and_false_otherwise():
    r = _make_registry()
    assert "alpha" in r
    assert "nonexistent" not in r


# -- get_dependencies -------------------------------------------------------

def test_get_dependencies_returns_set():
    r = AnalyzerRegistry(lazy_loading=False)
    r.register("with_dep", _DummyA, AnalyzerCategory.FORMAT, dependencies={"beta"})
    deps = r.get_dependencies("with_dep")
    assert "beta" in deps


def test_get_dependencies_returns_empty_set_for_unknown():
    r = _make_registry()
    assert r.get_dependencies("not_registered") == set()


# ---------------------------------------------------------------------------
# r2inspect/utils/memory_manager.py
# ---------------------------------------------------------------------------

from r2inspect.utils.memory_manager import (
    MemoryAwareAnalyzer,
    MemoryLimits,
    MemoryMonitor,
    check_memory_limits,
    cleanup_memory,
    configure_memory_limits,
    get_memory_stats,
    global_memory_monitor,
)


def _process_memory_mb() -> float:
    return psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024


def _make_warning_monitor() -> MemoryMonitor:
    """Return a monitor whose limit puts current process at warning level."""
    current_mb = _process_memory_mb()
    # target process_usage_percent ~= 0.85 (between 0.8 warning and 0.9 critical)
    limit_mb = max(1, int(current_mb / 0.85))
    limits = MemoryLimits(
        max_process_memory_mb=limit_mb,
        memory_warning_threshold=0.8,
        memory_critical_threshold=0.9,
        gc_trigger_threshold=0.75,
    )
    return MemoryMonitor(limits)


# -- lines 116,120,121: _handle_warning_memory with good callback -----------

def test_warning_callback_is_invoked():
    monitor = _make_warning_monitor()
    received: list[dict[str, Any]] = []

    def _cb(stats: dict[str, Any]) -> None:
        received.append(stats)

    monitor.set_callbacks(warning_callback=_cb)
    stats = monitor.check_memory(force=True)
    # If we're in the warning band the callback was called
    if stats.get("status") == "warning":
        assert len(received) == 1
        assert monitor.memory_warnings >= 1


# -- lines 121-122: _handle_warning_memory with raising callback ------------

def test_warning_callback_exception_is_swallowed():
    monitor = _make_warning_monitor()

    def _bad_cb(stats: dict[str, Any]) -> None:
        raise RuntimeError("simulated warning callback failure")

    monitor.set_callbacks(warning_callback=_bad_cb)
    # Must not propagate the exception
    result = monitor.check_memory(force=True)
    assert "status" in result


# -- lines 184-185: is_memory_available system-memory path ------------------

def test_is_memory_available_returns_bool():
    monitor = MemoryMonitor()
    # Small request - should be available on any reasonable machine
    assert isinstance(monitor.is_memory_available(1.0), bool)


def test_is_memory_available_false_when_exceeds_process_limit():
    limits = MemoryLimits(max_process_memory_mb=1)
    monitor = MemoryMonitor(limits)
    # Requesting more than the process limit must fail
    assert monitor.is_memory_available(9999.0) is False


# -- lines 356-363: configure_memory_limits ---------------------------------

def test_configure_memory_limits_updates_known_key():
    original = global_memory_monitor.limits.string_limit
    try:
        configure_memory_limits(string_limit=12345)
        assert global_memory_monitor.limits.string_limit == 12345
    finally:
        configure_memory_limits(string_limit=original)


def test_configure_memory_limits_ignores_unknown_key():
    # Should not raise for an unknown key
    configure_memory_limits(nonexistent_key_wave3=99)


# -- cleanup_memory ---------------------------------------------------------

def test_cleanup_memory_returns_stats_dict():
    result = cleanup_memory()
    assert isinstance(result, dict)
    assert "process_memory_mb" in result


# -- MemoryAwareAnalyzer.safe_large_operation lines 356-363 ----------------

def test_memory_aware_analyzer_safe_large_operation_executes():
    monitor = MemoryMonitor()
    monitor.check_interval = 0.0  # disable caching so system_memory_available_mb is populated
    monitor.check_memory(force=True)
    analyzer = MemoryAwareAnalyzer(memory_monitor=monitor)
    result = analyzer.safe_large_operation(lambda: 42, estimated_memory_mb=1.0)
    assert result == 42


def test_memory_aware_analyzer_skips_when_memory_unavailable():
    limits = MemoryLimits(max_process_memory_mb=1)
    monitor = MemoryMonitor(limits)
    analyzer = MemoryAwareAnalyzer(memory_monitor=monitor)
    result = analyzer.safe_large_operation(lambda: 99, estimated_memory_mb=9999.0)
    assert result is None


# ---------------------------------------------------------------------------
# r2inspect/modules/import_domain.py  -- lines 102-113
# ---------------------------------------------------------------------------

from r2inspect.modules.import_domain import (
    INJECTION_APIS,
    NETWORK_APIS,
    build_api_categories,
    categorize_apis,
    find_max_risk_score,
    risk_level_from_score,
)


# -- lines 102-109: build_api_categories return dict ------------------------

def test_build_api_categories_returns_all_expected_keys():
    cats = build_api_categories()
    expected_keys = {"Injection", "Anti-Analysis", "Crypto", "Persistence", "Network", "Process", "Memory", "Loading"}
    assert set(cats.keys()) == expected_keys


def test_build_api_categories_injection_contains_known_api():
    cats = build_api_categories()
    assert "CreateRemoteThread" in cats["Injection"]


# -- lines 110-113: categorize_apis with matching imports -------------------

def test_categorize_apis_matches_injection_apis():
    cats = build_api_categories()
    api_cats = {k: list(v.keys()) for k, v in cats.items()}
    imports = [
        {"name": "CreateRemoteThread"},
        {"name": "WriteProcessMemory"},
        {"name": "socket"},
    ]
    result = categorize_apis(imports, api_cats)
    assert "Injection" in result
    assert result["Injection"]["count"] >= 1


def test_categorize_apis_empty_imports_returns_empty():
    cats = build_api_categories()
    api_cats = {k: list(v.keys()) for k, v in cats.items()}
    result = categorize_apis([], api_cats)
    assert result == {}


def test_categorize_apis_no_category_match():
    result = categorize_apis(
        [{"name": "NotARealApi"}],
        {"Injection": ["CreateRemoteThread"]},
    )
    assert result == {}


def test_find_max_risk_score_with_matching_api():
    cats = build_api_categories()
    score, tags = find_max_risk_score("CreateRemoteThread", cats)
    assert score > 0
    assert len(tags) > 0


def test_find_max_risk_score_no_match():
    cats = build_api_categories()
    score, tags = find_max_risk_score("NoSuchApi", cats)
    assert score == 0
    assert tags == []


def test_risk_level_from_score_all_bands():
    assert risk_level_from_score(90) == "Critical"
    assert risk_level_from_score(70) == "High"
    assert risk_level_from_score(50) == "Medium"
    assert risk_level_from_score(30) == "Low"
    assert risk_level_from_score(5) == "Minimal"


# ---------------------------------------------------------------------------
# r2inspect/modules/rich_header_search.py  -- lines 53-55,128,137-139,187,191,197-199
# ---------------------------------------------------------------------------

from r2inspect.modules.rich_header_search import RichHeaderSearchMixin


class _BytesAdapter:
    """Adapter backed by a fixed bytes buffer."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def read_bytes(self, offset: int, size: int) -> bytes:
        return self._data[offset: offset + size]

    def read_bytes_list(self, offset: int, size: int) -> list[int]:
        chunk = self._data[offset: offset + size]
        return list(chunk)


class _RaisingAdapter:
    """Adapter whose read_bytes always raises."""

    def read_bytes(self, offset: int, size: int) -> bytes:
        raise RuntimeError("read error")

    def read_bytes_list(self, offset: int, size: int) -> list[int]:
        raise RuntimeError("read error")


class _Searcher(RichHeaderSearchMixin):
    def __init__(self, adapter: Any) -> None:
        self.adapter = adapter


# -- lines 53-55: _manual_rich_search exception path -----------------------

def test_manual_rich_search_returns_none_on_read_error():
    searcher = _Searcher(_RaisingAdapter())
    result = searcher._manual_rich_search()
    assert result is None


def test_manual_rich_search_returns_none_for_empty_data():
    searcher = _Searcher(_BytesAdapter(b""))
    result = searcher._manual_rich_search()
    assert result is None


def test_manual_rich_search_returns_none_when_adapter_is_none():
    searcher = _Searcher(None)
    result = searcher._manual_rich_search()
    assert result is None


# -- line 128: _pattern_based_rich_search returns None when no valid pairs --

def test_pattern_based_rich_search_no_match_returns_none():
    # Data with 'Rich' but no valid 'DanS' before it
    data = b"\x00" * 200 + b"Rich" + struct.pack("<I", 0xABCD1234) + b"\x00" * 100
    searcher = _Searcher(_BytesAdapter(data))
    result = searcher._pattern_based_rich_search(data)
    assert result is None


# -- lines 137-139: _pattern_based_rich_search exception path --------------

def test_pattern_based_rich_search_handles_exception_gracefully():
    # Pass an integer (not bytes) to trigger a TypeError inside the method
    searcher = _Searcher(_BytesAdapter(b""))
    result = searcher._pattern_based_rich_search(None)  # type: ignore[arg-type]
    assert result is None


# -- line 187: _validate_rich_size returns False for invalid sizes ----------

def test_validate_rich_size_too_small_returns_false():
    searcher = _Searcher(_BytesAdapter(b""))
    assert searcher._validate_rich_size(0) is False
    assert searcher._validate_rich_size(8) is False


def test_validate_rich_size_too_large_returns_false():
    searcher = _Searcher(_BytesAdapter(b""))
    assert searcher._validate_rich_size(513) is False


def test_validate_rich_size_valid_returns_true():
    searcher = _Searcher(_BytesAdapter(b""))
    assert searcher._validate_rich_size(16) is True


# -- line 191: _extract_xor_key returns None when adapter lacks method -----

def test_extract_xor_key_returns_none_when_adapter_is_none():
    searcher = _Searcher(None)
    assert searcher._extract_xor_key(0) is None


def test_extract_xor_key_returns_none_for_short_read():
    # Adapter returns fewer than 4 bytes
    searcher = _Searcher(_BytesAdapter(b"\x00" * 2))
    assert searcher._extract_xor_key(0) is None


def test_extract_xor_key_returns_none_for_zero_key():
    # All-zero key should return None
    searcher = _Searcher(_BytesAdapter(b"\x00" * 16))
    assert searcher._extract_xor_key(0) is None


def test_extract_xor_key_returns_value_for_valid_key():
    key = 0xABCD1234
    data = b"\x00" * 4 + struct.pack("<I", key) + b"\x00" * 8
    searcher = _Searcher(_BytesAdapter(data))
    result = searcher._extract_xor_key(0)
    assert result == key


# -- lines 197-199: _try_extract_rich_at_offsets exception path ------------

def test_try_extract_rich_at_offsets_returns_none_for_invalid_size():
    searcher = _Searcher(_BytesAdapter(b"\x00" * 64))
    # dans_offset == rich_offset -> size = 0 -> invalid
    result = searcher._try_extract_rich_at_offsets(10, 10)
    assert result is None


def test_try_extract_rich_at_offsets_returns_none_when_adapter_none():
    searcher = _Searcher(None)
    result = searcher._try_extract_rich_at_offsets(0, 20)
    assert result is None


# -- _find_all_occurrences --------------------------------------------------

def test_find_all_occurrences_finds_multiple():
    data = b"abcRichabcRichabc"
    searcher = _Searcher(_BytesAdapter(data))
    offsets = searcher._find_all_occurrences(data, b"Rich")
    assert len(offsets) == 2


def test_find_all_occurrences_empty_when_not_present():
    searcher = _Searcher(_BytesAdapter(b""))
    assert searcher._find_all_occurrences(b"nothing", b"Rich") == []


# -- _offset_pair_valid -----------------------------------------------------

def test_offset_pair_valid_true_within_delta():
    searcher = _Searcher(_BytesAdapter(b""))
    assert searcher._offset_pair_valid(10, 50, 512) is True


def test_offset_pair_valid_false_when_delta_exceeded():
    searcher = _Searcher(_BytesAdapter(b""))
    assert searcher._offset_pair_valid(10, 600, 512) is False


def test_offset_pair_valid_false_when_dans_after_rich():
    searcher = _Searcher(_BytesAdapter(b""))
    assert searcher._offset_pair_valid(60, 10, 512) is False
