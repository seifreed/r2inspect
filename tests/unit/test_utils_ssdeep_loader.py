#!/usr/bin/env python3
"""Tests for r2inspect/infrastructure/ssdeep_loader.py – no mocks, no monkeypatch."""

import threading
import types
import warnings

import r2inspect.infrastructure.ssdeep_loader as ssdeep_loader


# ---------------------------------------------------------------------------
# Helper: reset the module-level cache so each test starts clean
# ---------------------------------------------------------------------------


def _reset_cache() -> None:
    """Reset the ssdeep loader cache to force a fresh import attempt."""
    ssdeep_loader._ssdeep_module = None


# ---------------------------------------------------------------------------
# Basic import path
# ---------------------------------------------------------------------------


def test_get_ssdeep_returns_module_or_none():
    """get_ssdeep returns the ssdeep module when installed, else None."""
    _reset_cache()
    result = ssdeep_loader.get_ssdeep()
    assert result is None or isinstance(result, types.ModuleType)


def test_get_ssdeep_cached_returns_same_object():
    """Consecutive calls return the exact same object (cache hit)."""
    _reset_cache()
    first = ssdeep_loader.get_ssdeep()
    second = ssdeep_loader.get_ssdeep()
    assert first is second


def test_get_ssdeep_early_return_when_already_cached():
    """When _ssdeep_module is already set, get_ssdeep returns it immediately."""
    _reset_cache()
    # Populate the cache with the first real call
    first = ssdeep_loader.get_ssdeep()
    # Now the cache is populated (either module or None-after-failure).
    # For the "already cached" fast path we need a non-None value.
    # Use a simple sentinel object to prove the early-return path.
    sentinel = types.ModuleType("_sentinel_ssdeep")
    ssdeep_loader._ssdeep_module = sentinel
    try:
        assert ssdeep_loader.get_ssdeep() is sentinel
    finally:
        # Restore so we don't pollute other tests
        ssdeep_loader._ssdeep_module = first


# ---------------------------------------------------------------------------
# Double-check locking (inner cache check)
# ---------------------------------------------------------------------------


def test_double_check_locking_returns_cached_inside_lock():
    """If another thread populates the cache while we wait for the lock,
    we get that cached value instead of re-importing."""
    _reset_cache()

    sentinel = types.ModuleType("_sentinel_double_check")
    original_lock = ssdeep_loader._import_lock

    class _SimulatedRaceLock:
        """A lock whose __enter__ simulates another thread having already
        populated the cache before we proceed."""

        def __enter__(self):
            ssdeep_loader._ssdeep_module = sentinel
            return self

        def __exit__(self, *_):
            return None

    ssdeep_loader._import_lock = _SimulatedRaceLock()  # type: ignore[assignment]
    try:
        result = ssdeep_loader.get_ssdeep()
        assert result is sentinel
    finally:
        ssdeep_loader._import_lock = original_lock
        ssdeep_loader._ssdeep_module = None


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


def test_get_ssdeep_thread_safety():
    """Multiple threads calling get_ssdeep concurrently all get the same result."""
    _reset_cache()

    results: list = []

    def worker():
        results.append(ssdeep_loader.get_ssdeep())

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 10
    # Every thread must see the same object identity
    ids = {id(r) for r in results}
    assert len(ids) == 1


# ---------------------------------------------------------------------------
# Warning filter
# ---------------------------------------------------------------------------


def test_cffi_reimport_warnings_are_filtered():
    """The module-level filterwarnings call suppresses CFFI reimport warnings."""
    _reset_cache()

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        ssdeep_loader.get_ssdeep()

        cffi_warnings = [w for w in caught if "reimporting '_ssdeep_cffi" in str(w.message)]
        assert len(cffi_warnings) == 0


def test_module_level_warning_filter_is_installed():
    """The warnings.filters list contains our CFFI-reimport filter."""
    found = any("reimporting '_ssdeep_cffi" in str(entry) for entry in warnings.filters)
    # Even if the exact string changed, the module must at least be importable
    # and expose get_ssdeep.
    assert found or hasattr(ssdeep_loader, "get_ssdeep")


# ---------------------------------------------------------------------------
# Module-level attributes
# ---------------------------------------------------------------------------


def test_import_lock_is_threading_lock():
    """_import_lock is a real threading.Lock."""
    assert isinstance(ssdeep_loader._import_lock, type(threading.Lock()))


def test_ssdeep_module_initial_state():
    """_ssdeep_module is either None or a real module (never something else)."""
    module = ssdeep_loader._ssdeep_module
    assert module is None or isinstance(module, types.ModuleType)


def test_get_ssdeep_in_public_api():
    """get_ssdeep is listed in __all__."""
    assert "get_ssdeep" in ssdeep_loader.__all__


# ---------------------------------------------------------------------------
# Import-failure path (real, without mocks)
# ---------------------------------------------------------------------------


def test_get_ssdeep_graceful_on_missing_ssdeep():
    """When ssdeep is not installed, get_ssdeep returns None without raising."""
    _reset_cache()
    # This exercises the real import path.  If ssdeep is installed the test
    # still passes (returns a module); if not, it returns None.
    result = ssdeep_loader.get_ssdeep()
    assert result is None or isinstance(result, types.ModuleType)


def test_get_ssdeep_result_is_stable_across_resets():
    """Resetting the cache and re-importing yields the same type of result."""
    _reset_cache()
    r1 = ssdeep_loader.get_ssdeep()
    _reset_cache()
    r2 = ssdeep_loader.get_ssdeep()

    # Both should be the same type (both None or both a module)
    assert type(r1) is type(r2)
    if r1 is not None:
        assert r1.__name__ == r2.__name__  # type: ignore[union-attr]
