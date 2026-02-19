from __future__ import annotations

from r2inspect.error_handling.stats import (
    get_circuit_breaker_stats,
    get_error_stats,
    get_error_stats_snapshot,
    get_retry_stats,
    reset_error_stats,
)


def test_get_error_stats_snapshot():
    """Test consolidated error statistics snapshot"""
    snapshot = get_error_stats_snapshot()
    assert "error_stats" in snapshot
    assert "retry_stats" in snapshot
    assert "circuit_breaker_stats" in snapshot
    assert isinstance(snapshot, dict)
    assert isinstance(snapshot["error_stats"], dict)
    assert isinstance(snapshot["retry_stats"], dict)
    assert isinstance(snapshot["circuit_breaker_stats"], dict)


def test_stats_module_exports():
    """Test all exported stats functions are callable"""
    assert callable(get_error_stats)
    assert callable(get_retry_stats)
    assert callable(get_circuit_breaker_stats)
    assert callable(reset_error_stats)
    assert callable(get_error_stats_snapshot)


def test_stats_snapshot_after_reset():
    """Test snapshot returns valid data after reset"""
    reset_error_stats()
    snapshot = get_error_stats_snapshot()
    assert "error_stats" in snapshot
    assert isinstance(snapshot["error_stats"], dict)


def test_individual_stats_functions():
    """Test individual stats functions return expected structure"""
    error_stats = get_error_stats()
    retry_stats = get_retry_stats()
    cb_stats = get_circuit_breaker_stats()
    
    assert isinstance(error_stats, dict)
    assert isinstance(retry_stats, dict)
    assert isinstance(cb_stats, dict)
