from __future__ import annotations

from r2inspect.utils.rate_limiter import cleanup_memory


def test_cleanup_memory_returns_metrics_or_none():
    info = cleanup_memory()
    assert info is None or {"rss_mb", "vms_mb"}.issubset(info.keys())
