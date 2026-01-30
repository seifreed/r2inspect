import time

import psutil
import pytest

from r2inspect.registry.default_registry import create_default_registry

pytestmark = pytest.mark.slow


def test_registry_creation_baseline():
    start = time.perf_counter()
    registry = create_default_registry()
    elapsed = time.perf_counter() - start
    assert registry is not None
    assert elapsed < 2.0


def test_lazy_loader_metrics():
    registry = create_default_registry()
    loader = registry._lazy_loader
    assert loader is not None
    stats = loader.get_stats()
    assert stats["registered"] > 0
    assert stats["loaded"] == 0


def test_memory_baseline():
    process = psutil.Process()
    memory_mb = process.memory_info().rss / 1024 / 1024
    assert memory_mb < 1500
