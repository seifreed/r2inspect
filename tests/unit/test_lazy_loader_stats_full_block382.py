from __future__ import annotations

from r2inspect.lazy_loader import LazyAnalyzerLoader
from r2inspect.lazy_loader_stats import build_stats, print_stats


def test_lazy_loader_stats_empty() -> None:
    loader = LazyAnalyzerLoader()
    stats = build_stats(loader)
    assert stats["registered"] == 0
    assert stats["loaded"] == 0
    assert stats["cache_hit_rate"] == 0.0
    assert stats["lazy_ratio"] == 0.0


def test_lazy_loader_stats_non_empty(tmp_path) -> None:
    loader = LazyAnalyzerLoader()

    module_path = "lazy_stats_mod"
    module_file = tmp_path / f"{module_path}.py"
    module_file.write_text(
        "class LazyStatsAnalyzer:\n" "    def __init__(self, *args, **kwargs):\n" "        pass\n"
    )

    import sys

    sys.path.insert(0, str(tmp_path))
    try:
        loader.register("demo", module_path, "LazyStatsAnalyzer")
        cls = loader.get_analyzer_class("demo")
        assert cls is not None
        stats = build_stats(loader)
        assert stats["registered"] == 1
        assert stats["loaded"] == 1
        assert stats["cache_hits"] >= 0
        print_stats(loader)
    finally:
        sys.path.remove(str(tmp_path))
