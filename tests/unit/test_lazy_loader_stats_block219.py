from __future__ import annotations

from r2inspect.lazy_loader import LazyAnalyzerLoader
from r2inspect.lazy_loader_stats import build_stats, print_stats


def test_lazy_loader_stats_and_print(capsys) -> None:
    loader = LazyAnalyzerLoader()
    loader.register("base", "r2inspect.schemas.base", "AnalysisResultBase")
    stats = build_stats(loader)
    assert stats["registered"] == 1
    assert stats["loaded"] == 0
    loader.get_analyzer_class("base")
    stats = build_stats(loader)
    assert stats["loaded"] == 1
    print_stats(loader)
    out = capsys.readouterr().out
    assert "Lazy Loader Statistics" in out
