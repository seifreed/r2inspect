from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.config import Config
from r2inspect.core.r2_session import R2Session
from r2inspect.lazy_loader import LazyAnalyzerLoader
from r2inspect.lazy_loader_stats import build_stats, print_stats
from r2inspect.modules.pe_analyzer import PEAnalyzer
from r2inspect.pipeline.stages_common import AnalyzerStage, IndicatorStage
from r2inspect.utils.analyzer_factory import create_analyzer, run_analysis_method


@pytest.fixture
def r2_adapter(samples_dir: Path) -> R2PipeAdapter:
    target = samples_dir / "hello_pe.exe"
    session = R2Session(str(target))
    r2 = session.open(file_size_mb=target.stat().st_size / (1024 * 1024))
    adapter = R2PipeAdapter(r2)
    yield adapter
    session.close()


@pytest.mark.requires_r2
def test_analyzer_stage_success(r2_adapter: R2PipeAdapter, samples_dir: Path) -> None:
    ctx = {"results": {}}
    stage = AnalyzerStage(
        name="pe",
        analyzer_class=PEAnalyzer,
        adapter=r2_adapter,
        config=Config(),
        filename=str(samples_dir / "hello_pe.exe"),
    )
    result = stage._execute(ctx)
    assert "pe" in result["results"]


def test_analyzer_stage_error_path(samples_dir: Path) -> None:
    ctx = {"results": {}}
    stage = AnalyzerStage(
        name="pe",
        analyzer_class=PEAnalyzer,
        adapter=None,  # type: ignore[arg-type]
        config=Config(),
        filename=str(samples_dir / "hello_pe.exe"),
    )
    result = stage._execute(ctx)
    assert "error" in result["results"]["pe"]


def test_indicator_stage_generation() -> None:
    ctx = {
        "results": {
            "detection": {
                "suspicious_indicators": [
                    {"type": "Test", "description": "Hit", "severity": "High"}
                ]
            }
        }
    }
    stage = IndicatorStage()
    result = stage._execute(ctx)
    assert "indicators" in result


def test_lazy_loader_stats_output(capsys: pytest.CaptureFixture[str]) -> None:
    loader = LazyAnalyzerLoader()
    loader.register(
        name="pe",
        module_path="r2inspect.modules.pe_analyzer",
        class_name="PEAnalyzer",
        category="format",
    )
    loader.register(
        name="elf",
        module_path="r2inspect.modules.elf_analyzer",
        class_name="ELFAnalyzer",
        category="format",
    )
    assert loader.get_analyzer_class("pe") is not None
    stats = build_stats(loader)
    assert stats["registered"] == 2
    print_stats(loader)
    captured = capsys.readouterr().out
    assert "Lazy Loader Statistics" in captured


class AnalyzerWithSignature:
    def __init__(self, adapter, config=None, filename=None) -> None:
        self.adapter = adapter
        self.config = config
        self.filename = filename

    def analyze(self):
        return {"ok": True}


class AnalyzerWithFallback:
    def __init__(self, backend, filename) -> None:
        self.backend = backend
        self.filename = filename

    def scan(self):
        return {"scan": True}


class AnalyzerNoArgs:
    def analyze(self):
        return {"empty": True}


def test_analyzer_factory_paths() -> None:
    analyzer = create_analyzer(
        AnalyzerWithSignature, adapter="adapter", config=Config(), filename="x"
    )
    assert isinstance(analyzer, AnalyzerWithSignature)

    analyzer2 = create_analyzer(AnalyzerWithFallback, adapter="backend", filename="x")
    assert isinstance(analyzer2, AnalyzerWithFallback)

    analyzer3 = create_analyzer(AnalyzerNoArgs)
    assert isinstance(analyzer3, AnalyzerNoArgs)

    assert run_analysis_method(analyzer3, ("detect", "analyze")) == {"empty": True}
    assert run_analysis_method(analyzer3, ("detect",)) == {
        "error": "No suitable analysis method found"
    }
