"""Canonical import tests for analyzer factory helpers."""

from r2inspect.core.analyzer_factory import create_analyzer, run_analysis_method


class _Analyzer:
    def __init__(self, adapter=None, config=None, filename=None):
        self.adapter = adapter
        self.config = config
        self.filename = filename

    def analyze(self):
        return {"ok": True}


def test_core_analyzer_factory_exports_work() -> None:
    analyzer = create_analyzer(_Analyzer, adapter="backend", config="cfg", filename="file.bin")
    assert analyzer.adapter == "backend"
    assert analyzer.config == "cfg"
    assert analyzer.filename == "file.bin"
    assert run_analysis_method(analyzer, ("analyze",)) == {"ok": True}
