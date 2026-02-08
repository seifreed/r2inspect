from __future__ import annotations

from r2inspect.utils.analyzer_factory import create_analyzer, run_analysis_method


class _AnalyzerA:
    def __init__(self, adapter, config, filename):
        self.args = (adapter, config, filename)

    def analyze(self):
        return {"ok": True}


class _AnalyzerB:
    def __init__(self, filename):
        self.filename = filename


class _AnalyzerC:
    def __init__(self, adapter, config):
        self.args = (adapter, config)


class _AnalyzerD:
    def __init__(self):
        self.called = True


class _AnalyzerE:
    def __init__(self, backend):
        self.backend = backend


class _AnalyzerKwFail:
    def __init__(self, adapter, config, filename, /):
        self.args = (adapter, config, filename)


def test_create_analyzer_signatures() -> None:
    adapter = object()
    config = object()

    analyzer = create_analyzer(_AnalyzerA, adapter=adapter, config=config, filename="a.bin")
    assert analyzer.args == (adapter, config, "a.bin")

    analyzer = create_analyzer(_AnalyzerB, filename="b.bin")
    assert analyzer.filename == "b.bin"

    analyzer = create_analyzer(_AnalyzerC, adapter=adapter, config=config)
    assert analyzer.args == (adapter, config)

    analyzer = create_analyzer(_AnalyzerD)
    assert analyzer.called is True

    analyzer = create_analyzer(_AnalyzerE, adapter=adapter)
    assert analyzer.backend is adapter

    analyzer = create_analyzer(_AnalyzerKwFail, adapter=adapter, config=config, filename="c.bin")
    assert analyzer.args == (adapter, config, "c.bin")


def test_run_analysis_method() -> None:
    analyzer = _AnalyzerA(adapter=None, config=None, filename=None)
    result = run_analysis_method(analyzer, ["missing", "analyze"])
    assert result == {"ok": True}

    result = run_analysis_method(analyzer, ["missing"])
    assert result["error"].startswith("No suitable")
