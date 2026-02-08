from r2inspect.utils.analyzer_factory import create_analyzer, run_analysis_method


class AnalyzerWithKw:
    def __init__(self, r2=None, config=None, filename=None):
        self.r2 = r2
        self.config = config
        self.filename = filename

    def analyze(self):
        return {"ok": True}


class AnalyzerWithArgs:
    def __init__(self, r2, config):
        self.r2 = r2
        self.config = config


class AnalyzerDefault:
    def __init__(self):
        self.value = "default"


class AnalyzerAlt:
    def run(self):
        return "ran"


def test_create_analyzer_kw_and_fallback():
    analyzer = create_analyzer(AnalyzerWithKw, r2="r2", config="cfg", filename="file")
    assert analyzer.r2 == "r2"
    assert analyzer.config == "cfg"
    assert analyzer.filename == "file"

    analyzer2 = create_analyzer(AnalyzerWithArgs, r2="r2", config="cfg")
    assert analyzer2.r2 == "r2"

    analyzer3 = create_analyzer(AnalyzerDefault)
    assert analyzer3.value == "default"


def test_run_analysis_method():
    analyzer = AnalyzerWithKw()
    assert run_analysis_method(analyzer, ["analyze", "run"]) == {"ok": True}

    analyzer2 = AnalyzerAlt()
    assert run_analysis_method(analyzer2, ["missing", "run"]) == "ran"

    analyzer3 = AnalyzerDefault()
    assert run_analysis_method(analyzer3, ["missing"]) == {
        "error": "No suitable analysis method found"
    }
