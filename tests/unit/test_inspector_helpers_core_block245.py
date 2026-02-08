from pathlib import Path

from r2inspect.core.inspector_helpers import InspectorExecutionMixin
from r2inspect.core.result_aggregator import ResultAggregator
from r2inspect.pipeline.analysis_pipeline import AnalysisPipeline, AnalysisStage
from r2inspect.pipeline.stages_format import FileInfoStage, FormatDetectionStage

FIXTURE = Path("samples/fixtures/hello_pe.exe")


class DummyAdapter:
    thread_safe = True

    def __init__(self, info=None):
        self._info = info or {
            "bin": {"format": "pe", "arch": "x86", "bits": 64, "endian": "little"}
        }

    def get_file_info(self):
        return self._info


class DummyAnalyzer:
    def __init__(self, **_kwargs):
        pass

    def analyze(self):
        return {"ok": True}

    def detect(self):
        return {"detect": True}


class DummyStringAnalyzer(DummyAnalyzer):
    def extract_strings(self):
        return ["s"]

    def search_xor(self, _value):
        return [{"xor": True}]


class DummyPEAnalyzer(DummyAnalyzer):
    def get_security_features(self):
        return {"aslr": True}


class DummyCompiler(DummyAnalyzer):
    def detect_compiler(self):
        return {"compiler": "gcc"}


class DummyRegistry:
    def __init__(self):
        self._map = {
            "pe_analyzer": DummyPEAnalyzer,
            "string_analyzer": DummyStringAnalyzer,
            "packer_detector": DummyAnalyzer,
            "crypto_analyzer": DummyAnalyzer,
            "anti_analysis": DummyAnalyzer,
            "compiler_detector": DummyCompiler,
            "yara_analyzer": DummyAnalyzer,
            "function_analyzer": DummyAnalyzer,
        }

    def get_analyzer_class(self, name):
        return self._map.get(name)


class DummyInspector(InspectorExecutionMixin):
    def __init__(self):
        self.adapter = DummyAdapter()
        self.config = object()
        self.filename = str(FIXTURE)
        self.registry = DummyRegistry()
        self._result_aggregator = ResultAggregator()


def test_inspector_helpers_execute_and_getters():
    inspector = DummyInspector()

    assert inspector._execute_analyzer("missing") == {}
    assert inspector._execute_dict("missing") == {}
    assert inspector._execute_list("missing") == []

    assert inspector.get_strings() == ["s"]
    assert inspector.search_xor("x")[0]["xor"] is True
    assert inspector.get_security_features()["aslr"] is True

    assert inspector.detect_packer()["detect"] is True
    assert inspector.detect_compiler()["compiler"] == "gcc"
    assert inspector.detect_crypto()["detect"] is True

    assert isinstance(inspector.get_file_info(), dict)
    assert inspector._detect_file_format() == "Unknown"

    indicators = inspector.generate_indicators({"imports": [{"name": "VirtualAlloc"}]})
    assert indicators

    assert inspector.analyze_ssdeep() == {}


def test_inspector_execution_wrappers():
    inspector = DummyInspector()

    pipeline = AnalysisPipeline()

    class Stage(AnalysisStage):
        def __init__(self):
            super().__init__(name="stage")

        def _execute(self, _context):
            return {"stage": {"ok": True}}

    pipeline.add_stage(Stage())

    def progress(_name, _idx, _total):
        pass

    results = inspector._execute_with_progress(pipeline, {}, progress)
    assert results["stage"]["ok"] is True

    results2 = inspector._execute_without_progress(pipeline, {}, parallel=False)
    assert results2["stage"]["ok"] is True
