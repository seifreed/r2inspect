import time
from pathlib import Path

import pytest

from r2inspect.core.file_validator import FileValidator
from r2inspect.core.pipeline_builder import PipelineBuilder
from r2inspect.core.result_aggregator import ResultAggregator
from r2inspect.pipeline.analysis_pipeline import AnalysisPipeline, AnalysisStage, ThreadSafeContext
from r2inspect.pipeline.stages_common import AnalyzerStage, IndicatorStage
from r2inspect.pipeline.stages_detection import DetectionStage
from r2inspect.pipeline.stages_format import (
    FileInfoStage,
    FormatAnalysisStage,
    FormatDetectionStage,
)
from r2inspect.pipeline.stages_hashing import HashingStage
from r2inspect.pipeline.stages_metadata import MetadataStage
from r2inspect.pipeline.stages_security import SecurityStage
from r2inspect.registry.analyzer_registry import AnalyzerCategory, AnalyzerRegistry

FIXTURE = Path("samples/fixtures/hello_pe.exe")


class DummyConfig:
    def __init__(self) -> None:
        self.typed_config = type("Cfg", (), {})()
        self.typed_config.pipeline = type("Pipe", (), {})()
        self.typed_config.pipeline.max_workers = 2
        self.typed_config.pipeline.stage_timeout = None
        self.typed_config.pipeline.parallel_execution = False


class DummyAdapter:
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


class DummySectionAnalyzer(DummyAnalyzer):
    def analyze_sections(self):
        return [{"name": ".text"}]


class DummyImportAnalyzer(DummyAnalyzer):
    def get_imports(self):
        return [{"name": "VirtualAlloc"}]


class DummyExportAnalyzer(DummyAnalyzer):
    def get_exports(self):
        return [{"name": "main"}]


class DummyStringAnalyzer(DummyAnalyzer):
    def extract_strings(self):
        return ["str"]

    def search_xor(self, _value):
        return [{"match": "xor"}]


class DummyFunctionAnalyzer(DummyAnalyzer):
    def analyze_functions(self):
        return {"count": 1}


class DummyPackerDetector(DummyAnalyzer):
    def detect(self):
        return {"is_packed": True, "packer_type": "UPX"}


class DummyCryptoAnalyzer(DummyAnalyzer):
    def detect(self):
        return {"algorithms": ["AES"], "constants": []}


class DummyAntiAnalysis(DummyAnalyzer):
    def detect(self):
        return {"anti_debug": True}


class DummyCompilerDetector(DummyAnalyzer):
    def detect_compiler(self):
        return {"compiler": "clang"}


class DummyYaraAnalyzer(DummyAnalyzer):
    def scan(self, _rules=None):
        return [{"rule": "TestRule"}]


class DummyPEAnalyzer(DummyAnalyzer):
    def analyze(self):
        return {"format": "PE"}

    def get_security_features(self):
        return {"aslr": True}


class DummyMitigationAnalyzer(DummyAnalyzer):
    def analyze(self):
        return {"mitigations": {"aslr": True}}


class DummyHashAnalyzer(DummyAnalyzer):
    def analyze(self):
        return {"hash": "abc"}


class DummyTLSHAnalyzer(DummyAnalyzer):
    def analyze_sections(self):
        return {"tlsh": "x"}


class DummyCCBAnalyzer(DummyAnalyzer):
    def analyze_functions(self):
        return {"ccb": "y"}


class DummySimhashAnalyzer(DummyAnalyzer):
    def analyze_detailed(self):
        return {"simhash": "z"}


class SimpleStage(AnalysisStage):
    def __init__(self, name, result):
        super().__init__(name=name)
        self._result = result

    def _execute(self, context):
        return {self.name: self._result}


class FailingStage(AnalysisStage):
    def __init__(self, name):
        super().__init__(name=name)

    def _execute(self, _context):
        raise RuntimeError("boom")


class SlowStage(AnalysisStage):
    def __init__(self, name, delay):
        super().__init__(name=name)
        self.delay = delay

    def _execute(self, _context):
        time.sleep(self.delay)
        return {self.name: {"ok": True}}


def test_thread_safe_context_and_pipeline_basics():
    ctx = ThreadSafeContext({"a": 1})
    ctx.update({"b": 2})
    assert ctx.get("a") == 1
    assert ctx.get("missing", 3) == 3
    ctx.set("c", 4)
    assert ctx.get_all()["c"] == 4

    pipeline = AnalysisPipeline(max_workers=1)
    pipeline.add_stage(SimpleStage("one", {"v": 1}))
    pipeline.add_stage(SimpleStage("two", {"v": 2}))
    assert pipeline.get_stage("one") is not None
    assert pipeline.list_stages() == ["one", "two"]
    assert len(pipeline) == 2

    assert pipeline.remove_stage("two") is True
    assert pipeline.remove_stage("missing") is False

    pipeline.clear()
    assert len(pipeline) == 0
    assert "AnalysisPipeline" in repr(pipeline)


def test_pipeline_sequential_and_progress():
    pipeline = AnalysisPipeline()
    pipeline.add_stage(SimpleStage("one", {"v": 1}))
    pipeline.add_stage(FailingStage("fail"))

    progress = []

    def cb(name, idx, total):
        progress.append((name, idx, total))

    pipeline.set_progress_callback(cb)
    results = pipeline.execute(parallel=False)
    assert "one" in results
    assert results["fail"]["success"] is False
    assert progress

    progress2 = []

    def cb2(name, idx, total):
        progress2.append(name)

    results2 = pipeline.execute_with_progress(cb2)
    assert "one" in results2
    assert progress2[0] == "one"


def test_pipeline_parallel_timeout_and_skip():
    pipeline = AnalysisPipeline(max_workers=2)
    slow = SlowStage("slow", delay=0.05)
    slow.timeout = 0.01
    pipeline.add_stage(slow)
    pipeline.add_stage(SimpleStage("fast", {"v": 1}))

    results = pipeline.execute(parallel=True)
    assert results["slow"]["success"] is False
    assert results["fast"]["v"] == 1

    pipeline2 = AnalysisPipeline()

    class ConditionalStage(SimpleStage):
        def __init__(self):
            super().__init__("cond", {"ok": True})
            self.condition = lambda _ctx: False

    pipeline2.add_stage(ConditionalStage())
    assert pipeline2.execute(parallel=True) == {}

    pipeline3 = AnalysisPipeline()
    pipeline3.add_stage(SimpleStage("a", {"ok": True}))
    bad = SimpleStage("b", {"ok": True})
    bad.dependencies = ["missing"]
    pipeline3.add_stage(bad)
    results3 = pipeline3.execute(parallel=True)
    assert results3["a"]["ok"] is True
    assert "b" not in results3

    pipeline4 = AnalysisPipeline()
    only = SimpleStage("only", {"ok": True})
    only.dependencies = ["missing"]
    pipeline4.add_stage(only)
    with pytest.raises(RuntimeError):
        pipeline4.execute(parallel=True)


def test_pipeline_builder_and_stages(tmp_path):
    dummy_cfg = DummyConfig()
    dummy_adapter = DummyAdapter()
    registry = AnalyzerRegistry(lazy_loading=False)

    builder = PipelineBuilder(dummy_adapter, registry, dummy_cfg, str(FIXTURE))
    pipeline = builder.build({})
    assert len(pipeline) == 8
    for stage in pipeline.stages:
        assert stage.timeout == dummy_cfg.typed_config.pipeline.stage_timeout

    info_stage = FileInfoStage(dummy_adapter, str(FIXTURE))
    context = {"results": {}, "metadata": {}}
    result = info_stage.execute(context)
    assert result["file_info"]["name"] == FIXTURE.name
    assert result["file_info"]["architecture"] == "x86-64"

    detect_stage = FormatDetectionStage(dummy_adapter, str(FIXTURE))
    context = {"results": {}, "metadata": {}}
    detected = detect_stage.execute(context)
    assert detected["format_detection"]["file_format"] == "PE"

    registry.register(
        name="pe_analyzer", analyzer_class=DummyPEAnalyzer, category=AnalyzerCategory.FORMAT
    )
    registry.register(
        name="elf_analyzer", analyzer_class=DummyPEAnalyzer, category=AnalyzerCategory.FORMAT
    )
    registry.register(
        name="macho_analyzer", analyzer_class=DummyPEAnalyzer, category=AnalyzerCategory.FORMAT
    )

    fa = FormatAnalysisStage(registry, dummy_adapter, dummy_cfg, str(FIXTURE))
    for fmt, key in [("PE", "pe_info"), ("ELF", "elf_info"), ("Mach-O", "macho_info")]:
        ctx = {"results": {}, "metadata": {"file_format": fmt}}
        res = fa.execute(ctx)
        assert key in res


def test_metadata_security_hashing_detection_and_indicators():
    dummy_cfg = DummyConfig()
    dummy_adapter = DummyAdapter()
    registry = AnalyzerRegistry(lazy_loading=False)

    registry.register("section_analyzer", DummySectionAnalyzer, AnalyzerCategory.METADATA)
    registry.register("import_analyzer", DummyImportAnalyzer, AnalyzerCategory.METADATA)
    registry.register("export_analyzer", DummyExportAnalyzer, AnalyzerCategory.METADATA)
    registry.register("string_analyzer", DummyStringAnalyzer, AnalyzerCategory.METADATA)
    registry.register("function_analyzer", DummyFunctionAnalyzer, AnalyzerCategory.METADATA)

    registry.register("pe_analyzer", DummyPEAnalyzer, AnalyzerCategory.FORMAT)
    registry.register("exploit_mitigation", DummyMitigationAnalyzer, AnalyzerCategory.SECURITY)

    registry.register("ssdeep", DummyHashAnalyzer, AnalyzerCategory.HASHING, file_formats={"PE"})
    registry.register("tlsh", DummyTLSHAnalyzer, AnalyzerCategory.HASHING, file_formats={"PE"})
    registry.register("ccbhash", DummyCCBAnalyzer, AnalyzerCategory.HASHING, file_formats={"PE"})
    registry.register(
        "simhash", DummySimhashAnalyzer, AnalyzerCategory.HASHING, file_formats={"PE"}
    )

    registry.register("packer_detector", DummyPackerDetector, AnalyzerCategory.DETECTION)
    registry.register("crypto_analyzer", DummyCryptoAnalyzer, AnalyzerCategory.DETECTION)
    registry.register("anti_analysis", DummyAntiAnalysis, AnalyzerCategory.DETECTION)
    registry.register("compiler_detector", DummyCompilerDetector, AnalyzerCategory.DETECTION)
    registry.register("yara_analyzer", DummyYaraAnalyzer, AnalyzerCategory.DETECTION)

    ctx = {"results": {}, "metadata": {"file_format": "PE"}}

    metadata = MetadataStage(
        registry, dummy_adapter, dummy_cfg, str(FIXTURE), {"analyze_functions": True}
    )
    res_meta = metadata.execute(ctx)
    assert "sections" in res_meta
    assert "imports" in res_meta

    security = SecurityStage(registry, dummy_adapter, dummy_cfg, str(FIXTURE))
    res_sec = security.execute(ctx)
    assert "security" in res_sec
    assert ctx["results"]["security"]["aslr"] is True

    hashing = HashingStage(registry, dummy_adapter, dummy_cfg, str(FIXTURE))
    res_hash = hashing.execute(ctx)
    assert "ssdeep" in res_hash
    assert "simhash" in res_hash

    detection = DetectionStage(
        registry,
        dummy_adapter,
        dummy_cfg,
        str(FIXTURE),
        {"detect_packer": True, "detect_crypto": True},
    )
    res_det = detection.execute(ctx)
    assert "packer" in res_det
    assert "yara_matches" in res_det

    indicator = IndicatorStage()
    ctx["results"]["imports"] = [{"name": "VirtualAlloc"}]
    ctx["results"]["yara_matches"] = [{"rule": "Rule"}]
    res_ind = indicator.execute(ctx)
    assert "indicators" in res_ind

    aggregator = ResultAggregator()
    indicators = aggregator.generate_indicators(ctx["results"])
    assert indicators
    summary = aggregator.generate_executive_summary(ctx["results"])
    assert "file_overview" in summary


def test_file_validator(tmp_path):
    valid_file = tmp_path / "valid.bin"
    valid_file.write_bytes(b"A" * 64)
    validator = FileValidator(valid_file)
    assert validator.validate() is True

    empty_file = tmp_path / "empty.bin"
    empty_file.write_bytes(b"")
    assert FileValidator(empty_file).validate() is False

    small_file = tmp_path / "small.bin"
    small_file.write_bytes(b"A" * 2)
    assert FileValidator(small_file).validate() is False
