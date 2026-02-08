from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from r2inspect.core.inspector import R2Inspector
from r2inspect.core.inspector_helpers import InspectorExecutionMixin
from r2inspect.core.result_aggregator import ResultAggregator


class DummyMemoryMonitor:
    def __init__(self) -> None:
        self.gc_called = False
        self.memory_mb = 10.0

    def check_memory(self, force: bool = False) -> dict[str, Any]:
        return {
            "process_memory_mb": self.memory_mb,
            "peak_memory_mb": self.memory_mb,
            "gc_count": 0,
        }

    def is_memory_available(self, _estimated: float) -> bool:
        return True

    def _trigger_gc(self, aggressive: bool = False) -> None:
        self.gc_called = True


class DummyFileValidator:
    def __init__(self, _filename: str, valid: bool = True) -> None:
        self._valid = valid

    def validate(self) -> bool:
        return self._valid


class DummyAdapter:
    thread_safe = True

    def __init__(self, info: dict[str, Any] | None = None) -> None:
        self._info = info or {}

    def get_file_info(self) -> dict[str, Any]:
        return self._info


class DummyPipeline:
    def __init__(self, result: dict[str, Any] | None = None, raise_error: Exception | None = None):
        self.result = result or {"ok": True}
        self.raise_error = raise_error
        self.called: list[Any] = []

    def execute_with_progress(self, _callback, _options: dict[str, Any]) -> dict[str, Any]:
        self.called.append("progress")
        if self.raise_error:
            raise self.raise_error
        return dict(self.result)

    def execute(self, _options: dict[str, Any], parallel: bool = False) -> dict[str, Any]:
        self.called.append(("execute", parallel))
        if self.raise_error:
            raise self.raise_error
        return dict(self.result)


class DummyPipelineBuilder:
    def __init__(self, pipeline: DummyPipeline) -> None:
        self.pipeline = pipeline

    def build(self, _options: dict[str, Any]) -> DummyPipeline:
        return self.pipeline


class DummyRegistry:
    def __init__(self, mapping: dict[str, type] | None = None) -> None:
        self._mapping = mapping or {}

    def get_analyzer_class(self, name: str) -> type | None:
        return self._mapping.get(name)

    def list_analyzers(self) -> list[dict[str, Any]]:
        return [{"name": "dummy", "category": "metadata", "file_formats": []}]

    def __len__(self) -> int:
        return len(self._mapping)


class DummyConfig:
    class _Pipeline:
        def __init__(self, parallel: bool) -> None:
            self.parallel_execution = parallel

    class _Typed:
        def __init__(self, parallel: bool) -> None:
            self.pipeline = DummyConfig._Pipeline(parallel)

    def __init__(self, parallel: bool) -> None:
        self.typed_config = DummyConfig._Typed(parallel)


class DummyAnalyzer:
    def __init__(self, *args, **kwargs) -> None:
        self.args = args
        self.kwargs = kwargs

    def analyze(self, *args, **kwargs) -> dict[str, Any]:
        return {"args": args, "kwargs": kwargs}

    def detect(self) -> dict[str, Any]:
        return {"detected": True}

    def get_security_features(self) -> dict[str, bool]:
        return {"aslr": True}

    def extract_strings(self) -> list[str]:
        return ["one", "two"]

    def search_xor(self, _value: str) -> list[dict[str, Any]]:
        return [{"value": "xor"}]


class ExplodingAnalyzer:
    def __init__(self, *args, **kwargs) -> None:
        raise RuntimeError("boom")


class DummyInspector(InspectorExecutionMixin):
    def __init__(self, filename: str, registry: DummyRegistry, adapter: DummyAdapter):
        self.filename = filename
        self.registry = registry
        self.adapter = adapter
        self.config = DummyConfig(parallel=False)
        self._result_aggregator = ResultAggregator()


def test_inspector_helpers_execute_paths(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abcd")
    registry = DummyRegistry(
        {
            "pe_analyzer": DummyAnalyzer,
            "string_analyzer": DummyAnalyzer,
            "elf_analyzer": DummyAnalyzer,
            "macho_analyzer": DummyAnalyzer,
            "import_analyzer": DummyAnalyzer,
            "export_analyzer": DummyAnalyzer,
            "section_analyzer": DummyAnalyzer,
            "packer_detector": DummyAnalyzer,
            "anti_analysis": DummyAnalyzer,
            "compiler_detector": DummyAnalyzer,
            "yara_analyzer": DummyAnalyzer,
            "function_analyzer": DummyAnalyzer,
            "ssdeep": DummyAnalyzer,
            "tlsh": DummyAnalyzer,
            "telfhash": DummyAnalyzer,
            "rich_header": DummyAnalyzer,
            "impfuzzy": DummyAnalyzer,
            "ccbhash": DummyAnalyzer,
            "binlex": DummyAnalyzer,
            "binbloom": DummyAnalyzer,
            "simhash": DummyAnalyzer,
            "bindiff": DummyAnalyzer,
        }
    )
    adapter = DummyAdapter({"bin": {"arch": "x86", "bits": 64, "endian": "little"}})
    inspector = DummyInspector(str(sample), registry, adapter)

    assert inspector._as_dict({"a": 1}) == {"a": 1}
    assert inspector._as_dict("x") == {}
    assert inspector._as_bool_dict({"a": 1, "b": 0}) == {"a": True, "b": False}
    assert inspector._as_bool_dict("nope") == {}
    assert inspector._as_str("ok", "default") == "ok"
    assert inspector._as_str(123, "default") == "default"

    assert inspector._execute_analyzer("missing") == {}
    assert inspector._execute_analyzer("pe_analyzer", "detect") == {"detected": True}
    assert inspector._execute_analyzer("pe_analyzer", "analyze", 1) == {"args": (1,), "kwargs": {}}
    assert inspector._execute_analyzer("pe_analyzer", "missing_method") == {}
    assert inspector._execute_analyzer("pe_analyzer", "analyze", 1, flag=True)["kwargs"]["flag"]

    assert inspector.get_strings() == ["one", "two"]
    assert inspector.search_xor("a") == [{"value": "xor"}]
    assert inspector.get_security_features()["aslr"] is True
    assert isinstance(inspector.get_pe_info(), dict)
    assert isinstance(inspector.get_elf_info(), dict)
    assert isinstance(inspector.get_macho_info(), dict)
    assert inspector.get_imports() == []
    assert inspector.get_exports() == []
    assert inspector.get_sections() == []
    assert inspector.detect_packer() == {"detected": True}
    assert inspector.detect_anti_analysis() == {"detected": True}
    assert inspector.detect_compiler() == {}
    assert inspector.run_yara_rules() == []
    assert isinstance(inspector.analyze_functions(), dict)
    assert isinstance(inspector.analyze_ssdeep(), dict)
    assert isinstance(inspector.analyze_tlsh(), dict)
    assert isinstance(inspector.analyze_telfhash(), dict)
    assert isinstance(inspector.analyze_rich_header(), dict)
    assert isinstance(inspector.analyze_impfuzzy(), dict)
    assert isinstance(inspector.analyze_ccbhash(), dict)
    assert isinstance(inspector.analyze_binlex(), dict)
    assert isinstance(inspector.analyze_binbloom(), dict)
    assert isinstance(inspector.analyze_simhash(), dict)
    assert isinstance(inspector.analyze_bindiff(), dict)
    assert inspector.generate_indicators({}) == []

    file_info = inspector.get_file_info()
    assert file_info["architecture"] == "x86-64"

    fmt = inspector._detect_file_format()
    assert isinstance(fmt, str)

    crypto = inspector.detect_crypto()
    assert crypto["error"] == "Analyzer not found"

    registry._mapping["crypto_analyzer"] = DummyAnalyzer
    assert inspector.detect_crypto()["detected"] is True

    registry._mapping["bad_analyzer"] = ExplodingAnalyzer
    assert inspector._execute_analyzer("bad_analyzer") == {}

    summary = inspector.generate_executive_summary({})
    assert isinstance(summary, dict)


def test_inspector_analyze_variants(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abcd")

    memory = DummyMemoryMonitor()
    adapter = DummyAdapter()
    registry = DummyRegistry()

    def registry_factory() -> DummyRegistry:
        return registry

    pipeline = DummyPipeline(result={"ok": True})
    builder = DummyPipelineBuilder(pipeline)

    def pipeline_builder_factory(_adapter, _registry, _config, _filename):
        return builder

    inspector = R2Inspector(
        filename=str(sample),
        config=DummyConfig(parallel=False),
        adapter=adapter,
        registry_factory=registry_factory,
        pipeline_builder_factory=pipeline_builder_factory,
        config_factory=lambda: DummyConfig(parallel=False),
        file_validator_factory=lambda _f: DummyFileValidator(_f, valid=True),
        result_aggregator_factory=ResultAggregator,
        memory_monitor=memory,
        verbose=True,
    )

    result = inspector.analyze(progress_callback=lambda _s: None)
    assert result["memory_stats"]["initial_memory_mb"] == memory.memory_mb
    assert "progress" in pipeline.called

    adapter.thread_safe = False
    pipeline.called.clear()
    result = inspector.analyze()
    assert ("execute", False) in pipeline.called

    inspector._pipeline_builder = None
    result = inspector.analyze()
    assert result["error"] == "Pipeline builder is not initialized"
    inspector._pipeline_builder = builder

    failing_pipeline = DummyPipeline(raise_error=MemoryError("oom"))
    builder.pipeline = failing_pipeline
    result = inspector.analyze()
    assert result["error"] == "Memory limit exceeded"
    assert memory.gc_called is True

    failing_pipeline = DummyPipeline(raise_error=ValueError("boom"))
    builder.pipeline = failing_pipeline
    result = inspector.analyze()
    assert result["error"] == "boom"

    inspector.close()


def test_inspector_init_errors(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abcd")

    with pytest.raises(ValueError):
        R2Inspector(filename=str(sample), config=DummyConfig(False), adapter=DummyAdapter())

    with pytest.raises(ValueError):
        R2Inspector(
            filename=str(sample),
            config=None,
            adapter=DummyAdapter(),
            registry_factory=lambda: DummyRegistry(),
            pipeline_builder_factory=lambda *args: DummyPipelineBuilder(DummyPipeline()),
            config_factory=None,
            file_validator_factory=lambda _f: DummyFileValidator(_f, valid=True),
            result_aggregator_factory=ResultAggregator,
            memory_monitor=DummyMemoryMonitor(),
        )

    with pytest.raises(ValueError):
        R2Inspector(
            filename=str(sample),
            config=DummyConfig(False),
            adapter=None,
            registry_factory=lambda: DummyRegistry(),
            pipeline_builder_factory=lambda *args: DummyPipelineBuilder(DummyPipeline()),
            config_factory=lambda: DummyConfig(False),
            file_validator_factory=lambda _f: DummyFileValidator(_f, valid=True),
            result_aggregator_factory=ResultAggregator,
            memory_monitor=DummyMemoryMonitor(),
        )

    with pytest.raises(ValueError):
        R2Inspector(
            filename=str(sample),
            config=DummyConfig(False),
            adapter=DummyAdapter(),
            registry_factory=lambda: DummyRegistry(),
            pipeline_builder_factory=lambda *args: DummyPipelineBuilder(DummyPipeline()),
            config_factory=lambda: DummyConfig(False),
            file_validator_factory=None,
            result_aggregator_factory=None,
            memory_monitor=DummyMemoryMonitor(),
        )

    with pytest.raises(ValueError):
        R2Inspector(
            filename=str(sample),
            config=DummyConfig(False),
            adapter=DummyAdapter(),
            registry_factory=None,
            pipeline_builder_factory=lambda *args: DummyPipelineBuilder(DummyPipeline()),
            config_factory=lambda: DummyConfig(False),
            file_validator_factory=lambda _f: DummyFileValidator(_f, valid=False),
            result_aggregator_factory=ResultAggregator,
            memory_monitor=DummyMemoryMonitor(),
        )

    with pytest.raises(ValueError):
        R2Inspector(
            filename=str(sample),
            config=DummyConfig(False),
            adapter=DummyAdapter(),
            registry_factory=None,
            pipeline_builder_factory=None,
            config_factory=lambda: DummyConfig(False),
            file_validator_factory=lambda _f: DummyFileValidator(_f, valid=True),
            result_aggregator_factory=ResultAggregator,
            memory_monitor=DummyMemoryMonitor(),
        )

    inspector = R2Inspector(
        filename=str(sample),
        config=None,
        adapter=DummyAdapter(),
        registry_factory=lambda: DummyRegistry(),
        pipeline_builder_factory=lambda *args: DummyPipelineBuilder(DummyPipeline()),
        config_factory=lambda: DummyConfig(False),
        file_validator_factory=lambda _f: DummyFileValidator(_f, valid=True),
        result_aggregator_factory=ResultAggregator,
        memory_monitor=DummyMemoryMonitor(),
    )
    inspector._registry_factory = None
    inspector._pipeline_builder_factory = None
    with pytest.raises(ValueError):
        inspector._init_infrastructure()
