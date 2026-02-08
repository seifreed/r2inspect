from __future__ import annotations

import os
import struct
import time
from pathlib import Path

import pytest

from r2inspect.config import Config
from r2inspect.core import file_validator as file_validator_module
from r2inspect.core import r2_session as r2_session_module
from r2inspect.core.file_validator import FileValidator
from r2inspect.core.inspector import R2Inspector
from r2inspect.core.inspector_helpers import InspectorExecutionMixin
from r2inspect.core.pipeline_builder import PipelineBuilder
from r2inspect.core.r2_session import R2Session
from r2inspect.core.result_aggregator import (
    ResultAggregator,
    _build_file_overview,
    _build_security_assessment,
    _build_technical_details,
    _build_threat_indicators,
    _generate_recommendations,
    _normalize_results,
)
from r2inspect.utils import memory_manager as memory_manager_module


class _DummyPipeline:
    def __init__(self, result: dict[str, object]) -> None:
        self.result = result
        self.calls: list[tuple[str, object]] = []

    def execute(self, _options: dict[str, object], parallel: bool = False) -> dict[str, object]:
        self.calls.append(("execute", parallel))
        return dict(self.result)

    def execute_with_progress(
        self, _callback: object, _options: dict[str, object]
    ) -> dict[str, object]:
        self.calls.append(("progress", None))
        return dict(self.result)


class _DummyPipelineBuilder:
    def __init__(self, pipeline: _DummyPipeline) -> None:
        self.pipeline = pipeline

    def build(self, _options: dict[str, object]) -> _DummyPipeline:
        return self.pipeline


class _DummyRegistry:
    def __len__(self) -> int:
        return 0

    def list_analyzers(self) -> list[dict[str, object]]:
        return [{"name": "x", "category": "c", "file_formats": ["PE"]}]

    def get_analyzer_class(self, _name: str) -> object | None:
        return _DummyAnalyzer


class _DummyAnalyzer:
    def __init__(self, *_args: object, **_kwargs: object) -> None:
        pass

    def analyze(self, *_args: object, **_kwargs: object) -> dict[str, object]:
        return {"analyzed": True}

    def detect(self, *_args: object, **_kwargs: object) -> dict[str, object]:
        return {"detected": True}

    def scan(self, *_args: object, **_kwargs: object) -> list[dict[str, object]]:
        return [{"rule": "r1"}]

    def extract_strings(self) -> list[str]:
        return ["a", "b"]

    def get_security_features(self) -> dict[str, bool]:
        return {"aslr": True, "dep": False}

    def get_imports(self) -> list[dict[str, object]]:
        return [{"name": "imp"}]

    def get_exports(self) -> list[dict[str, object]]:
        return [{"name": "exp"}]

    def analyze_sections(self) -> list[dict[str, object]]:
        return [{"name": ".text"}]

    def detect_compiler(self) -> dict[str, object]:
        return {"compiler": "gcc"}

    def search_xor(self, _value: str) -> list[dict[str, object]]:
        return [{"match": True}]

    def analyze_functions(self) -> dict[str, object]:
        return {"analyzed": True}


class _DummyAdapter:
    thread_safe = True

    def get_file_info(self) -> dict[str, object]:
        return {"bin": {"format": "ELF", "arch": "x86", "bits": 64}}


class _InspectorHarness(InspectorExecutionMixin):
    def __init__(self, filename: str) -> None:
        self.adapter = _DummyAdapter()
        self.config = Config()
        self.filename = filename
        self.registry = _DummyRegistry()
        self._result_aggregator = ResultAggregator()


def test_file_validator_branches(tmp_path: Path) -> None:
    missing = FileValidator(tmp_path / "missing.bin")
    assert missing._file_exists() is False

    directory = FileValidator(tmp_path)
    assert directory._file_exists() is False
    assert directory._is_readable() is False

    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    validator = FileValidator(empty)
    assert validator._is_size_valid(0) is False

    small = tmp_path / "small.bin"
    small.write_bytes(b"x" * 2)
    assert validator._is_size_valid(len(small.read_bytes())) is False

    readable = tmp_path / "readable.bin"
    readable.write_bytes(b"abcd")
    assert FileValidator(readable)._is_readable() is True
    assert FileValidator(readable)._file_size_mb() >= 0
    assert FileValidator(readable)._file_exists() is True

    original_check = file_validator_module.check_memory_limits
    try:
        file_validator_module.check_memory_limits = (  # type: ignore[assignment]
            lambda **_kwargs: False
        )
        assert FileValidator(readable)._within_memory_limits(10) is False
    finally:
        file_validator_module.check_memory_limits = original_check  # type: ignore[assignment]


def test_inspector_init_and_analyze_paths(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x7fELF\x02" + b"x" * 60)

    adapter = _DummyAdapter()

    def registry_factory() -> _DummyRegistry:
        return _DummyRegistry()

    pipeline = _DummyPipeline({"ok": True})

    def pipeline_builder_factory(*_args: object) -> _DummyPipelineBuilder:
        return _DummyPipelineBuilder(pipeline)

    class _PipelineConfig:
        def __init__(self, parallel: bool) -> None:
            self.parallel_execution = parallel

    class _TypedConfig:
        def __init__(self, parallel: bool) -> None:
            self.pipeline = _PipelineConfig(parallel)

    class _Config:
        def __init__(self, parallel: bool) -> None:
            self.typed_config = _TypedConfig(parallel)

    def _validator_factory(_path: str) -> FileValidator:
        return FileValidator(sample)

    inspector = R2Inspector(
        filename=str(sample),
        config=None,
        verbose=True,
        cleanup_callback=None,
        adapter=adapter,
        registry_factory=registry_factory,
        pipeline_builder_factory=pipeline_builder_factory,
        config_factory=lambda: _Config(False),
        file_validator_factory=_validator_factory,
        result_aggregator_factory=ResultAggregator,
        memory_monitor=memory_manager_module.MemoryMonitor(),
    )
    assert inspector.analyze(progress_callback=lambda _stage: None)["ok"] is True

    inspector.config.typed_config.pipeline.parallel_execution = True
    adapter.thread_safe = False
    assert inspector.analyze(progress_callback=lambda _stage: None)["ok"] is True

    adapter.thread_safe = True
    assert inspector.analyze()["ok"] is True

    inspector._pipeline_builder = None
    assert inspector.analyze().get("error") == "Pipeline builder is not initialized"

    with inspector as ctx:
        assert ctx is inspector
    inspector.close()
    inspector.__del__()

    class _FailValidator(FileValidator):
        def validate(self) -> bool:  # type: ignore[override]
            return False

    with pytest.raises(ValueError):
        R2Inspector(
            filename=str(sample),
            config=Config(),
            verbose=False,
            cleanup_callback=None,
            adapter=adapter,
            registry_factory=registry_factory,
            pipeline_builder_factory=pipeline_builder_factory,
            config_factory=Config,
            file_validator_factory=lambda _path: _FailValidator(sample),
            result_aggregator_factory=ResultAggregator,
            memory_monitor=memory_manager_module.MemoryMonitor(),
        )


def test_inspector_missing_factories_and_cleanup(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x" * 64)
    adapter = _DummyAdapter()

    def registry_factory() -> _DummyRegistry:
        return _DummyRegistry()

    def pipeline_builder_factory(*_args: object) -> _DummyPipelineBuilder:
        return _DummyPipelineBuilder(_DummyPipeline({}))

    with pytest.raises(ValueError):
        R2Inspector(
            filename=str(sample),
            config=Config(),
            verbose=False,
            cleanup_callback=None,
            adapter=adapter,
            registry_factory=registry_factory,
            pipeline_builder_factory=pipeline_builder_factory,
            config_factory=Config,
            file_validator_factory=None,
            result_aggregator_factory=ResultAggregator,
            memory_monitor=memory_manager_module.MemoryMonitor(),
        )

    with pytest.raises(ValueError):
        R2Inspector(
            filename=str(sample),
            config=Config(),
            verbose=False,
            cleanup_callback=None,
            adapter=adapter,
            registry_factory=registry_factory,
            pipeline_builder_factory=pipeline_builder_factory,
            config_factory=Config,
            file_validator_factory=FileValidator,
            result_aggregator_factory=None,
            memory_monitor=memory_manager_module.MemoryMonitor(),
        )

    called = {"ok": False}

    def _cleanup() -> None:
        called["ok"] = True

    inspector = R2Inspector(
        filename=str(sample),
        config=Config(),
        verbose=False,
        cleanup_callback=_cleanup,
        adapter=adapter,
        registry_factory=registry_factory,
        pipeline_builder_factory=pipeline_builder_factory,
        config_factory=Config,
        file_validator_factory=FileValidator,
        result_aggregator_factory=ResultAggregator,
        memory_monitor=memory_manager_module.MemoryMonitor(),
    )
    inspector._cleanup()
    assert called["ok"] is True

    inspector._registry_factory = None
    with pytest.raises(ValueError):
        inspector._init_infrastructure()


def test_inspector_helpers_paths(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x7fELF\x02" + b"x" * 60)
    harness = _InspectorHarness(str(sample))

    assert harness.get_file_info().get("name") == "sample.bin"
    assert harness._detect_file_format() == "Unknown"
    assert harness.get_pe_info()["analyzed"] is True
    assert harness.get_elf_info()["analyzed"] is True
    assert harness.get_macho_info()["analyzed"] is True
    assert harness.get_strings() == ["a", "b"]
    assert harness.get_security_features()["aslr"] is True
    assert harness.get_imports()[0]["name"] == "imp"
    assert harness.get_exports()[0]["name"] == "exp"
    assert harness.get_sections()[0]["name"] == ".text"
    assert harness.detect_packer()["detected"] is True
    assert harness.detect_crypto()["detected"] is True
    assert harness.detect_anti_analysis()["detected"] is True
    assert harness.detect_compiler()["compiler"] == "gcc"
    assert harness.run_yara_rules(None)[0]["rule"] == "r1"
    assert harness.search_xor("x")[0]["match"] is True
    assert harness.analyze_functions()["analyzed"] is True
    assert harness.analyze_ssdeep()["analyzed"] is True
    assert harness.analyze_tlsh()["analyzed"] is True
    assert harness.analyze_telfhash()["analyzed"] is True
    assert harness.analyze_rich_header()["analyzed"] is True
    assert harness.analyze_impfuzzy()["analyzed"] is True
    assert harness.analyze_ccbhash()["analyzed"] is True
    assert harness.analyze_binlex()["analyzed"] is True
    assert harness.analyze_binbloom()["analyzed"] is True
    assert harness.analyze_simhash()["analyzed"] is True
    assert harness.analyze_bindiff()["analyzed"] is True
    assert harness.generate_executive_summary({"file_info": {"name": "sample.bin"}})

    harness.registry.get_analyzer_class = lambda _name: None  # type: ignore[assignment]
    assert harness._execute_analyzer("missing") == {}

    harness.registry.get_analyzer_class = lambda _name: _DummyAnalyzer  # type: ignore[assignment]
    harness._result_aggregator = type(
        "Agg", (), {"generate_indicators": lambda _self, _res: [{"type": "x"}]}
    )()
    assert harness.generate_indicators({"any": True})


def test_result_aggregator_helpers() -> None:
    data = {
        "file_info": {"name": "sample.bin", "file_type": "PE", "size": 10},
        "pe_info": {"compilation_timestamp": "2020"},
        "rich_header": {"available": True, "compilers": [{"compiler_name": "MSVC"}]},
        "security": {"authenticode": False, "aslr": True, "dep": False},
        "packer": {"is_packed": False},
        "anti_analysis": {"anti_debug": True, "anti_vm": True},
        "imports": [{"name": "VirtualAlloc"}],
        "yara_matches": [{"rule": "rule1"}],
        "sections": [{"entropy": 8.0, "name": ".text", "suspicious_indicators": ["x"]}],
        "functions": {"count": 1},
        "crypto": {"matches": [1]},
    }
    normalized = _normalize_results(data)
    assert normalized["file_info"]["name"] == "sample.bin"
    assert _build_file_overview(normalized)["filename"] == "sample.bin"
    assert _build_security_assessment(normalized)["is_signed"] is False
    assert _build_threat_indicators(normalized)["yara_matches"] == 1
    assert _build_technical_details(normalized)["functions"] == 1

    assert _generate_recommendations(normalized)
    empty_recs = _generate_recommendations(_normalize_results({"security": {"authenticode": True}}))
    assert empty_recs


def test_pipeline_builder_builds_stages(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x" * 64)

    class _PipelineConfig:
        def __init__(self) -> None:
            self.max_workers = 2
            self.stage_timeout = 3.0

    class _TypedConfig:
        def __init__(self) -> None:
            self.pipeline = _PipelineConfig()

    class _Config:
        def __init__(self) -> None:
            self.typed_config = _TypedConfig()

    builder = PipelineBuilder(_DummyAdapter(), _DummyRegistry(), _Config(), str(sample))
    pipeline = builder.build({})
    assert len(pipeline.stages) == 8
    assert pipeline.stages[0].timeout == 3.0


def test_r2_session_core_paths(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x" * 64)

    session = R2Session(str(sample))
    assert session._get_open_timeout() > 0
    assert session._get_cmd_timeout() > 0
    assert session._get_analysis_timeout(full_analysis=True) > 0
    assert session._get_large_file_threshold() > 0
    assert session._get_huge_file_threshold() > 0

    os.environ["R2INSPECT_TEST_MODE"] = "1"
    try:
        test_session = R2Session(str(sample))
        assert test_session._get_open_timeout() > 0
        assert test_session._get_cmd_timeout() > 0
        assert test_session._get_analysis_timeout(full_analysis=False) > 0
    finally:
        os.environ.pop("R2INSPECT_TEST_MODE", None)

    class _R2:
        def __init__(self) -> None:
            self.commands: list[str] = []

        def cmd(self, command: str) -> str:
            self.commands.append(command)
            return "info" if command == "i" else ""

        def quit(self) -> None:
            pass

    session.r2 = _R2()
    assert session._run_cmd_with_timeout("i", 1.0) is True

    os.environ["R2INSPECT_FORCE_CMD_TIMEOUT"] = "i"
    try:
        assert session._run_cmd_with_timeout("i", 1.0) is False
    finally:
        os.environ.pop("R2INSPECT_FORCE_CMD_TIMEOUT", None)

    class _FailR2(_R2):
        def cmd(self, command: str) -> str:  # type: ignore[override]
            raise RuntimeError("boom")

    session.r2 = _FailR2()
    assert session._run_cmd_with_timeout("i", 1.0) is False

    session.r2 = _R2()
    session._run_cmd_with_timeout = lambda *_args, **_kwargs: True  # type: ignore[assignment]
    session.r2.cmd = lambda _cmd: "x"  # type: ignore[assignment]
    assert session._run_basic_info_check() is True

    session.r2.cmd = lambda _cmd: (_ for _ in ()).throw(RuntimeError("fail"))  # type: ignore[assignment]
    with pytest.raises(RuntimeError):
        session._run_basic_info_check()

    session = R2Session(str(sample))
    session.r2 = None
    assert session._run_cmd_with_timeout("i", 0.1) is False

    os.environ["R2INSPECT_ANALYSIS_DEPTH"] = "0"
    try:
        session = R2Session(str(sample))
        session.r2 = _R2()
        assert session._perform_initial_analysis(1.0) is True
    finally:
        os.environ.pop("R2INSPECT_ANALYSIS_DEPTH", None)

    session = R2Session(str(sample))
    session.r2 = _R2()
    session._run_cmd_with_timeout = lambda *_args, **_kwargs: False  # type: ignore[assignment]
    assert session._perform_initial_analysis(10000.0) is True

    session = R2Session(str(sample))
    session.r2 = _R2()
    session._run_cmd_with_timeout = lambda *_args, **_kwargs: True  # type: ignore[assignment]
    assert session._perform_initial_analysis(1.0) is True

    session = R2Session(str(sample))
    session.r2 = _R2()
    session._run_cmd_with_timeout = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        RuntimeError("boom")
    )  # type: ignore[assignment]
    assert session._perform_initial_analysis(1.0) is True

    class _Proc:
        def __init__(self, name: str, cmdline: list[str]) -> None:
            self.info = {"name": name, "cmdline": cmdline}
            self.terminated = False

        def terminate(self) -> None:
            self.terminated = True

    proc = _Proc("radare2", [str(sample)])
    original_iter = r2_session_module.psutil.process_iter
    r2_session_module.psutil.process_iter = lambda *_args, **_kwargs: [proc]
    try:
        session._terminate_radare2_processes()
    finally:
        r2_session_module.psutil.process_iter = original_iter
    assert proc.terminated is True

    original_open = r2_session_module.r2pipe.open
    try:
        r2_session_module.r2pipe.open = lambda *_args, **_kwargs: _R2()  # type: ignore[assignment]
        session._cleanup_required = True
        session.r2 = _R2()
        reopened = session._reopen_safe_mode()
        assert reopened is not None
    finally:
        r2_session_module.r2pipe.open = original_open  # type: ignore[assignment]

    session = R2Session(str(sample))
    session.r2 = _R2()
    session._cleanup_required = True
    session.close()
    assert session.r2 is None

    class _SuccessSession(R2Session):
        def _open_with_timeout(self, flags: list[str], timeout: float) -> object:  # type: ignore[override]
            self.r2 = _R2()
            return self.r2

        def _run_basic_info_check(self) -> bool:  # type: ignore[override]
            return True

        def _perform_initial_analysis(self, _size: float) -> bool:  # type: ignore[override]
            return True

    success = _SuccessSession(str(sample))
    assert success.open(1.0) is success.r2

    fat_file = tmp_path / "fat.macho"
    magic = struct.pack(">I", 0xCAFEBABE)
    nfat = struct.pack(">I", 1)
    entry = struct.pack(">IIIII", 0x01000007, 0, 0, 0, 0)
    fat_file.write_bytes(magic + nfat + entry)
    session = R2Session(str(fat_file))
    original_machine = r2_session_module.platform.machine
    try:
        r2_session_module.platform.machine = lambda: "x86_64"  # type: ignore[assignment]
        flags = session._select_r2_flags()
        os.environ["R2INSPECT_DISABLE_PLUGINS"] = "1"
        flags = session._select_r2_flags()
        assert "-NN" in flags
    finally:
        r2_session_module.platform.machine = original_machine  # type: ignore[assignment]
        os.environ.pop("R2INSPECT_DISABLE_PLUGINS", None)

    missing_session = R2Session(str(tmp_path / "missing.bin"))
    assert missing_session._detect_fat_macho_arches() == set()

    class _BadProc:
        @property
        def info(self) -> dict[str, object]:
            raise r2_session_module.psutil.AccessDenied()

    original_iter = r2_session_module.psutil.process_iter
    try:
        r2_session_module.psutil.process_iter = lambda *_args, **_kwargs: [_BadProc()]  # type: ignore[assignment]
        session._terminate_radare2_processes()
    finally:
        r2_session_module.psutil.process_iter = original_iter  # type: ignore[assignment]

    class _SlowR2(_R2):
        def cmd(self, command: str) -> str:  # type: ignore[override]
            time.sleep(0.05)
            return "info"

    session = R2Session(str(sample))
    session.r2 = _SlowR2()
    assert session._run_cmd_with_timeout("i", timeout=0.001) is False

    session = R2Session(str(sample))
    session.r2 = _R2()
    session._run_cmd_with_timeout = lambda *_args, **_kwargs: False  # type: ignore[assignment]
    assert session._run_basic_info_check() is False

    session = R2Session(str(sample))
    session.r2 = _R2()
    session._run_cmd_with_timeout = lambda *_args, **_kwargs: True  # type: ignore[assignment]
    assert session._perform_initial_analysis(session._get_large_file_threshold() + 1) is True

    session = R2Session(str(sample))
    session.r2 = _R2()
    session._run_cmd_with_timeout = lambda *_args, **_kwargs: False  # type: ignore[assignment]
    assert session._perform_initial_analysis(session._get_large_file_threshold() + 1) is False

    class _FailingQuit(_R2):
        def quit(self) -> None:  # type: ignore[override]
            raise RuntimeError("boom")

    session = R2Session(str(sample))
    session.r2 = _FailingQuit()
    session._cleanup_required = True
    session.close()

    session = R2Session(str(sample))
    session.r2 = _R2()
    session._cleanup_required = True
    with session as ctx:
        assert ctx is session
