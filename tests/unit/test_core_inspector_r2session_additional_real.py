from __future__ import annotations

import os
import struct
import time
from pathlib import Path

import pytest

from r2inspect.config import Config
from r2inspect.core import r2_session as r2_session_module
from r2inspect.core.file_validator import FileValidator
from r2inspect.core.inspector import R2Inspector
from r2inspect.core.inspector_helpers import InspectorExecutionMixin
from r2inspect.core.r2_session import R2Session
from r2inspect.core.result_aggregator import ResultAggregator
from r2inspect.utils.memory_manager import (
    MemoryMonitor,
    configure_memory_limits,
    global_memory_monitor,
)


class _DummyR2:
    def __init__(self, cmd_response: str = "info") -> None:
        self._cmd_response = cmd_response
        self.commands: list[str] = []
        self.quit_called = False

    def cmd(self, command: str) -> str:
        self.commands.append(command)
        if command == "boom":
            raise RuntimeError("cmd failed")
        return self._cmd_response

    def quit(self) -> None:
        self.quit_called = True


class _DummyPipeline:
    def __init__(self, result: dict[str, object], fail: Exception | None = None) -> None:
        self._result = result
        self._fail = fail

    def execute(self, _options: dict[str, object], parallel: bool = False) -> dict[str, object]:
        if self._fail:
            raise self._fail
        return self._result

    def execute_with_progress(
        self, _callback: object, _options: dict[str, object]
    ) -> dict[str, object]:
        if self._fail:
            raise self._fail
        return self._result


class _DummyPipelineBuilder:
    def __init__(self, pipeline: _DummyPipeline) -> None:
        self._pipeline = pipeline

    def build(self, _options: dict[str, object]) -> _DummyPipeline:
        return self._pipeline


class _DummyRegistry(dict):
    def list_analyzers(self) -> list[dict[str, object]]:
        return []

    def get_analyzer_class(self, name: str) -> object | None:
        return None if name == "missing" else _DummyAnalyzer


class _DummyAnalyzer:
    def __init__(self, *_args: object, **_kwargs: object) -> None:
        self.called: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def analyze(self, *_args: object, **_kwargs: object) -> dict[str, object]:
        return {"analyzed": True}

    def custom(self, value: str) -> dict[str, object]:
        return {"value": value}


class _InspectorHarness(InspectorExecutionMixin):
    def __init__(self) -> None:
        self.adapter = object()
        self.config = Config()
        self.filename = "sample.bin"
        self.registry = _DummyRegistry()
        self._result_aggregator = ResultAggregator()


def test_file_validator_branches(tmp_path: Path) -> None:
    missing = FileValidator(tmp_path / "missing.bin")
    assert missing.validate() is False

    directory = FileValidator(tmp_path)
    assert directory.validate() is False

    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    assert FileValidator(empty).validate() is False

    tiny = tmp_path / "tiny.bin"
    tiny.write_bytes(b"x" * 8)
    assert FileValidator(tiny).validate() is False

    small = tmp_path / "small.bin"
    small.write_bytes(b"x" * 32)
    assert FileValidator(small).validate() is True
    assert FileValidator(small)._file_size_mb() > 0

    short = tmp_path / "short.bin"
    short.write_bytes(b"123")
    assert FileValidator(short)._is_readable() is False

    restricted = tmp_path / "restricted.bin"
    restricted.write_bytes(b"x" * 32)
    restricted.chmod(0)
    try:
        assert FileValidator(restricted)._is_readable() is False
    finally:
        restricted.chmod(0o600)

    original_limit = global_memory_monitor.limits.max_file_size_mb
    try:
        configure_memory_limits(max_file_size_mb=0)
        assert FileValidator(small).validate() is False
    finally:
        configure_memory_limits(max_file_size_mb=original_limit)


def test_r2_session_analysis_paths(tmp_path: Path) -> None:
    test_file = tmp_path / "sample.bin"
    test_file.write_bytes(b"x" * 64)

    session = R2Session(str(test_file))
    session.r2 = _DummyR2(cmd_response="i")

    os.environ["R2INSPECT_FORCE_CMD_TIMEOUT"] = "i"
    try:
        assert session._run_cmd_with_timeout("i", timeout=0.01) is False
    finally:
        os.environ.pop("R2INSPECT_FORCE_CMD_TIMEOUT", None)

    session.r2 = _DummyR2(cmd_response="i")
    assert session._run_basic_info_check() is True

    session.r2 = _DummyR2(cmd_response="")
    assert session._run_basic_info_check() is True

    session.r2 = _DummyR2(cmd_response="info")
    session.r2.cmd = lambda _cmd: (_ for _ in ()).throw(RuntimeError("fail"))  # type: ignore[assignment]
    assert session._run_cmd_with_timeout("boom", timeout=0.01) is False

    session.r2 = _DummyR2(cmd_response="info")
    session._run_cmd_with_timeout = lambda _cmd, _timeout: True  # type: ignore[assignment]
    session.r2.cmd = lambda _cmd: (_ for _ in ()).throw(RuntimeError("fail"))  # type: ignore[assignment]
    with pytest.raises(RuntimeError):
        session._run_basic_info_check()

    session.r2 = _DummyR2(cmd_response="info")
    os.environ["R2INSPECT_ANALYSIS_DEPTH"] = "0"
    try:
        assert session._perform_initial_analysis(1.0) is True
    finally:
        os.environ.pop("R2INSPECT_ANALYSIS_DEPTH", None)

    os.environ["R2INSPECT_TEST_MODE"] = "1"
    try:
        session = R2Session(str(test_file))
        session.r2 = _DummyR2(cmd_response="info")
        assert session._perform_initial_analysis(9999.0) is True
    finally:
        os.environ.pop("R2INSPECT_TEST_MODE", None)

    session = R2Session(str(test_file))
    session.r2 = _DummyR2(cmd_response="info")
    assert session._run_basic_info_check() is True
    session.r2 = None
    with pytest.raises(RuntimeError):
        session._run_basic_info_check()

    session = R2Session(str(test_file))
    session.r2 = _DummyR2(cmd_response="info")
    session._run_cmd_with_timeout = lambda _cmd, _timeout: False  # type: ignore[assignment]
    assert session._perform_initial_analysis(1.0) is False

    os.environ["R2INSPECT_TEST_MODE"] = "0"
    try:
        session = R2Session(str(test_file))
        session.r2 = _DummyR2(cmd_response="info")
        session._run_cmd_with_timeout = lambda _cmd, _timeout: False  # type: ignore[assignment]
        assert session._perform_initial_analysis(0.1) is False
    finally:
        os.environ.pop("R2INSPECT_TEST_MODE", None)

    session = R2Session(str(test_file))
    session.r2 = None
    assert session._perform_initial_analysis(1.0) is True


def test_r2_session_flags_and_fat_macho(tmp_path: Path) -> None:
    fat_file = tmp_path / "fat.macho"
    magic = struct.pack(">I", 0xCAFEBABE)
    nfat = struct.pack(">I", 1)
    entry = struct.pack(">IIIII", 0x0100000C, 0, 0, 0, 0)
    fat_file.write_bytes(magic + nfat + entry)

    os.environ["R2INSPECT_TEST_MODE"] = "1"
    os.environ["R2INSPECT_DISABLE_PLUGINS"] = "1"
    try:
        session = R2Session(str(fat_file))
        flags = session._select_r2_flags()
        assert "-2" in flags
        assert "-M" in flags
        assert "-NN" in flags
    finally:
        os.environ.pop("R2INSPECT_TEST_MODE", None)
        os.environ.pop("R2INSPECT_DISABLE_PLUGINS", None)

    short_file = tmp_path / "short.macho"
    short_file.write_bytes(b"short")
    session = R2Session(str(short_file))
    assert session._detect_fat_macho_arches() == set()

    little_file = tmp_path / "fat_le.macho"
    magic = struct.pack(">I", 0xBEBAFECA)
    nfat = struct.pack(">I", 1)
    entry = struct.pack("<IIIII", 0x01000007, 0, 0, 0, 0)
    little_file.write_bytes(magic + nfat + entry)
    session = R2Session(str(little_file))
    assert "x86_64" in session._detect_fat_macho_arches()


def test_r2_session_open_timeout_and_close(tmp_path: Path) -> None:
    test_file = tmp_path / "sample.bin"
    test_file.write_bytes(b"x" * 64)
    session = R2Session(str(test_file))

    original_open = r2_session_module.r2pipe.open
    try:

        def _slow_open(_filename: str, flags: list[str] | None = None) -> object:
            time.sleep(0.05)
            return object()

        r2_session_module.r2pipe.open = _slow_open  # type: ignore[assignment]
        with pytest.raises(TimeoutError):
            session._open_with_timeout(["-2"], timeout=0.001)
    finally:
        r2_session_module.r2pipe.open = original_open  # type: ignore[assignment]

    session.r2 = _DummyR2(cmd_response="info")
    session._cleanup_required = True
    assert session.is_open is True
    session.close()
    assert session.is_open is False


def test_r2_session_open_branches(tmp_path: Path) -> None:
    test_file = tmp_path / "sample.bin"
    test_file.write_bytes(b"x" * 64)

    class _SafeModeSession(R2Session):
        def _open_with_timeout(self, flags: list[str], timeout: float) -> object:  # type: ignore[override]
            self.r2 = _DummyR2(cmd_response="info")
            return self.r2

        def _run_basic_info_check(self) -> bool:  # type: ignore[override]
            return False

        def _perform_initial_analysis(self, _size: float) -> bool:  # type: ignore[override]
            return True

    safe_session = _SafeModeSession(str(test_file))
    original_open = r2_session_module.r2pipe.open
    try:
        r2_session_module.r2pipe.open = lambda *_args, **_kwargs: _DummyR2(  # type: ignore[assignment]
            cmd_response="info"
        )
        assert safe_session.open(1.0) is not None
    finally:
        r2_session_module.r2pipe.open = original_open  # type: ignore[assignment]

    class _SafeModeSessionAnalysis(_SafeModeSession):
        def _run_basic_info_check(self) -> bool:  # type: ignore[override]
            return True

        def _perform_initial_analysis(self, _size: float) -> bool:  # type: ignore[override]
            return False

    safe_session = _SafeModeSessionAnalysis(str(test_file))
    original_open = r2_session_module.r2pipe.open
    try:
        r2_session_module.r2pipe.open = lambda *_args, **_kwargs: _DummyR2(  # type: ignore[assignment]
            cmd_response="info"
        )
        assert safe_session.open(1.0) is not None
    finally:
        r2_session_module.r2pipe.open = original_open  # type: ignore[assignment]

    class _FailingSession(R2Session):
        def _open_with_timeout(self, flags: list[str], timeout: float) -> object:  # type: ignore[override]
            self.r2 = _DummyR2(cmd_response="info")
            raise RuntimeError("boom")

    failing = _FailingSession(str(test_file))
    assert failing.open(1.0) == ""

    safe_mode = R2Session(str(test_file))
    original_open = r2_session_module.r2pipe.open
    try:
        r2_session_module.r2pipe.open = lambda *_args, **_kwargs: _DummyR2(  # type: ignore[assignment]
            cmd_response="info"
        )
        safe_mode._reopen_safe_mode()
    finally:
        r2_session_module.r2pipe.open = original_open  # type: ignore[assignment]


def test_inspector_analyze_paths(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x" * 64)

    memory_monitor = MemoryMonitor()
    adapter = type("Adapter", (), {"thread_safe": False})()

    def registry_factory() -> _DummyRegistry:
        return _DummyRegistry()

    def pipeline_builder_factory(
        _adapter: object, _registry: object, _config: object, _path: object
    ) -> _DummyPipelineBuilder:
        return _DummyPipelineBuilder(_DummyPipeline({"ok": True}))

    def file_validator_factory(_path: object) -> FileValidator:
        return FileValidator(sample)

    def result_aggregator_factory() -> ResultAggregator:
        return ResultAggregator()

    inspector = R2Inspector(
        filename=str(sample),
        config=Config(),
        verbose=True,
        cleanup_callback=None,
        adapter=adapter,
        registry_factory=registry_factory,
        pipeline_builder_factory=pipeline_builder_factory,
        config_factory=Config,
        file_validator_factory=file_validator_factory,
        result_aggregator_factory=result_aggregator_factory,
        memory_monitor=memory_monitor,
    )
    results = inspector.analyze(progress_callback=lambda _stage: None)
    assert "memory_stats" in results

    class _VerboseRegistry(_DummyRegistry):
        def list_analyzers(self) -> list[dict[str, object]]:
            return [{"name": "a", "category": "cat", "file_formats": ["PE"]}]

    verbose_inspector = R2Inspector(
        filename=str(sample),
        config=Config(),
        verbose=True,
        cleanup_callback=None,
        adapter=adapter,
        registry_factory=lambda: _VerboseRegistry(),
        pipeline_builder_factory=pipeline_builder_factory,
        config_factory=Config,
        file_validator_factory=file_validator_factory,
        result_aggregator_factory=result_aggregator_factory,
        memory_monitor=memory_monitor,
    )
    assert verbose_inspector.analyze()["memory_stats"]["gc_count"] >= 0

    def failing_builder(
        _adapter: object, _registry: object, _config: object, _path: object
    ) -> _DummyPipelineBuilder:
        return _DummyPipelineBuilder(_DummyPipeline({}, fail=MemoryError("mem")))

    inspector_fail = R2Inspector(
        filename=str(sample),
        config=Config(),
        verbose=False,
        cleanup_callback=None,
        adapter=adapter,
        registry_factory=registry_factory,
        pipeline_builder_factory=failing_builder,
        config_factory=Config,
        file_validator_factory=file_validator_factory,
        result_aggregator_factory=result_aggregator_factory,
        memory_monitor=memory_monitor,
    )
    assert inspector_fail.analyze()["error"] == "Memory limit exceeded"

    def error_builder(
        _adapter: object, _registry: object, _config: object, _path: object
    ) -> _DummyPipelineBuilder:
        return _DummyPipelineBuilder(_DummyPipeline({}, fail=RuntimeError("boom")))

    inspector_error = R2Inspector(
        filename=str(sample),
        config=Config(),
        verbose=False,
        cleanup_callback=None,
        adapter=adapter,
        registry_factory=registry_factory,
        pipeline_builder_factory=error_builder,
        config_factory=Config,
        file_validator_factory=file_validator_factory,
        result_aggregator_factory=result_aggregator_factory,
        memory_monitor=memory_monitor,
    )
    assert inspector_error.analyze()["error"] == "boom"


def test_inspector_init_errors(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x" * 64)
    memory_monitor = MemoryMonitor()

    with pytest.raises(ValueError):
        R2Inspector(
            filename=str(sample),
            config=Config(),
            verbose=False,
            cleanup_callback=None,
            adapter=object(),
            registry_factory=lambda: _DummyRegistry(),
            pipeline_builder_factory=lambda *_args: _DummyPipelineBuilder(_DummyPipeline({})),
            config_factory=Config,
            file_validator_factory=FileValidator,
            result_aggregator_factory=ResultAggregator,
            memory_monitor=None,
        )

    with pytest.raises(ValueError):
        R2Inspector(
            filename=str(sample),
            config=None,
            verbose=False,
            cleanup_callback=None,
            adapter=object(),
            registry_factory=lambda: _DummyRegistry(),
            pipeline_builder_factory=lambda *_args: _DummyPipelineBuilder(_DummyPipeline({})),
            config_factory=None,
            file_validator_factory=FileValidator,
            result_aggregator_factory=ResultAggregator,
            memory_monitor=memory_monitor,
        )

    with pytest.raises(ValueError):
        R2Inspector(
            filename=str(sample),
            config=Config(),
            verbose=False,
            cleanup_callback=None,
            adapter=None,
            registry_factory=lambda: _DummyRegistry(),
            pipeline_builder_factory=lambda *_args: _DummyPipelineBuilder(_DummyPipeline({})),
            config_factory=Config,
            file_validator_factory=FileValidator,
            result_aggregator_factory=ResultAggregator,
            memory_monitor=memory_monitor,
        )

    with pytest.raises(ValueError):
        R2Inspector(
            filename=str(sample),
            config=Config(),
            verbose=False,
            cleanup_callback=None,
            adapter=object(),
            registry_factory=lambda: _DummyRegistry(),
            pipeline_builder_factory=None,
            config_factory=Config,
            file_validator_factory=FileValidator,
            result_aggregator_factory=ResultAggregator,
            memory_monitor=memory_monitor,
        )


def test_inspector_helpers_missing_analyzer_and_conversion() -> None:
    harness = _InspectorHarness()
    assert harness._execute_analyzer("missing") == {}
    assert harness._execute_analyzer("missing", "custom") == {}

    assert harness._execute_analyzer("dummy", "custom", "value") == {"value": "value"}
    assert harness._execute_analyzer("dummy", "missing_method") == {}
    assert harness._execute_analyzer("dummy", "analyze", 1, key="v") == {"analyzed": True}

    class _FailingAnalyzer:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raise RuntimeError("fail")

    harness.registry.get_analyzer_class = lambda _name: _FailingAnalyzer  # type: ignore[assignment]
    assert harness._execute_analyzer("any") == {}

    assert harness._as_bool_dict("bad") == {}
    assert harness._as_str(123, default="fallback") == "fallback"

    assert harness.detect_crypto() == {
        "algorithms": [],
        "constants": [],
        "error": "Analyzer not found",
    }

    harness._result_aggregator = type("Agg", (), {"generate_indicators": lambda _self, _res: {}})()
    assert harness.generate_indicators({"anything": True}) == []

    harness._result_aggregator = type(
        "Agg", (), {"generate_executive_summary": lambda _self, _res: []}
    )()
    assert harness.generate_executive_summary({"anything": True}) == {}


def test_inspector_helpers_execution_and_format_detection() -> None:
    class _Pipeline:
        def execute_with_progress(
            self, _callback: object, _options: dict[str, object]
        ) -> dict[str, object]:
            return {"ok": True}

        def execute(self, _options: dict[str, object], parallel: bool = False) -> dict[str, object]:
            return {"parallel": parallel}

    harness = _InspectorHarness()
    assert harness._execute_with_progress(_Pipeline(), {}, lambda _stage: None) == {"ok": True}
    assert harness._execute_without_progress(_Pipeline(), {}, parallel=True) == {"parallel": True}

    class _Adapter:
        def get_file_info(self) -> dict[str, object]:
            return {"bin": {"format": "ELF"}}

    harness.adapter = _Adapter()
    assert harness._detect_file_format() == "Unknown"


def test_result_aggregator_paths() -> None:
    aggregator = ResultAggregator()
    analysis_results = {
        "file_info": {
            "name": "sample.bin",
            "file_type": "PE32",
            "size": 123,
            "architecture": "x86",
            "md5": "md5",
            "sha256": "sha",
        },
        "pe_info": {"compilation_timestamp": "2024-01-01"},
        "rich_header": {
            "available": True,
            "compilers": [{"compiler_name": "MSVC", "build_number": 19}],
        },
        "security": {"authenticode": False, "aslr": True, "dep": True},
        "packer": {"is_packed": True, "packer_type": "UPX"},
        "anti_analysis": {"anti_debug": True, "anti_vm": True},
        "imports": [{"name": "VirtualAlloc"}],
        "yara_matches": [{"rule": "rule1"}],
        "sections": [{"name": ".text", "entropy": 7.5, "suspicious_indicators": ["x"]}],
        "crypto": {"matches": [1]},
        "functions": {"count": 3},
    }

    indicators = aggregator.generate_indicators(analysis_results)
    assert any(ind["type"] == "Packer" for ind in indicators)
    assert any(ind["type"] == "Anti-Debug" for ind in indicators)
    assert any(ind["type"] == "Suspicious API" for ind in indicators)

    summary = aggregator.generate_executive_summary(analysis_results)
    assert summary["file_overview"]["compiled"] == "2024-01-01"
    assert "toolset" in summary["file_overview"]
    assert summary["security_assessment"]["is_packed"] is True
    assert summary["threat_indicators"]["yara_matches"] == 1
    assert summary["recommendations"]

    error_summary = aggregator.generate_executive_summary(None)  # type: ignore[arg-type]
    assert "error" in error_summary
