from __future__ import annotations

from types import SimpleNamespace
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

from r2inspect.application.analysis_service import AnalysisService
from r2inspect.cli import validators
from r2inspect.cli_main import CLIArgs, run_cli
from r2inspect.core.inspector import R2Inspector
from r2inspect.domain.analysis_runtime import AnalysisRuntimeStats
from r2inspect.pipeline.stages_detection import DetectionStage
from r2inspect.pipeline.stages_security import SecurityStage


class _DummyConfig:
    def __init__(self) -> None:
        self.typed_config = SimpleNamespace(pipeline=SimpleNamespace(parallel_execution=False))


class _DummyMemoryMonitor:
    def __init__(self) -> None:
        self.gc_calls = 0

    def check_memory(self, force: bool = False) -> dict[str, Any]:
        return {
            "process_memory_mb": 1.0,
            "peak_memory_mb": 1.0,
            "gc_count": 0,
        }

    def _trigger_gc(self, aggressive: bool = False) -> None:
        self.gc_calls += 1

    def is_memory_available(self, required_mb: float) -> bool:
        return True


class _DummyValidator:
    def __init__(self, valid: bool = True) -> None:
        self._valid = valid

    def validate(self) -> bool:
        return self._valid


class _DummyAdapter(SimpleNamespace):
    thread_safe: bool = True


class _DummyPipeline:
    def __init__(self, executor: Any) -> None:
        self._executor = executor

    def build(self, options: dict[str, Any]) -> _DummyPipeline:
        return self

    def execute(
        self, options: dict[str, Any] | None = None, parallel: bool = False
    ) -> dict[str, Any]:
        return self._executor(options=options, parallel=parallel)

    def execute_with_progress(self, callback: Any, options: dict[str, Any]) -> dict[str, Any]:
        return self._executor(options=options, parallel=False)


class _DummyStageContext(dict[str, Any]):
    def __init__(self) -> None:
        super().__init__()
        self["results"] = {}


def test_inspector_missing_memory_monitor() -> None:
    with pytest.raises(ValueError, match="memory_monitor must be provided"):
        R2Inspector(  # type: ignore[arg-type]
            filename="sample.bin",
            config=_DummyConfig(),
            adapter=_DummyAdapter(),
            file_validator_factory=_DummyValidator,
            result_aggregator_factory=lambda: {},
            registry_factory=lambda: {},
            pipeline_builder_factory=lambda *args, **kwargs: Mock(),
            config_factory=lambda: _DummyConfig(),
            memory_monitor=None,
        )


def test_inspector_init_missing_config_factory() -> None:
    with pytest.raises(ValueError, match="config_factory must be provided"):
        R2Inspector(
            filename="sample.bin",
            config=None,
            verbose=False,
            adapter=_DummyAdapter(),
            config_factory=None,
            file_validator_factory=_DummyValidator,
            result_aggregator_factory=lambda: {},
            registry_factory=lambda: {},
            pipeline_builder_factory=lambda *args, **kwargs: Mock(),
            memory_monitor=_DummyMemoryMonitor(),
        )


def test_inspector_init_missing_adapter() -> None:
    with pytest.raises(ValueError, match="adapter must be provided"):
        R2Inspector(
            filename="sample.bin",
            config=_DummyConfig(),
            adapter=None,
            file_validator_factory=_DummyValidator,
            result_aggregator_factory=lambda: {},
            registry_factory=lambda: {},
            pipeline_builder_factory=lambda *args, **kwargs: Mock(),
            config_factory=lambda: _DummyConfig(),
            memory_monitor=_DummyMemoryMonitor(),
        )


def test_inspector_init_fails_file_validation(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="File validation failed"):
        file_path = tmp_path / "sample.bin"
        file_path.write_bytes(b"data")
        R2Inspector(
            filename=str(file_path),
            config=_DummyConfig(),
            adapter=_DummyAdapter(),
            config_factory=lambda: _DummyConfig(),
            registry_factory=lambda: {},
            pipeline_builder_factory=lambda *args, **kwargs: Mock(),
            file_validator_factory=lambda _: _DummyValidator(valid=False),
            result_aggregator_factory=lambda: {},
            memory_monitor=_DummyMemoryMonitor(),
        )


def test_inspector_analyze_catches_memory_errors() -> None:
    sample = _DummyPipeline(lambda **_: (_ for _ in ()).throw(MemoryError("limit")))

    inspector = R2Inspector(
        filename="sample.bin",
        config=_DummyConfig(),
        adapter=_DummyAdapter(),
        config_factory=lambda: _DummyConfig(),
        file_validator_factory=_DummyValidator,
        result_aggregator_factory=lambda: {},
        registry_factory=lambda: {},
        pipeline_builder_factory=lambda *args, **kwargs: sample,
        memory_monitor=_DummyMemoryMonitor(),
    )
    result = inspector.analyze()
    assert result["error"] == "Memory limit exceeded"
    assert "memory_stats" in result


def test_inspector_analyze_catches_generic_errors() -> None:
    sample = _DummyPipeline(lambda **_: (_ for _ in ()).throw(RuntimeError("boom")))

    inspector = R2Inspector(
        filename="sample.bin",
        config=_DummyConfig(),
        adapter=_DummyAdapter(),
        config_factory=lambda: _DummyConfig(),
        file_validator_factory=_DummyValidator,
        result_aggregator_factory=lambda: {},
        registry_factory=lambda: {},
        pipeline_builder_factory=lambda *args, **kwargs: sample,
        memory_monitor=_DummyMemoryMonitor(),
    )
    result = inspector.analyze()
    assert result["error"] == "boom"
    assert "memory_stats" in result


def test_detection_stage_error_paths() -> None:
    class _FailingAnalyzer:
        def detect(self) -> dict[str, Any]:
            raise RuntimeError("detection failed")

        def detect_compiler(self) -> dict[str, Any]:
            raise RuntimeError("compiler failed")

        def scan(self, custom_rules: str | None = None) -> list[dict[str, Any]]:
            raise RuntimeError("yara failed")

    registry = SimpleNamespace(
        get_analyzer_class=lambda _: _FailingAnalyzer,
    )
    stage = DetectionStage(
        registry=registry,
        adapter=_DummyAdapter(),
        config={},
        filename="sample.bin",
        options={"detect_packer": True, "detect_crypto": True},
        analyzer_factory=lambda analyzer_class, **_: analyzer_class(),
    )

    context = _DummyStageContext()
    result = stage._run_analyzer(context, "packer_detector", "packer")
    assert result == {"packer": {"error": "detection failed"}}
    assert context["results"]["packer"]["error"] == "detection failed"

    context = _DummyStageContext()
    result = stage._run_compiler_detection(context)
    assert result == {"compiler": {"error": "compiler failed"}}
    assert context["results"]["compiler"] == {"error": "compiler failed"}

    context = _DummyStageContext()
    result = stage._run_yara_analysis(context)
    assert result == {"yara_matches": []}


def test_detection_stage_execute_collects_fallbacks() -> None:
    class _FailingAnalyzer:
        def detect(self) -> dict[str, str]:
            raise RuntimeError("detection failed")

    registry = SimpleNamespace(
        get_analyzer_class=lambda name: _FailingAnalyzer,
    )
    stage = DetectionStage(
        registry=registry,
        adapter=_DummyAdapter(),
        config={},
        filename="sample.bin",
        options={"detect_packer": True, "detect_crypto": True},
        analyzer_factory=lambda analyzer_class, **_: analyzer_class(),
    )
    context = _DummyStageContext()
    analyzer_result = stage._run_analyzer(context, "packer_detector", "packer")
    assert analyzer_result == {"packer": {"error": "detection failed"}}
    assert context["results"]["packer"]["error"] == "detection failed"


def test_security_stage_error_paths() -> None:
    class _FailingPEAnalyzer:
        def get_security_features(self) -> dict[str, Any]:
            raise RuntimeError("pe failed")

    class _FailingMitigationAnalyzer:
        def analyze(self) -> dict[str, Any]:
            raise RuntimeError("mitigation failed")

    class _Registry:
        def get_analyzer_class(self, name: str) -> Any:
            if name == "pe_analyzer":
                return _FailingPEAnalyzer
            if name == "exploit_mitigation":
                return _FailingMitigationAnalyzer
            return None

    stage = SecurityStage(
        registry=_Registry(),
        adapter=_DummyAdapter(),
        config={},
        filename="sample.bin",
        analyzer_factory=lambda analyzer_class, **_: analyzer_class(),
    )
    context = _DummyStageContext()
    pe_result = stage._analyze_pe_security(context)
    assert pe_result == {"security": {"error": "pe failed"}}
    assert context["results"]["security"]["error"] == "pe failed"

    context = _DummyStageContext()
    mitigation_result = stage._analyze_mitigations(context)
    assert mitigation_result is None


def test_analysis_service_add_statistics_and_schema_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = type(
        "_Runtime",
        (),
        {
            "reset": staticmethod(lambda: None),
            "collect": staticmethod(
                lambda: AnalysisRuntimeStats(
                    {"total_errors": 1},
                    {"total_retries": 2},
                    {"breaker": 1},
                )
            ),
        },
    )()
    conversions: list[tuple[str, dict[str, Any], bool]] = []

    class _Validator:
        @staticmethod
        def validate(results: dict[str, Any], *, enabled: bool) -> None:
            if enabled and isinstance(results.get("pe"), dict):
                conversions.append(("pe", results["pe"], False))

    service = AnalysisService(runtime=runtime, result_validator=_Validator())
    result: dict[str, Any] = {}

    service.add_statistics(result)
    assert "error_statistics" in result
    assert "retry_statistics" in result
    assert "circuit_breaker_statistics" in result

    monkeypatch.setenv("R2INSPECT_VALIDATE_SCHEMAS", "1")
    service.validate_results({"pe": {"some": "value"}})
    assert conversions == [("pe", {"some": "value"}, False)]


def test_analysis_service_circuit_breaker_detection() -> None:
    assert not AnalysisService.has_circuit_breaker_data({})
    assert AnalysisService.has_circuit_breaker_data({"breaker": 1})
    assert AnalysisService.has_circuit_breaker_data({"nested": {"state": "open"}})


def test_validators_exception_paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    valid_file = tmp_path / "valid.bin"
    valid_file.write_bytes(b"test")
    valid_dir = tmp_path / "batch-dir"
    valid_dir.mkdir()

    class _RaisesValueErrorValidator:
        def validate_path(self, *args: Any, **kwargs: Any) -> Path:
            raise ValueError("no")

    class _PathValidator:
        def validate_path(self, path: str, *_: Any, **__: Any) -> Path:
            if path == "any.bin":
                return valid_file
            if path == "anydir":
                return valid_dir
            return Path(path)

    # filename check: security branch
    monkeypatch.setattr("r2inspect.cli.validators.FileValidator", _RaisesValueErrorValidator)
    assert validators.validate_file_input("bad.bin") == ["File path security validation failed: no"]

    # filename check: simulated runtime error branch
    monkeypatch.setattr("r2inspect.cli.validators.FileValidator", _PathValidator)
    monkeypatch.setenv("R2INSPECT_TEST_RAISE_FILE_ERROR", "1")
    assert validators.validate_file_input("any.bin") == [
        "File access error: Simulated file access error"
    ]
    monkeypatch.delenv("R2INSPECT_TEST_RAISE_FILE_ERROR", raising=False)

    # batch check: security / runtime branches
    monkeypatch.setattr("r2inspect.cli.validators.FileValidator", _RaisesValueErrorValidator)
    assert validators.validate_batch_input("bad-batch") == [
        "Batch directory security validation failed: no"
    ]
    monkeypatch.setattr("r2inspect.cli.validators.FileValidator", _PathValidator)
    monkeypatch.setenv("R2INSPECT_TEST_RAISE_BATCH_ERROR", "1")
    assert validators.validate_batch_input("anydir") == [
        "Batch directory access error: Simulated batch access error"
    ]


def test_validate_output_input_permission_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    output_file = tmp_path / "locked.txt"
    output_file.write_text("x")

    real_open = open

    def fake_open(file_path: str, mode: str = "r") -> Any:
        if "a" in mode:
            raise PermissionError("no permission")
        return real_open(file_path, mode)

    monkeypatch.setattr("builtins.open", fake_open)
    assert validators.validate_output_input(str(output_file)) == [
        f"Cannot write to output file: {output_file}"
    ]
    assert validators.validate_output_input(str(tmp_path / "dir_without_file")) == []


def test_cli_main_list_yara_invokes_config_command(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str | None, str | None]] = []
    exit_codes: list[int] = []

    def fake_execute_list_yara(config: str | None, yara: str | None) -> None:
        calls.append((config, yara))
        fake_exit(0)

    def fake_exit(code: int) -> None:
        exit_codes.append(code)
        raise SystemExit(code)

    monkeypatch.setattr("r2inspect.cli_main._execute_list_yara", fake_execute_list_yara)
    monkeypatch.setattr("r2inspect.cli_main.validate_inputs", lambda *_args, **_kwargs: [])
    monkeypatch.setattr("r2inspect.cli_main.validate_input_mode", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("r2inspect.cli_main.handle_xor_input", lambda value: value)
    monkeypatch.setattr("r2inspect.cli_main.sys.exit", fake_exit)

    with pytest.raises(SystemExit):
        run_cli(CLIArgs(**_cli_kwargs(list_yara=True, yara="custom.yar")))
    assert calls == [(None, "custom.yar")]
    assert exit_codes == [0]


def _cli_kwargs(**overrides: Any) -> dict[str, Any]:
    base = {
        "filename": None,
        "interactive": False,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "xor": None,
        "verbose": False,
        "quiet": False,
        "config": None,
        "yara": None,
        "batch": None,
        "extensions": None,
        "list_yara": False,
        "threads": 10,
        "version": False,
    }
    base.update(overrides)
    return base
