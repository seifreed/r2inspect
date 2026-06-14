from __future__ import annotations

from types import SimpleNamespace
from pathlib import Path
from typing import Any, cast

import pytest

from tests.helpers import env_vars

from r2inspect.application.analysis_service import AnalysisService
from r2inspect.cli import validators
from r2inspect.cli_main import CLIArgs, run_cli
from r2inspect.core.inspector import InspectorDependencies, R2Inspector
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
        R2Inspector(
            filename="sample.bin",
            config=_DummyConfig(),
            deps=InspectorDependencies(
                adapter=_DummyAdapter(),
                file_validator_factory=_DummyValidator,
                result_aggregator_factory=lambda: {},
                registry_factory=lambda: {},
                pipeline_builder_factory=lambda *args, **kwargs: SimpleNamespace(),
                config_factory=lambda: _DummyConfig(),
                memory_monitor=cast(Any, None),
            ),
        )


def test_inspector_init_missing_config_factory() -> None:
    with pytest.raises(ValueError, match="config_factory must be provided"):
        R2Inspector(
            filename="sample.bin",
            config=None,
            verbose=False,
            deps=InspectorDependencies(
                adapter=_DummyAdapter(),
                config_factory=None,
                file_validator_factory=_DummyValidator,
                result_aggregator_factory=lambda: {},
                registry_factory=lambda: {},
                pipeline_builder_factory=lambda *args, **kwargs: SimpleNamespace(),
                memory_monitor=_DummyMemoryMonitor(),
            ),
        )


def test_inspector_init_missing_adapter() -> None:
    with pytest.raises(ValueError, match="adapter must be provided"):
        R2Inspector(
            filename="sample.bin",
            config=_DummyConfig(),
            deps=InspectorDependencies(
                adapter=None,  # type: ignore[arg-type]
                file_validator_factory=_DummyValidator,
                result_aggregator_factory=lambda: {},
                registry_factory=lambda: {},
                pipeline_builder_factory=lambda *args, **kwargs: SimpleNamespace(),
                config_factory=lambda: _DummyConfig(),
                memory_monitor=_DummyMemoryMonitor(),
            ),
        )


def test_inspector_init_fails_file_validation(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="File validation failed"):
        file_path = tmp_path / "sample.bin"
        file_path.write_bytes(b"data")
        R2Inspector(
            filename=str(file_path),
            config=_DummyConfig(),
            deps=InspectorDependencies(
                adapter=_DummyAdapter(),
                config_factory=lambda: _DummyConfig(),
                registry_factory=lambda: {},
                pipeline_builder_factory=lambda *args, **kwargs: SimpleNamespace(),
                file_validator_factory=lambda _: _DummyValidator(valid=False),
                result_aggregator_factory=lambda: {},
                memory_monitor=_DummyMemoryMonitor(),
            ),
        )


def test_inspector_analyze_catches_memory_errors() -> None:
    sample = _DummyPipeline(lambda **_: (_ for _ in ()).throw(MemoryError("limit")))

    inspector = R2Inspector(
        filename="sample.bin",
        config=_DummyConfig(),
        deps=InspectorDependencies(
            adapter=_DummyAdapter(),
            config_factory=lambda: _DummyConfig(),
            file_validator_factory=_DummyValidator,
            result_aggregator_factory=lambda: {},
            registry_factory=lambda: {},
            pipeline_builder_factory=lambda *args, **kwargs: sample,
            memory_monitor=_DummyMemoryMonitor(),
        ),
    )
    result = inspector.analyze()
    assert result["error"] == "Memory limit exceeded"
    assert "memory_stats" in result


def test_inspector_analyze_catches_generic_errors() -> None:
    sample = _DummyPipeline(lambda **_: (_ for _ in ()).throw(RuntimeError("boom")))

    inspector = R2Inspector(
        filename="sample.bin",
        config=_DummyConfig(),
        deps=InspectorDependencies(
            adapter=_DummyAdapter(),
            config_factory=lambda: _DummyConfig(),
            file_validator_factory=_DummyValidator,
            result_aggregator_factory=lambda: {},
            registry_factory=lambda: {},
            pipeline_builder_factory=lambda *args, **kwargs: sample,
            memory_monitor=_DummyMemoryMonitor(),
        ),
    )
    result = inspector.analyze()
    assert result["error"] == "boom"
    assert "memory_stats" in result


def test_detection_stage_error_paths() -> None:
    # 69353a1 unified every detector behind analyze(); stages_detection
    # dispatches through analyze() (was detect()/detect_compiler()/scan()).
    class _FailingPacker:
        def analyze(self) -> dict[str, Any]:
            raise RuntimeError("detection failed")

    class _FailingCompiler:
        def analyze(self) -> dict[str, Any]:
            raise RuntimeError("compiler failed")

    class _FailingYara:
        def analyze(self, custom_rules: str | None = None) -> list[dict[str, Any]]:
            raise RuntimeError("yara failed")

    failing_by_name = {
        "packer_detector": _FailingPacker,
        "compiler_detector": _FailingCompiler,
        "yara_analyzer": _FailingYara,
    }
    registry = SimpleNamespace(
        get_analyzer_class=lambda name: failing_by_name.get(name),
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
        def analyze(self) -> dict[str, str]:
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


def test_analysis_service_add_statistics_and_schema_validation() -> None:
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

    with env_vars(R2INSPECT_VALIDATE_SCHEMAS="1"):
        service.validate_results({"pe": {"some": "value"}})
    assert conversions == [("pe", {"some": "value"}, False)]


def test_analysis_service_circuit_breaker_detection() -> None:
    assert not AnalysisService.has_circuit_breaker_data({})
    assert AnalysisService.has_circuit_breaker_data({"breaker": 1})
    assert AnalysisService.has_circuit_breaker_data({"nested": {"state": "open"}})


def test_validators_exception_paths(tmp_path: Path) -> None:
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

    raises_cls = cast(Any, _RaisesValueErrorValidator)
    path_cls = cast(Any, _PathValidator)

    # filename check: security branch
    assert validators.validate_file_input("bad.bin", file_validator_cls=raises_cls) == [
        "File path security validation failed: no"
    ]

    # filename check: simulated runtime error branch
    with env_vars(R2INSPECT_TEST_RAISE_FILE_ERROR="1"):
        assert validators.validate_file_input("any.bin", file_validator_cls=path_cls) == [
            "File access error: Simulated file access error"
        ]

    # batch check: security / runtime branches
    assert validators.validate_batch_input("bad-batch", file_validator_cls=raises_cls) == [
        "Batch directory security validation failed: no"
    ]
    with env_vars(R2INSPECT_TEST_RAISE_BATCH_ERROR="1"):
        assert validators.validate_batch_input("anydir", file_validator_cls=path_cls) == [
            "Batch directory access error: Simulated batch access error"
        ]


def test_validate_output_input_permission_error(tmp_path: Path) -> None:
    output_file = tmp_path / "locked.txt"
    output_file.write_text("x")

    original_mode = output_file.stat().st_mode
    # Real read-only file: open(path, "a") raises PermissionError for real,
    # exercising the actual except branch without patching builtins.open.
    output_file.chmod(0o000)
    try:
        assert validators.validate_output_input(str(output_file)) == [
            f"Cannot write to output file: {output_file}"
        ]
    finally:
        output_file.chmod(original_mode)

    assert validators.validate_output_input(str(tmp_path / "dir_without_file")) == []


def test_cli_main_list_yara_invokes_config_command(tmp_path: Path) -> None:
    calls: list[tuple[str | None, str | None]] = []

    def fake_list_yara(config: str | None, yara: str | None) -> None:
        calls.append((config, yara))
        raise SystemExit(0)

    # A real existing directory makes validate_inputs pass naturally, so the
    # list-yara branch is reached without patching the validators; the
    # list_yara_fn DI seam captures the terminal call.
    yara_dir = tmp_path / "rules"
    yara_dir.mkdir()

    with pytest.raises(SystemExit) as exc:
        run_cli(
            CLIArgs(**_cli_kwargs(list_yara=True, yara=str(yara_dir))),
            list_yara_fn=fake_list_yara,
        )
    assert exc.value.code == 0
    assert calls == [(None, str(yara_dir))]


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
