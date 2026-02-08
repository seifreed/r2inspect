from __future__ import annotations

import builtins
import io
import sys
from pathlib import Path

from r2inspect.cli.analysis_runner import has_circuit_breaker_data, output_results
from r2inspect.cli.commands.analyze_command import AnalyzeCommand
from r2inspect.cli.commands.base import Command, CommandContext, configure_quiet_logging
from r2inspect.cli.commands.batch_command import BatchCommand
from r2inspect.cli.commands.interactive_command import InteractiveCommand
from r2inspect.cli.display_base import print_banner
from r2inspect.cli.validators import (
    display_validation_errors,
    validate_batch_input,
    validate_file_input,
    validate_output_input,
)
from r2inspect.error_handling.policies import ErrorHandlingStrategy, ErrorPolicy
from r2inspect.error_handling.unified_handler import handle_errors, reset_circuit_breakers
from r2inspect.utils.error_handler import reset_error_stats, safe_execute
from r2inspect.utils.output import OutputFormatter
from r2inspect.utils.retry_manager import global_retry_manager, reset_retry_stats


class _DummyInspector:
    def __init__(self, raise_strings: bool = False) -> None:
        self._raise_strings = raise_strings

    def analyze(self, **_kwargs: object) -> dict[str, object]:
        return {"ok": True}

    def get_strings(self) -> list[str]:
        if self._raise_strings:
            raise RuntimeError("boom")
        return ["alpha", "beta"]

    def get_file_info(self) -> dict[str, object]:
        return {"name": "sample.bin"}

    def get_pe_info(self) -> dict[str, object]:
        return {"machine": "x86"}

    def get_imports(self) -> list[dict[str, object]]:
        return [{"name": "CreateFileA"}]

    def get_exports(self) -> list[dict[str, object]]:
        return [{"name": "ExportedFunc"}]

    def get_sections(self) -> list[dict[str, object]]:
        return [{"name": ".text", "entropy": 6.1}]


class _AnalyzeCommandStats(AnalyzeCommand):
    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self._stats = (
            {"total_errors": 1},
            {"total_retries": 1},
            {"breaker_stats": 1},
        )

    def _collect_statistics(self) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        return self._stats


class _AnalyzeCommandVerboseStats(AnalyzeCommand):
    def _collect_statistics(self) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        return (
            {
                "total_errors": 1,
                "recent_errors": 1,
                "errors_by_category": {"analysis": 1},
                "errors_by_severity": {"high": 1},
                "recovery_strategies_available": 1,
            },
            {
                "total_retries": 1,
                "successful_retries": 1,
                "failed_after_retries": 0,
                "commands_retried": {"aaa": 1},
                "error_types_retried": {"OSError": 1},
                "success_rate": 100.0,
            },
            {"breaker_example": {"state": "open", "failure_count": 2}},
        )


class _BatchCommandError(BatchCommand):
    def _run_batch_analysis(self, *args: object, **kwargs: object) -> None:
        raise RuntimeError("batch boom")


class _BatchCommandInterrupt(BatchCommand):
    def _run_batch_analysis(self, *args: object, **kwargs: object) -> None:
        raise KeyboardInterrupt()


class _CommandHarness(Command):
    def execute(self, args: dict[str, object]) -> int:  # pragma: no cover - required by abstract
        return 0


class _DummyInspectorContext:
    def __init__(self, inspector: _DummyInspector) -> None:
        self._inspector = inspector

    def __enter__(self) -> _DummyInspector:
        return self._inspector

    def __exit__(self, *_args: object) -> bool:
        return False


def test_analyze_command_error_and_outputs(tmp_path: Path) -> None:
    context = CommandContext.create()
    cmd = _AnalyzeCommandStats(context=context)

    results: dict[str, object] = {}
    cmd._add_statistics_to_results(results)
    assert "error_statistics" in results
    assert "retry_statistics" in results
    assert "circuit_breaker_statistics" in results

    formatter = OutputFormatter({"file_info": {"name": "sample.bin"}})
    json_out = tmp_path / "out.json"
    csv_out = tmp_path / "out.csv"
    cmd._output_json_results(formatter, json_out)
    cmd._output_csv_results(formatter, csv_out)
    cmd._output_json_results(formatter, None)
    cmd._output_csv_results(formatter, None)

    cmd._output_results({"file_info": {"name": "sample.bin"}}, True, False, json_out, False)
    cmd._output_results({"file_info": {"name": "sample.bin"}}, False, True, csv_out, False)
    cmd._output_results({"file_info": {"name": "sample.bin"}}, False, False, None, False)

    cmd._print_status_if_needed(False, False, None)
    cmd._print_status_if_needed(True, False, json_out)

    cmd._handle_error(RuntimeError("boom"), verbose=False)
    cmd._handle_error(RuntimeError("boom"), verbose=True)

    verbose_cmd = _AnalyzeCommandVerboseStats(context=context)
    verbose_cmd._output_console_results({"ok": True}, verbose=True)

    missing = AnalyzeCommand(context=context)
    result = missing.execute({"filename": "does-not-exist.bin", "verbose": True})
    assert result == 1

    import r2inspect.cli.commands.analyze_command as analyze_module

    original_create = analyze_module.create_inspector
    try:
        analyze_module.create_inspector = lambda **_kwargs: _DummyInspectorContext(  # type: ignore[assignment]
            _DummyInspector()
        )
        success = AnalyzeCommand(context=context)
        assert (
            success.execute(
                {
                    "filename": "sample.bin",
                    "config": None,
                    "yara": None,
                    "xor": None,
                    "output_json": False,
                    "output_csv": False,
                    "output": None,
                    "verbose": False,
                }
            )
            == 0
        )

        analyze_module.create_inspector = lambda **_kwargs: (_ for _ in ()).throw(  # type: ignore[assignment]
            KeyboardInterrupt()
        )
        assert (
            AnalyzeCommand(context=context).execute(
                {"filename": "sample.bin", "config": None, "verbose": False}
            )
            == 1
        )
    finally:
        analyze_module.create_inspector = original_create  # type: ignore[assignment]


def test_batch_command_error_and_logging(tmp_path: Path) -> None:
    context = CommandContext.create()
    cmd = _BatchCommandError(context=context)

    recursive, auto_detect, output_dir = cmd._setup_batch_mode(
        str(tmp_path), None, True, False, None
    )
    assert recursive is True
    assert auto_detect is True
    assert output_dir == "output"

    cmd._configure_batch_logging(verbose=False, quiet=True)
    cmd._handle_error(RuntimeError("boom"), verbose=False)
    cmd._handle_error(RuntimeError("boom"), verbose=True)

    result = cmd.execute(
        {
            "batch": str(tmp_path),
            "config": None,
            "yara": None,
            "xor": None,
            "output_json": False,
            "output_csv": False,
            "output": None,
            "extensions": None,
            "threads": 1,
            "verbose": False,
            "quiet": False,
        }
    )
    assert result == 1

    interrupt_cmd = _BatchCommandInterrupt(context=context)
    assert (
        interrupt_cmd.execute(
            {
                "batch": str(tmp_path),
                "config": None,
                "yara": None,
                "xor": None,
                "output_json": False,
                "output_csv": False,
                "output": None,
                "extensions": None,
                "threads": 1,
                "verbose": False,
                "quiet": False,
            }
        )
        == 1
    )


def test_interactive_command_flow_and_errors(tmp_path: Path) -> None:
    context = CommandContext.create()
    cmd = InteractiveCommand(context=context)

    inspector = _DummyInspector()
    cmd._execute_interactive_command("help", inspector, {})
    cmd._execute_interactive_command("info", inspector, {})
    cmd._execute_interactive_command("pe", inspector, {})
    cmd._execute_interactive_command("imports", inspector, {})
    cmd._execute_interactive_command("exports", inspector, {})
    cmd._execute_interactive_command("sections", inspector, {})
    cmd._execute_interactive_command("analyze", inspector, {})
    cmd._execute_interactive_command("unknown", inspector, {})

    original_stdin = sys.stdin
    try:
        sys.stdin = io.StringIO(" \nstrings\nquit\n")
        cmd._run_interactive_mode(_DummyInspector(raise_strings=True), {})
    finally:
        sys.stdin = original_stdin

    original_input = builtins.input
    try:
        builtins.input = lambda _prompt="": (_ for _ in ()).throw(EOFError())
        cmd._run_interactive_mode(_DummyInspector(), {})
    finally:
        builtins.input = original_input

    cmd._handle_error(RuntimeError("boom"), verbose=False)
    cmd._handle_error(RuntimeError("boom"), verbose=True)

    result = cmd.execute({"filename": "missing.bin", "config": None, "verbose": False})
    assert result == 1


def test_analysis_runner_circuit_detection_and_banner() -> None:
    assert has_circuit_breaker_data({"breaker": {"state": "open"}}) is True
    print_banner()


def test_command_base_config_and_output_results(tmp_path: Path) -> None:
    context = CommandContext.create()
    context.config = None
    cmd = _CommandHarness(context=context)
    assert cmd._get_config(None) is not None

    output_results({"file_info": {"name": "sample.bin"}}, False, True, None, False)

    output_file = tmp_path / "out.csv"
    output_results({"file_info": {"name": "sample.bin"}}, False, True, output_file, False)


def test_validate_output_input_paths(tmp_path: Path) -> None:
    output_file = tmp_path / "output.txt"
    output_file.write_text("x")
    assert validate_output_input(str(output_file)) == []

    parent_file = tmp_path / "notadir"
    parent_file.write_text("x")
    output_path = parent_file / "child"
    errors = validate_output_input(str(output_path))
    assert errors
    display_validation_errors(["bad"])


def test_cli_validators_error_branches(tmp_path: Path) -> None:
    errors = validate_file_input("bad\x00path")
    assert any("security validation failed" in err for err in errors)

    errors = validate_batch_input("bad\x00batch")
    assert any("security validation failed" in err for err in errors)

    temp_file = tmp_path / "target.bin"
    temp_file.write_bytes(b"data")

    class _TransientPath(type(temp_file)):
        def stat(self, *args: object, **kwargs: object) -> object:  # type: ignore[override]
            raise OSError("stat failed")

    class _TransientValidator:
        def validate_path(self, _filename: str, check_exists: bool = True) -> Path:
            return _TransientPath(str(temp_file))

    import r2inspect.cli.validators as validators_module

    original_validator = validators_module.FileValidator
    validators_module.FileValidator = _TransientValidator  # type: ignore[assignment]
    try:
        errors = validate_file_input(str(temp_file))
        assert any("File access error" in err for err in errors)
    finally:
        validators_module.FileValidator = original_validator  # type: ignore[assignment]

    class _FailingValidator:
        def validate_path(self, _filename: str, check_exists: bool = True) -> Path:
            raise RuntimeError("boom")

    validators_module.FileValidator = _FailingValidator  # type: ignore[assignment]
    try:
        errors = validate_batch_input(str(temp_file))
        assert any("Batch directory access error" in err for err in errors)
    finally:
        validators_module.FileValidator = original_validator  # type: ignore[assignment]

    configure_quiet_logging(False)
    harness = _CommandHarness(CommandContext.create(config=None))
    assert harness._get_config(None) is not None

    reset_error_stats()
    reset_retry_stats()
    reset_circuit_breakers()

    def _fail_once() -> None:
        raise ValueError("boom")

    safe_execute(_fail_once, fallback_result=None)

    attempts = {"count": 0}

    def _retry(**_kwargs: object) -> str:
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise OSError("transient")
        return "ok"

    global_retry_manager.retry_operation(_retry, command_type="generic", command="aaa")

    policy = ErrorPolicy(ErrorHandlingStrategy.CIRCUIT_BREAK, max_retries=0, circuit_threshold=1)

    @handle_errors(policy)
    def _circuit_fail() -> None:
        raise RuntimeError("fail")

    try:
        _circuit_fail()
    except RuntimeError:
        pass
