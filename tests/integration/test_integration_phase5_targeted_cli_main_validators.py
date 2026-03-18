from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from r2inspect.cli import validators
from r2inspect.cli.commands.base import CommandContext
from r2inspect.cli_main import CLIArgs, _build_context, _dispatch_command, main, run_cli


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


def test_main_uses_run_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_run_cli(args: CLIArgs) -> None:
        captured["args"] = args

    monkeypatch.setattr("r2inspect.cli_main.run_cli", fake_run_cli)
    kwargs = _cli_kwargs(filename="sample.bin")
    main(**kwargs)
    assert isinstance(captured["args"], CLIArgs)
    assert captured["args"].filename == "sample.bin"


def test_main_handles_keyboard_interrupt(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run_cli(_: CLIArgs) -> None:
        raise KeyboardInterrupt()

    monkeypatch.setattr("r2inspect.cli_main.run_cli", fake_run_cli)
    exit_called: list[int] = []

    def fake_exit(code: int) -> None:
        exit_called.append(code)

    monkeypatch.setattr("sys.exit", fake_exit)
    main(**_cli_kwargs())
    assert exit_called == [1]


def test_main_handles_generic_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    error = RuntimeError("boom")

    def fake_run_cli(_: CLIArgs) -> None:
        raise error

    monkeypatch.setattr("r2inspect.cli_main.run_cli", fake_run_cli)
    captured: dict[str, Any] = {}

    def fake_handle_main_error(exc: Exception, verbose: bool) -> None:
        captured["exc"] = exc
        captured["verbose"] = verbose

    monkeypatch.setattr("r2inspect.cli_main.handle_main_error", fake_handle_main_error)
    main(**_cli_kwargs())
    assert captured["exc"] is error
    assert captured["verbose"] is False


def test_run_cli_version_short_circuits(monkeypatch: pytest.MonkeyPatch) -> None:
    version_calls: list[str] = []
    fake_exit_codes: list[int] = []

    def fake_exit(code: int = 0) -> None:
        fake_exit_codes.append(code)
        raise SystemExit(code)

    def fake_execute_version() -> None:
        version_calls.append("version")
        fake_exit(0)

    monkeypatch.setattr("r2inspect.cli_main._execute_version", fake_execute_version)
    monkeypatch.setattr("r2inspect.cli_main.sys.exit", fake_exit)

    with pytest.raises(SystemExit):
        run_cli(CLIArgs(**_cli_kwargs(version=True, filename="/tmp/a")))
    assert version_calls == ["version"]
    assert fake_exit_codes == [0]


def test_run_cli_with_validation_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "r2inspect.cli_main.validate_inputs",
        lambda *_args, **_kwargs: ["bad input"],
    )
    exit_mock = pytest.raises(SystemExit, match="1")

    displayed: dict[str, list[str]] = {}

    def fake_exit(code: int) -> None:
        raise SystemExit(code)

    def fake_display(errors: list[str]) -> None:
        displayed["errors"] = errors

    monkeypatch.setattr("sys.exit", fake_exit)
    monkeypatch.setattr("r2inspect.cli_main.display_validation_errors", fake_display)

    with exit_mock:
        run_cli(CLIArgs(**_cli_kwargs(filename="/tmp/a")))
    assert displayed["errors"] == ["bad input"]


def test_run_cli_dispatch_batch_command(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("r2inspect.cli_main.validate_inputs", lambda *_args, **_kwargs: [])
    monkeypatch.setattr("r2inspect.cli_main.validate_input_mode", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("r2inspect.cli_main.handle_xor_input", lambda value: value)

    captured = {}

    class FakeCommand:
        def __init__(self, _context: Any) -> None:
            captured["init"] = True

        def execute(self, payload: dict[str, Any]) -> int:
            captured["payload"] = payload
            return 7

    monkeypatch.setattr("r2inspect.cli_main.BatchCommand", FakeCommand)
    monkeypatch.setattr("r2inspect.cli_main.VersionCommand", FakeCommand)
    monkeypatch.setattr("r2inspect.cli_main.InteractiveCommand", FakeCommand)
    monkeypatch.setattr("r2inspect.cli_main.AnalyzeCommand", FakeCommand)
    exit_code: list[int] = []

    def fake_exit(code: int = 0) -> None:
        exit_code.append(code)
        raise SystemExit(code)

    monkeypatch.setattr("r2inspect.cli_main.sys.exit", fake_exit)

    with pytest.raises(SystemExit) as exc_info:
        run_cli(
            CLIArgs(
                **_cli_kwargs(
                    batch="/tmp",
                    threads=4,
                    verbose=True,
                    quiet=True,
                    interactive=False,
                    output_json=True,
                )
            )
        )
    assert captured.get("init") is True
    assert exit_code == [7]
    assert exc_info.value.code == 7
    assert captured["payload"]["batch"] == "/tmp"
    assert captured["payload"]["threads"] == 4


def test_run_cli_dispatch_interactive_and_analyze(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("r2inspect.cli_main.validate_inputs", lambda *_args, **_kwargs: [])
    monkeypatch.setattr("r2inspect.cli_main.validate_input_mode", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("r2inspect.cli_main.handle_xor_input", lambda value: value)
    captured = {}

    class FakeCommand:
        def __init__(self, _context: Any) -> None:
            captured.setdefault("calls", []).append(self.__class__.__name__)

        def execute(self, payload: dict[str, Any]) -> int:
            captured.setdefault("payloads", []).append(payload)
            return 3

    monkeypatch.setattr("r2inspect.cli_main.InteractiveCommand", FakeCommand)
    monkeypatch.setattr("r2inspect.cli_main.AnalyzeCommand", FakeCommand)
    monkeypatch.setattr("r2inspect.cli_main.BatchCommand", FakeCommand)
    pytest.MonkeyPatch()

    monkeypatch.setattr("sys.exit", lambda code=1: (_ for _ in ()).throw(SystemExit(code)))
    with pytest.raises(SystemExit):
        run_cli(CLIArgs(**_cli_kwargs(interactive=True, filename="/tmp/file")))
    with pytest.raises(SystemExit):
        run_cli(CLIArgs(**_cli_kwargs(filename="/tmp/file")))

    assert captured["calls"] == ["FakeCommand", "FakeCommand"]


def test_build_context_configures_batch_flag_for_batch_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_create(
        *, config=None, verbose: bool = False, quiet: bool = False, thread_safe: bool = False
    ) -> CommandContext:
        captured["verbose"] = verbose
        captured["quiet"] = quiet
        captured["thread_safe"] = thread_safe
        return CommandContext(
            console=SimpleNamespace(),
            logger=SimpleNamespace(),
            config=config,
            verbose=verbose,
            quiet=quiet,
        )

    monkeypatch.setattr("r2inspect.cli_main.CommandContext.create", fake_create)
    context = _build_context(verbose=True, quiet=False, batch="/tmp")
    assert context.verbose is True
    assert context.quiet is False
    assert captured["thread_safe"] is True


def test_build_context_configures_non_batch_flag_for_single_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_create(
        *, config=None, verbose: bool = False, quiet: bool = False, thread_safe: bool = False
    ) -> CommandContext:
        captured["verbose"] = verbose
        captured["quiet"] = quiet
        captured["thread_safe"] = thread_safe
        return CommandContext(
            console=SimpleNamespace(),
            logger=SimpleNamespace(),
            config=config,
            verbose=verbose,
            quiet=quiet,
        )

    monkeypatch.setattr("r2inspect.cli_main.CommandContext.create", fake_create)
    context = _build_context(verbose=False, quiet=True, batch=None)
    assert context.verbose is False
    assert context.quiet is True
    assert captured["thread_safe"] is False


def test_validate_input_mode_requires_one_of_filename_or_batch() -> None:
    with pytest.raises(SystemExit):
        validators.validate_input_mode(filename=None, batch=None)


def test_validate_input_mode_rejects_both_filename_and_batch() -> None:
    with pytest.raises(SystemExit):
        validators.validate_input_mode(filename="a.bin", batch="/tmp")


def test_validate_input_mode_no_errors_for_file_like_path(tmp_path: Path) -> None:
    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(b"hello")
    validators.validate_input_mode(str(file_path), batch=None)


def test_validate_input_mode_errors_for_missing_file() -> None:
    with pytest.raises(SystemExit):
        validators.validate_input_mode("/does/not/exist.bin", batch=None)


def test_handle_xor_input_returns_warningless_value(monkeypatch: pytest.MonkeyPatch) -> None:
    recorded: list[str] = []

    monkeypatch.setattr(
        "r2inspect.cli.validators.console",
        SimpleNamespace(print=lambda message: recorded.append(str(message))),
    )

    assert validators.handle_xor_input("abcXYZ") == "abcXYZ"
    assert recorded == []


def test_handle_xor_input_filters_invalid_chars(monkeypatch: pytest.MonkeyPatch) -> None:
    recorded: list[str] = []

    monkeypatch.setattr(
        "r2inspect.cli.validators.console",
        SimpleNamespace(print=lambda message: recorded.append(str(message))),
    )

    assert validators.handle_xor_input("!@#") is None
    assert recorded and "Warning" in recorded[0]


def test_validate_extensions_input_long_and_invalid_tokens() -> None:
    assert any(
        "Invalid file extension" in e for e in validators.validate_extensions_input("$bad,.bin")
    )
    assert any("too long" in e for e in validators.validate_extensions_input("a" * 11))
