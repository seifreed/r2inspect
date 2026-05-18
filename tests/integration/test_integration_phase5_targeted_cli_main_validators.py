from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from r2inspect.cli import validators
from r2inspect.cli.cli_entry import build_dispatch
from r2inspect.cli.commands import AnalyzeCommand, BatchCommand, InteractiveCommand
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


def test_main_uses_run_cli() -> None:
    captured: dict[str, Any] = {}

    def fake_run_cli(args: CLIArgs) -> None:
        captured["args"] = args

    main(run_cli_fn=fake_run_cli, **_cli_kwargs(filename="sample.bin"))
    assert isinstance(captured["args"], CLIArgs)
    assert captured["args"].filename == "sample.bin"


def test_main_handles_keyboard_interrupt() -> None:
    def fake_run_cli(_: CLIArgs) -> None:
        raise KeyboardInterrupt()

    with pytest.raises(SystemExit) as exc:
        main(run_cli_fn=fake_run_cli, **_cli_kwargs())
    assert exc.value.code == 1


def test_main_handles_generic_exception() -> None:
    error = RuntimeError("boom")

    def fake_run_cli(_: CLIArgs) -> None:
        raise error

    captured: dict[str, Any] = {}

    def fake_handle_main_error(exc: Exception, verbose: bool) -> None:
        captured["exc"] = exc
        captured["verbose"] = verbose

    main(
        run_cli_fn=fake_run_cli,
        error_handler_fn=fake_handle_main_error,
        **_cli_kwargs(),
    )
    assert captured["exc"] is error
    assert captured["verbose"] is False


def test_run_cli_version_short_circuits() -> None:
    # Real _execute_version runs VersionCommand (prints, returns 0) and
    # sys.exit(0); no patching needed.
    with pytest.raises(SystemExit) as exc:
        run_cli(CLIArgs(**_cli_kwargs(version=True, filename="/tmp/a")))
    assert exc.value.code == 0


def test_run_cli_with_validation_errors(tmp_path: Path) -> None:
    # A real nonexistent file produces a genuine validation error, so
    # run_cli displays it and exits 1 through the real path.
    missing = tmp_path / "nope.bin"
    with pytest.raises(SystemExit) as exc:
        run_cli(CLIArgs(**_cli_kwargs(filename=str(missing))))
    assert exc.value.code == 1


def test_build_dispatch_routes_batch_command() -> None:
    # The {Batch,Interactive,Analyze}Command classes are constructed in
    # cli.cli_entry.build_dispatch, not the cli_main module (an old refactor
    # moved them). Drive the real dispatch builder — no patching — and
    # assert the actual command selection + payload contract.
    ctx = CommandContext.create(config=None, verbose=True, quiet=True, thread_safe=True)
    args = CLIArgs(
        **_cli_kwargs(
            batch="/tmp",
            threads=4,
            verbose=True,
            quiet=True,
            interactive=False,
            output_json=True,
        )
    )
    dispatch = build_dispatch(ctx, args)
    assert isinstance(dispatch.command, BatchCommand)
    assert dispatch.payload["batch"] == "/tmp"
    assert dispatch.payload["threads"] == 4
    assert dispatch.payload["output_json"] is True
    assert dispatch.payload["verbose"] is True
    assert dispatch.payload["quiet"] is True


def test_build_dispatch_routes_interactive_then_analyze() -> None:
    ctx = CommandContext.create(config=None, verbose=False, quiet=False, thread_safe=False)

    interactive = build_dispatch(
        ctx, CLIArgs(**_cli_kwargs(interactive=True, filename="/tmp/file"))
    )
    assert isinstance(interactive.command, InteractiveCommand)
    assert interactive.payload["filename"] == "/tmp/file"

    analyze = build_dispatch(ctx, CLIArgs(**_cli_kwargs(filename="/tmp/file")))
    assert isinstance(analyze.command, AnalyzeCommand)
    assert analyze.payload["filename"] == "/tmp/file"


def _recording_context_factory(
    captured: dict[str, Any],
) -> Any:
    def fake_create(
        *, config: Any = None, verbose: bool = False, quiet: bool = False, thread_safe: bool = False
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

    return fake_create


def test_build_context_configures_batch_flag_for_batch_mode() -> None:
    captured: dict[str, Any] = {}
    context = _build_context(
        verbose=True,
        quiet=False,
        batch="/tmp",
        context_factory=_recording_context_factory(captured),
    )
    assert context.verbose is True
    assert context.quiet is False
    assert captured["thread_safe"] is True


def test_build_context_configures_non_batch_flag_for_single_file() -> None:
    captured: dict[str, Any] = {}
    context = _build_context(
        verbose=False,
        quiet=True,
        batch=None,
        context_factory=_recording_context_factory(captured),
    )
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


def test_handle_xor_input_returns_warningless_value() -> None:
    recorded: list[str] = []
    rec_console = SimpleNamespace(print=lambda message: recorded.append(str(message)))

    assert validators.handle_xor_input("abcXYZ", console_obj=rec_console) == "abcXYZ"
    assert recorded == []


def test_handle_xor_input_filters_invalid_chars() -> None:
    recorded: list[str] = []
    rec_console = SimpleNamespace(print=lambda message: recorded.append(str(message)))

    assert validators.handle_xor_input("!@#", console_obj=rec_console) is None
    assert recorded and "Warning" in recorded[0]


def test_validate_extensions_input_long_and_invalid_tokens() -> None:
    assert any(
        "Invalid file extension" in e for e in validators.validate_extensions_input("$bad,.bin")
    )
    assert any("too long" in e for e in validators.validate_extensions_input("a" * 11))
