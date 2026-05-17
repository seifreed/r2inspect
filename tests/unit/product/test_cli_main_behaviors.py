from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console

import r2inspect.cli_main as cli_main
from r2inspect.cli.cli_entry import CommandDispatch, build_dispatch
from r2inspect.cli.commands import (
    AnalyzeCommand,
    BatchCommand,
    Command,
    CommandContext,
    InteractiveCommand,
)
from r2inspect.cli.validators import handle_xor_input


class RecordingCommand(Command):
    """Hand-rolled Command double that records the payload it executes."""

    def __init__(self, context: CommandContext | None = None, *, exit_code: int = 0) -> None:
        super().__init__(context)
        self._exit_code = exit_code
        self.calls: list[dict[str, Any]] = []

    def execute(self, args: dict[str, Any]) -> int:
        self.calls.append(args)
        return self._exit_code


def _make_context() -> CommandContext:
    return CommandContext(console=Console(), logger=logging.getLogger("test-cli-main"))


def _args(**overrides: Any) -> cli_main.CLIArgs:
    base: dict[str, Any] = {
        "filename": "/tmp/sample.bin",
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
        "threads": 4,
        "version": False,
    }
    return cli_main.CLIArgs(**(base | overrides))


def test_run_cli_sanitizes_xor_and_dispatches_without_validation_errors(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ" + b"\x00" * 256)

    dispatched: list[tuple[CommandContext, cli_main.CLIArgs]] = []

    def fake_dispatch(ctx: CommandContext, args: cli_main.CLIArgs) -> None:
        dispatched.append((ctx, args))

    cli_main.run_cli(
        _args(filename=str(sample), xor="414243", output_json=True),
        dispatch_fn=fake_dispatch,
    )

    assert dispatched
    dispatched_context, dispatched_args = dispatched[0]
    assert isinstance(dispatched_context, CommandContext)
    # run_cli must forward the sanitized xor (real sanitizer is the oracle).
    assert dispatched_args.xor == handle_xor_input("414243")


def test_run_cli_displays_validation_errors_and_exits(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli_main.run_cli(_args(filename="/nonexistent/zzz_missing_dir/zzz_missing.bin"))

    assert exc.value.code == 1
    assert "Error:" in capsys.readouterr().out


def test_dispatch_command_routes_to_analyze_when_not_batch_or_interactive() -> None:
    dispatch = build_dispatch(_make_context(), _args())
    assert isinstance(dispatch.command, AnalyzeCommand)
    assert dispatch.payload["filename"] == "/tmp/sample.bin"

    recording = RecordingCommand()

    def fake_build(ctx: CommandContext, args: cli_main.CLIArgs) -> CommandDispatch:
        return CommandDispatch(command=recording, payload={"filename": args.filename})

    with pytest.raises(SystemExit) as exc:
        cli_main._dispatch_command(_make_context(), _args(), build_dispatch_fn=fake_build)

    assert exc.value.code == 0
    assert recording.calls == [{"filename": "/tmp/sample.bin"}]


def test_build_context_uses_thread_safe_mode_for_batch() -> None:
    recorded: list[dict[str, Any]] = []

    def recording_factory(**kwargs: Any) -> CommandContext:
        recorded.append(kwargs)
        return _make_context()

    cli_main._build_context(True, False, "/tmp/batch", context_factory=recording_factory)
    cli_main._build_context(False, False, None, context_factory=recording_factory)

    assert recorded[0]["thread_safe"] is True
    assert recorded[1]["thread_safe"] is False


def test_dispatch_command_routes_to_batch_and_interactive() -> None:
    batch_dispatch = build_dispatch(_make_context(), _args(batch="/tmp/batch"))
    assert isinstance(batch_dispatch.command, BatchCommand)
    assert batch_dispatch.payload["batch"] == "/tmp/batch"

    interactive_dispatch = build_dispatch(_make_context(), _args(interactive=True))
    assert isinstance(interactive_dispatch.command, InteractiveCommand)
    assert interactive_dispatch.payload["filename"] == "/tmp/sample.bin"

    batch_cmd = RecordingCommand()
    interactive_cmd = RecordingCommand()

    with pytest.raises(SystemExit) as exc:
        cli_main._dispatch_command(
            _make_context(),
            _args(batch="/tmp/batch"),
            build_dispatch_fn=lambda c, a: CommandDispatch(command=batch_cmd, payload={"b": 1}),
        )
    assert exc.value.code == 0

    with pytest.raises(SystemExit) as exc:
        cli_main._dispatch_command(
            _make_context(),
            _args(interactive=True),
            build_dispatch_fn=lambda c, a: CommandDispatch(
                command=interactive_cmd, payload={"i": 1}
            ),
        )
    assert exc.value.code == 0

    assert batch_cmd.calls == [{"b": 1}]
    assert interactive_cmd.calls == [{"i": 1}]


def test_cli_shortcuts_and_main_error_paths(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli_main._execute_version()
    assert exc.value.code == 0
    assert "r2inspect" in capsys.readouterr().out

    with pytest.raises(SystemExit) as exc:
        cli_main._execute_list_yara(None, None)
    assert exc.value.code == 0
    assert "Rules directory" in capsys.readouterr().out

    def interrupt_runner(_args: cli_main.CLIArgs) -> None:
        raise KeyboardInterrupt

    with pytest.raises(SystemExit) as exc:
        cli_main.main(
            run_cli_fn=interrupt_runner,
            filename=None,
            interactive=False,
            output_json=False,
            output_csv=False,
            output=None,
            xor=None,
            verbose=False,
            quiet=False,
            config=None,
            yara=None,
            batch=None,
            extensions=None,
            list_yara=False,
            threads=1,
            version=False,
        )
    assert exc.value.code == 1
    assert "interrupted" in capsys.readouterr().out.lower()
