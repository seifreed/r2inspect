from __future__ import annotations

from types import SimpleNamespace

import pytest

import r2inspect.cli_main as cli_main


class FakeCommand:
    def __init__(self, context):
        self.context = context
        self.calls: list[dict[str, object]] = []

    def execute(self, args: dict[str, object]) -> int:
        self.calls.append(args)
        return 0


def _args(**overrides):
    base = {
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


def test_run_cli_sanitizes_xor_and_dispatches_without_validation_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dispatched: list[tuple[object, cli_main.CLIArgs]] = []
    context = SimpleNamespace(kind="context")

    monkeypatch.setattr(cli_main, "validate_inputs", lambda *_a, **_k: [])
    monkeypatch.setattr(cli_main, "validate_input_mode", lambda *_a, **_k: None)
    monkeypatch.setattr(cli_main, "print_banner", lambda: None)
    monkeypatch.setattr(cli_main, "handle_xor_input", lambda value: "decoded" if value else None)
    monkeypatch.setattr(cli_main, "_build_context", lambda *_a, **_k: context)
    monkeypatch.setattr(
        cli_main, "_dispatch_command", lambda ctx, args: dispatched.append((ctx, args))
    )

    cli_main.run_cli(_args(xor="414243"))

    assert dispatched
    dispatched_context, dispatched_args = dispatched[0]
    assert dispatched_context is context
    assert dispatched_args.xor == "decoded"


def test_run_cli_displays_validation_errors_and_exits(monkeypatch: pytest.MonkeyPatch) -> None:
    displayed: list[list[str]] = []

    monkeypatch.setattr(cli_main, "validate_inputs", lambda *_a, **_k: ["bad-input"])
    monkeypatch.setattr(
        cli_main, "display_validation_errors", lambda errors: displayed.append(errors)
    )

    with pytest.raises(SystemExit) as exc:
        cli_main.run_cli(_args())

    assert exc.value.code == 1
    assert displayed == [["bad-input"]]


def test_dispatch_command_routes_to_analyze_when_not_batch_or_interactive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[FakeCommand] = []

    def fake_analyze(context):
        cmd = FakeCommand(context)
        created.append(cmd)
        return cmd

    monkeypatch.setattr(cli_main, "AnalyzeCommand", fake_analyze)
    monkeypatch.setattr(
        cli_main,
        "BatchCommand",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("batch not expected")),
    )
    monkeypatch.setattr(
        cli_main,
        "InteractiveCommand",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("interactive not expected")),
    )

    with pytest.raises(SystemExit) as exc:
        cli_main._dispatch_command(SimpleNamespace(kind="ctx"), _args())

    assert exc.value.code == 0
    assert created and created[0].calls


def test_build_context_uses_thread_safe_mode_for_batch(monkeypatch: pytest.MonkeyPatch) -> None:
    created: list[dict[str, object]] = []

    def fake_create(**kwargs):
        created.append(kwargs)
        return SimpleNamespace()

    monkeypatch.setattr(cli_main.CommandContext, "create", staticmethod(fake_create))

    cli_main._build_context(verbose=True, quiet=False, batch="/tmp/batch")
    cli_main._build_context(verbose=False, quiet=False, batch=None)

    assert created[0]["thread_safe"] is True
    assert created[1]["thread_safe"] is False


def test_dispatch_command_routes_to_batch_and_interactive(monkeypatch: pytest.MonkeyPatch) -> None:
    batch_created: list[FakeCommand] = []
    interactive_created: list[FakeCommand] = []

    def fake_batch(context):
        cmd = FakeCommand(context)
        batch_created.append(cmd)
        return cmd

    def fake_interactive(context):
        cmd = FakeCommand(context)
        interactive_created.append(cmd)
        return cmd

    monkeypatch.setattr(cli_main, "BatchCommand", fake_batch)
    monkeypatch.setattr(cli_main, "InteractiveCommand", fake_interactive)
    monkeypatch.setattr(
        cli_main,
        "AnalyzeCommand",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("analyze not expected")),
    )

    with pytest.raises(SystemExit) as exc:
        cli_main._dispatch_command(SimpleNamespace(kind="ctx"), _args(batch="/tmp/batch"))
    assert exc.value.code == 0

    with pytest.raises(SystemExit) as exc:
        cli_main._dispatch_command(SimpleNamespace(kind="ctx"), _args(interactive=True))
    assert exc.value.code == 0

    assert batch_created and batch_created[0].calls
    assert interactive_created and interactive_created[0].calls


def test_cli_shortcuts_and_main_error_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    version_calls: list[str] = []
    yara_calls: list[tuple[object, object]] = []

    monkeypatch.setattr(
        cli_main,
        "VersionCommand",
        lambda: SimpleNamespace(execute=lambda _args: version_calls.append("v") or 0),
    )
    monkeypatch.setattr(
        cli_main,
        "ConfigCommand",
        lambda: SimpleNamespace(execute=lambda args: yara_calls.append((None, args)) or 0),
    )

    with pytest.raises(SystemExit) as exc:
        cli_main._execute_version()
    assert exc.value.code == 0

    with pytest.raises(SystemExit) as exc:
        cli_main._execute_list_yara(None, None)
    assert exc.value.code == 0
    assert version_calls == ["v"]
    assert len(yara_calls) == 1

    printed: list[tuple[tuple[object, ...], dict[str, object]]] = []
    monkeypatch.setattr(
        cli_main.console, "print", lambda *args, **kwargs: printed.append((args, kwargs))
    )
    monkeypatch.setattr(
        cli_main, "run_cli", lambda *_a, **_k: (_ for _ in ()).throw(KeyboardInterrupt())
    )

    with pytest.raises(SystemExit) as exc:
        cli_main.main(
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
    assert printed
