#!/usr/bin/env python3
"""Phase A baseline coverage smoke tests.

NO mocks, NO @patch, NO MagicMock. Uses real objects and monkeypatch only.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from r2inspect import cli_main
from r2inspect.cli_main import CLIArgs, _build_context, _dispatch_command, main
from r2inspect.error_handling import classifier as error_handler
from r2inspect.infrastructure import command_helpers, r2_helpers, r2_session
from r2inspect.cli import validators
from r2inspect.infrastructure.circuit_breaker import CircuitBreaker, CircuitState


def _make_args(**overrides: Any) -> CLIArgs:
    base = {
        "filename": None,
        "interactive": False,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "xor": None,
        "verbose": False,
        "quiet": True,
        "config": None,
        "yara": None,
        "batch": None,
        "extensions": None,
        "list_yara": False,
        "threads": 2,
        "version": False,
    }
    base.update(overrides)
    return CLIArgs(**base)


def test_main_keyboard_interrupt_exits_with_code_one(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main, "run_cli", lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt())
    )

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 1


def test_run_cli_cli_command_version_and_invalid_flags() -> None:
    runner = CliRunner()
    version_result = runner.invoke(cli_main.cli, ["--version"])
    assert version_result.exit_code == 0

    invalid_result = runner.invoke(cli_main.cli, ["--no-such-option"])
    assert invalid_result.exit_code == 2
    assert "No such option" in invalid_result.output


class _FakeCommand:
    """Lightweight Command stand-in that returns a fixed exit code."""

    def __init__(self, exit_code: int) -> None:
        self._exit_code = exit_code
        self.execute_called = False
        self.execute_args: dict[str, Any] | None = None

    def execute(self, args: dict[str, Any]) -> int:
        self.execute_called = True
        self.execute_args = args
        return self._exit_code


@pytest.mark.parametrize(
    ("kwargs", "expected_exit"),
    [
        ({"batch": "/tmp/batch"}, 11),
        ({"interactive": True, "filename": "file.bin"}, 12),
        ({"filename": "file.bin"}, 13),
    ],
)
def test_dispatch_command_routes_to_expected_command(
    kwargs: dict[str, Any],
    expected_exit: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from r2inspect.cli.cli_entry import CommandDispatch

    ctx = _build_context(verbose=False, quiet=True, batch=kwargs.get("batch"))
    args = _make_args(**kwargs)
    args.xor = None

    fake = _FakeCommand(expected_exit)

    # Replace build_dispatch at the cli_main module level (where it's imported)
    def _fake_dispatch(_context, _args):
        return CommandDispatch(command=fake, payload={})

    monkeypatch.setattr(cli_main, "build_dispatch", _fake_dispatch)

    with pytest.raises(SystemExit) as exc:
        _dispatch_command(ctx, args)

    assert exc.value.code == expected_exit
    assert fake.execute_called


def test_validate_output_and_extensions_and_file_inputs(tmp_path: Path) -> None:
    output_parent = tmp_path / "invalid_parent"
    output_parent.write_text("blocked")
    bad_output = output_parent / "report"
    errors = validators.validate_output_input(str(bad_output))
    assert any("Output parent path is not a directory" in error for error in errors)

    errors = validators.validate_extensions_input("good, bad$ext")
    assert any("Invalid file extension" in error for error in errors)

    test_file = tmp_path / "sample.bin"
    test_file.write_text("", encoding="utf-8")

    old_val = os.environ.get("R2INSPECT_TEST_RAISE_FILE_ERROR")
    try:
        os.environ["R2INSPECT_TEST_RAISE_FILE_ERROR"] = "1"
        access_errors = validators.validate_file_input(str(test_file))
    finally:
        if old_val is None:
            os.environ.pop("R2INSPECT_TEST_RAISE_FILE_ERROR", None)
        else:
            os.environ["R2INSPECT_TEST_RAISE_FILE_ERROR"] = old_val

    assert any("File access error" in error for error in access_errors)


def test_canonical_modules_export_expected_objects() -> None:
    assert callable(command_helpers.cmd)
    assert callable(command_helpers.cmdj)
    assert callable(command_helpers.cmd_list)
    assert callable(r2_helpers.cmd)
    assert hasattr(r2_helpers, "cmd")
    assert hasattr(r2_helpers, "safe_cmd_list")
    assert r2_session.R2Session.__name__ == "R2Session"


def test_error_handler_exports_classifier_api() -> None:
    for symbol in (
        "ErrorCategory",
        "ErrorClassifier",
        "ErrorInfo",
        "safe_execute",
        "error_handler",
        "get_error_stats",
        "reset_error_stats",
    ):
        assert hasattr(error_handler, symbol)


def test_circuit_breaker_open_half_open_closed_transition() -> None:
    breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=0.0, name="phase_a")

    with pytest.raises(ValueError):
        breaker.call(lambda: (_ for _ in ()).throw(ValueError("boom")))

    assert breaker.state == CircuitState.OPEN

    assert breaker.call(lambda: "ok") == "ok"
    assert breaker.state == CircuitState.CLOSED
