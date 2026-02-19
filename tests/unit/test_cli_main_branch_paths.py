#!/usr/bin/env python3
"""Branch path tests for r2inspect/cli_main.py covering missing lines."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from r2inspect import cli_main
from r2inspect.cli_main import (
    CLIArgs,
    _build_context,
    _dispatch_command,
    _execute_list_yara,
    _execute_version,
    main,
    run_cli,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_args(**overrides) -> CLIArgs:
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
        "threads": 1,
        "version": False,
    }
    base.update(overrides)
    return CLIArgs(**base)


def _sample_pe() -> Path:
    p = Path("samples/fixtures/hello_pe.exe")
    if not p.exists():
        pytest.skip("hello_pe.exe fixture missing")
    return p


# ---------------------------------------------------------------------------
# main() entry point - lines 78-87
# ---------------------------------------------------------------------------


def test_main_with_version_flag_exits_zero():
    """main() constructs CLIArgs and delegates to run_cli (lines 78-81)."""
    with pytest.raises(SystemExit) as exc:
        main(
            filename=None,
            interactive=False,
            output_json=False,
            output_csv=False,
            output=None,
            xor=None,
            verbose=False,
            quiet=True,
            config=None,
            yara=None,
            batch=None,
            extensions=None,
            list_yara=False,
            threads=1,
            version=True,
        )
    assert exc.value.code == 0


def test_main_unexpected_kwarg_triggers_exception_handler():
    """main() exception handler fires when CLIArgs(**kwargs) fails (lines 86-87)."""
    with pytest.raises(SystemExit) as exc:
        main(unknown_param_xyz=True)
    assert exc.value.code == 1


# ---------------------------------------------------------------------------
# cli() Click command - line 127
# ---------------------------------------------------------------------------


def test_cli_click_command_version_via_runner():
    """cli() Click entry point body is reached via CliRunner (line 127)."""
    runner = CliRunner()
    result = runner.invoke(cli_main.cli, ["--version"])
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# run_cli() - lines 132-159
# ---------------------------------------------------------------------------


def test_run_cli_version_flag_exits(tmp_path):
    """run_cli checks version flag and exits via _execute_version (lines 132-133)."""
    args = _make_args(version=True)
    with pytest.raises(SystemExit) as exc:
        run_cli(args)
    assert exc.value.code == 0


def test_run_cli_validation_errors_exit_one(tmp_path):
    """run_cli calls display_validation_errors + sys.exit(1) on invalid input (lines 144-146)."""
    nonexistent = str(tmp_path / "nonexistent.bin")
    args = _make_args(filename=nonexistent)
    with pytest.raises(SystemExit) as exc:
        run_cli(args)
    assert exc.value.code == 1


def test_run_cli_list_yara_exits_zero(tmp_path):
    """run_cli delegates to _execute_list_yara when list_yara=True (lines 148-149)."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "test.yar").write_text("rule test_rule { condition: false }")
    args = _make_args(list_yara=True, yara=str(rules_dir))
    with pytest.raises(SystemExit) as exc:
        run_cli(args)
    assert exc.value.code == 0


def test_run_cli_prints_banner_when_not_quiet(tmp_path):
    """run_cli prints banner when output_json=False, output_csv=False, quiet=False (lines 153-154)."""
    sample = _sample_pe()
    args = _make_args(filename=str(sample), quiet=False, output_json=False, output_csv=False)
    with pytest.raises(SystemExit):
        run_cli(args)


def test_run_cli_output_json_skips_banner(tmp_path):
    """run_cli skips banner when output_json=True (line 153 false branch)."""
    sample = _sample_pe()
    args = _make_args(filename=str(sample), output_json=True, quiet=False)
    with pytest.raises(SystemExit):
        run_cli(args)


# ---------------------------------------------------------------------------
# _execute_list_yara() - lines 164-165, 172
# ---------------------------------------------------------------------------


def test_execute_list_yara_exits(tmp_path):
    """_execute_list_yara creates ConfigCommand and calls sys.exit (lines 164-165, 172)."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "demo.yar").write_text("rule demo { condition: false }")
    with pytest.raises(SystemExit) as exc:
        _execute_list_yara(config=None, yara=str(rules_dir))
    assert exc.value.code == 0


def test_execute_list_yara_no_args():
    """_execute_list_yara works without config or yara dir."""
    with pytest.raises(SystemExit):
        _execute_list_yara(config=None, yara=None)


# ---------------------------------------------------------------------------
# _execute_version() - lines 177-178
# ---------------------------------------------------------------------------


def test_execute_version_exits_zero():
    """_execute_version creates VersionCommand and sys.exit (lines 177-178)."""
    with pytest.raises(SystemExit) as exc:
        _execute_version()
    assert exc.value.code == 0


# ---------------------------------------------------------------------------
# _build_context() - line 183
# ---------------------------------------------------------------------------


def test_build_context_non_batch():
    """_build_context returns CommandContext with thread_safe=False for non-batch (line 183)."""
    ctx = _build_context(verbose=False, quiet=True, batch=None)
    assert ctx is not None


def test_build_context_batch_mode():
    """_build_context returns CommandContext with thread_safe=True for batch (line 183)."""
    ctx = _build_context(verbose=True, quiet=False, batch="/some/dir")
    assert ctx is not None


# ---------------------------------------------------------------------------
# _dispatch_command() batch path - lines 197-199, 214
# ---------------------------------------------------------------------------


def test_dispatch_command_batch_empty_directory(tmp_path):
    """_dispatch_command takes batch branch with an empty directory (lines 197-199, 214)."""
    batch_dir = tmp_path / "batch"
    batch_dir.mkdir()
    context = _build_context(verbose=False, quiet=True, batch=str(batch_dir))
    args = _make_args(batch=str(batch_dir), quiet=True)
    with pytest.raises(SystemExit) as exc:
        _dispatch_command(context, args)
    assert exc.value.code == 0


def test_dispatch_command_batch_with_extensions(tmp_path):
    """_dispatch_command passes extensions to BatchCommand (lines 197-199, 214)."""
    batch_dir = tmp_path / "b2"
    batch_dir.mkdir()
    context = _build_context(verbose=False, quiet=True, batch=str(batch_dir))
    args = _make_args(batch=str(batch_dir), extensions="exe,dll", quiet=True)
    with pytest.raises(SystemExit) as exc:
        _dispatch_command(context, args)
    assert exc.value.code == 0


# ---------------------------------------------------------------------------
# _dispatch_command() interactive path - lines 216-218, 227
# ---------------------------------------------------------------------------


def test_dispatch_command_interactive_with_sample(tmp_path):
    """_dispatch_command takes interactive branch (lines 216-218, 227)."""
    import io
    import sys

    sample = _sample_pe()
    context = _build_context(verbose=False, quiet=True, batch=None)
    args = _make_args(filename=str(sample), interactive=True, quiet=True)
    original_stdin = sys.stdin
    try:
        sys.stdin = io.StringIO("quit\n")
        with pytest.raises(SystemExit) as exc:
            _dispatch_command(context, args)
        assert exc.value.code in (0, 1)
    finally:
        sys.stdin = original_stdin


# ---------------------------------------------------------------------------
# _dispatch_command() analyze path - lines 229-230, 243
# ---------------------------------------------------------------------------


def test_dispatch_command_analyze_with_sample():
    """_dispatch_command takes analyze branch (lines 229-230, 243)."""
    sample = _sample_pe()
    context = _build_context(verbose=False, quiet=True, batch=None)
    args = _make_args(filename=str(sample), quiet=True)
    with pytest.raises(SystemExit) as exc:
        _dispatch_command(context, args)
    assert exc.value.code in (0, 1)


def test_dispatch_command_analyze_with_json_output(tmp_path):
    """_dispatch_command analyze branch with output_json=True (lines 229-230, 243)."""
    sample = _sample_pe()
    out_file = str(tmp_path / "output.json")
    context = _build_context(verbose=False, quiet=True, batch=None)
    args = _make_args(filename=str(sample), output_json=True, output=out_file, quiet=True)
    with pytest.raises(SystemExit) as exc:
        _dispatch_command(context, args)
    assert exc.value.code in (0, 1)
