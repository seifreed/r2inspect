from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.cli_main import CLIArgs, _build_context, _dispatch_command, run_cli


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _fixture_path(name: str) -> Path:
    return _project_root() / "samples" / "fixtures" / name


def test_build_context() -> None:
    ctx = _build_context(verbose=False, quiet=True, batch=None)
    assert ctx is not None
    ctx_batch = _build_context(verbose=False, quiet=False, batch="/tmp")
    assert ctx_batch is not None


def test_run_cli_version_exits() -> None:
    args = CLIArgs(
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
        version=True,
    )
    with pytest.raises(SystemExit) as excinfo:
        run_cli(args)
    assert excinfo.value.code == 0


def test_run_cli_list_yara_exits() -> None:
    rules_dir = _project_root() / "r2inspect" / "rules" / "yara"
    args = CLIArgs(
        filename=None,
        interactive=False,
        output_json=False,
        output_csv=False,
        output=None,
        xor=None,
        verbose=False,
        quiet=True,
        config=None,
        yara=str(rules_dir),
        batch=None,
        extensions=None,
        list_yara=True,
        threads=1,
        version=False,
    )
    with pytest.raises(SystemExit) as excinfo:
        run_cli(args)
    assert excinfo.value.code == 0


def test_run_cli_validation_errors() -> None:
    args = CLIArgs(
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
        threads=0,
        version=False,
    )
    with pytest.raises(SystemExit) as excinfo:
        run_cli(args)
    assert excinfo.value.code == 1


@pytest.mark.requires_r2
def test_dispatch_command_analyze() -> None:
    sample = _fixture_path("hello_pe.exe")
    args = CLIArgs(
        filename=str(sample),
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
        version=False,
    )
    with pytest.raises(SystemExit) as excinfo:
        run_cli(args)
    assert excinfo.value.code == 0


@pytest.mark.requires_r2
def test_dispatch_command_batch() -> None:
    fixtures = _project_root() / "samples" / "fixtures"
    args = CLIArgs(
        filename=None,
        interactive=False,
        output_json=False,
        output_csv=True,
        output=None,
        xor=None,
        verbose=False,
        quiet=True,
        config=None,
        yara=None,
        batch=str(fixtures),
        extensions=None,
        list_yara=False,
        threads=2,
        version=False,
    )
    with pytest.raises(SystemExit) as excinfo:
        run_cli(args)
    assert excinfo.value.code == 0


@pytest.mark.requires_r2
def test_dispatch_command_direct() -> None:
    sample = _fixture_path("hello_pe.exe")
    args = CLIArgs(
        filename=str(sample),
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
        version=False,
    )
    ctx = _build_context(verbose=False, quiet=True, batch=None)
    with pytest.raises(SystemExit) as excinfo:
        _dispatch_command(ctx, args)
    assert excinfo.value.code == 0
