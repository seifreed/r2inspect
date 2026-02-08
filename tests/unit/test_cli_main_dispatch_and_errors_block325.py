from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect import cli_main


def _sample_path() -> Path:
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("sample binary missing")
    return sample


@pytest.mark.unit
def test_main_handles_unexpected_error() -> None:
    with pytest.raises(SystemExit) as exc:
        cli_main.main(bogus_option=True)
    assert exc.value.code == 1


@pytest.mark.unit
def test_dispatch_analyze_path_exits_zero() -> None:
    sample = _sample_path()
    args = cli_main.CLIArgs(
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
    context = cli_main._build_context(verbose=False, quiet=True, batch=None)

    with pytest.raises(SystemExit) as exc:
        cli_main._dispatch_command(context, args)
    assert exc.value.code == 0
