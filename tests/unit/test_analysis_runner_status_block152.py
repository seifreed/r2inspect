from __future__ import annotations

from r2inspect.cli.analysis_runner import print_status_if_appropriate


def test_print_status_if_appropriate(capsys):
    print_status_if_appropriate(False, False, None)
    out = capsys.readouterr().out
    assert "Starting analysis" in out

    print_status_if_appropriate(True, False, None)
    out = capsys.readouterr().out
    assert out == ""

    print_status_if_appropriate(True, False, "out.json")
    out = capsys.readouterr().out
    assert "Starting analysis" in out
