import sys

from r2inspect import __main__


def test_main_entrypoint_help_returns_zero(capsys):
    argv = sys.argv
    try:
        sys.argv = ["r2inspect", "--help"]
        code = __main__.main()
        assert code == 0
    finally:
        sys.argv = argv
    captured = capsys.readouterr()
    assert "Usage" in captured.out
