from __future__ import annotations

import io
import sys

from r2inspect.cli import interactive


class DummyInspector:
    def analyze(self, **_options):
        return {"file_info": {"name": "dummy"}}

    def get_strings(self):
        return ["s1", "s2"]

    def get_file_info(self):
        return {"name": "dummy"}

    def get_pe_info(self):
        return {"type": "EXE"}

    def get_imports(self):
        return ["imp1"]

    def get_exports(self):
        return ["exp1"]

    def get_sections(self):
        return [{"name": ".text"}]


def test_run_interactive_mode_quick_exit():
    inspector = DummyInspector()
    old_stdin = sys.stdin
    sys.stdin = io.StringIO("help\nstrings\ninfo\npe\nimports\nexports\nsections\nunknown\nquit\n")
    try:
        interactive.run_interactive_mode(inspector, options={})
    finally:
        sys.stdin = old_stdin


def test_show_strings_only(capsys):
    buffer = io.StringIO()
    original_file = interactive.console.file
    try:
        interactive.console.file = buffer
        interactive.show_strings_only(DummyInspector())
    finally:
        interactive.console.file = original_file

    out = buffer.getvalue()
    assert "s1" in out
