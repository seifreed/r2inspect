from __future__ import annotations

import builtins

from r2inspect.cli import interactive
from r2inspect.utils.output import OutputFormatter


class FakeInspector:
    def analyze(self, **_options):
        return {"file_info": {"name": "f", "size": 0, "file_type": "x", "md5": "m"}}

    def get_strings(self):
        return ["s1", "s2"]

    def get_file_info(self):
        return {"name": "f"}

    def get_pe_info(self):
        return {"pe": True}

    def get_imports(self):
        return ["imp1", "imp2"]

    def get_exports(self):
        return ["exp1"]

    def get_sections(self):
        return [{"name": ".text", "raw_size": 1, "flags": "r-x", "entropy": 1.0}]


def test_show_strings_only_and_helpers() -> None:
    inspector = FakeInspector()
    interactive.show_strings_only(inspector)
    interactive._print_help()
    interactive._show_info_table("Info", {"a": 1}, OutputFormatter({}))


def test_run_interactive_mode_commands(monkeypatch) -> None:
    inspector = FakeInspector()
    options = {}

    commands = iter(
        [
            "info",
            "pe",
            "imports",
            "exports",
            "sections",
            "strings",
            "analyze",
            "help",
            "",
            "unknown",
            "quit",
        ]
    )

    def fake_input(_prompt: str) -> str:
        return next(commands)

    monkeypatch.setattr(builtins, "input", fake_input)
    interactive.run_interactive_mode(inspector, options)


def test_run_interactive_mode_keyboard_interrupt(monkeypatch) -> None:
    inspector = FakeInspector()

    def raise_interrupt(_prompt: str) -> str:
        raise KeyboardInterrupt

    monkeypatch.setattr(builtins, "input", raise_interrupt)
    interactive.run_interactive_mode(inspector, {})


def test_run_interactive_mode_eof(monkeypatch) -> None:
    inspector = FakeInspector()

    def raise_eof(_prompt: str) -> str:
        raise EOFError

    monkeypatch.setattr(builtins, "input", raise_eof)
    interactive.run_interactive_mode(inspector, {})
