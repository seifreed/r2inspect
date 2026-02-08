import builtins
from io import StringIO
from types import SimpleNamespace

import pytest

from r2inspect.cli import interactive


class FakeInspector:
    def __init__(self) -> None:
        self.analyze_calls: list[dict[str, object]] = []

    def analyze(self, **options: object) -> dict[str, object]:
        self.analyze_calls.append(dict(options))
        return {}

    def get_strings(self) -> list[str]:
        return ["alpha", "beta"]

    def get_file_info(self) -> dict[str, object]:
        return {"Name": "sample.bin"}

    def get_pe_info(self) -> dict[str, object]:
        return {"Type": "PE32+"}

    def get_imports(self) -> list[str]:
        return ["kernel32.dll!CreateFileA"]

    def get_exports(self) -> list[str]:
        return ["ExportedFunc"]

    def get_sections(self) -> list[dict[str, object]]:
        return [{"name": ".text", "size": 10, "perm": "r-x", "entropy": 1.0}]


class _InputFeeder:
    def __init__(self, items: list[str | BaseException]) -> None:
        self._items = list(items)

    def __call__(self, _prompt: str) -> str:
        if not self._items:
            raise EOFError
        item = self._items.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


@pytest.mark.unit
def test_run_interactive_mode_handles_all_commands() -> None:
    inspector = FakeInspector()
    options = {"verbose": True}
    feeder = _InputFeeder(
        [
            "",
            "help",
            "info",
            "pe",
            "imports",
            "exports",
            "sections",
            "strings",
            "analyze",
            "unknown",
            "quit",
        ]
    )

    original_input = builtins.input
    original_stdout = interactive.console.file
    try:
        builtins.input = feeder
        interactive.console.file = StringIO()
        interactive.run_interactive_mode(inspector, options)
    finally:
        builtins.input = original_input
        interactive.console.file = original_stdout

    assert inspector.analyze_calls == [options]


@pytest.mark.unit
def test_run_interactive_mode_handles_keyboard_interrupt() -> None:
    inspector = FakeInspector()
    options = {}
    feeder = _InputFeeder([KeyboardInterrupt()])

    original_input = builtins.input
    original_stdout = interactive.console.file
    try:
        builtins.input = feeder
        interactive.console.file = StringIO()
        interactive.run_interactive_mode(inspector, options)
    finally:
        builtins.input = original_input
        interactive.console.file = original_stdout


@pytest.mark.unit
def test_run_interactive_mode_handles_eof() -> None:
    inspector = FakeInspector()
    options = {}
    feeder = _InputFeeder([EOFError()])

    original_input = builtins.input
    original_stdout = interactive.console.file
    try:
        builtins.input = feeder
        interactive.console.file = StringIO()
        interactive.run_interactive_mode(inspector, options)
    finally:
        builtins.input = original_input
        interactive.console.file = original_stdout


@pytest.mark.unit
def test_show_strings_only_prints_strings() -> None:
    inspector = SimpleNamespace(get_strings=lambda: ["one", "two"])
    original_stdout = interactive.console.file
    try:
        interactive.console.file = StringIO()
        interactive.show_strings_only(inspector)
        output = interactive.console.file.getvalue()
    finally:
        interactive.console.file = original_stdout

    assert "one" in output
    assert "two" in output
