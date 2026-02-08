from __future__ import annotations

import io
import sys

from r2inspect.cli import interactive


class DummyInspector:
    def __init__(self) -> None:
        self._calls: list[str] = []

    def analyze(self, **_options: object) -> dict[str, object]:
        self._calls.append("analyze")
        return {}

    def get_strings(self) -> list[str]:
        self._calls.append("strings")
        return ["alpha", "beta"]

    def get_file_info(self) -> dict[str, object]:
        self._calls.append("info")
        return {"name": "sample.bin", "size": 10}

    def get_pe_info(self) -> dict[str, object]:
        self._calls.append("pe")
        return {"format": "PE"}

    def get_imports(self) -> list[str]:
        self._calls.append("imports")
        return ["CreateFileA"]

    def get_exports(self) -> list[str]:
        self._calls.append("exports")
        return ["Exported"]

    def get_sections(self) -> list[dict[str, object]]:
        self._calls.append("sections")
        return [{"name": ".text", "size": 1}]


def test_run_interactive_mode_commands() -> None:
    inspector = DummyInspector()
    options = {"foo": "bar"}

    commands = "\n".join(
        [
            "help",
            "strings",
            "info",
            "pe",
            "imports",
            "exports",
            "sections",
            "analyze",
            "unknown",
            "",
            "quit",
        ]
    )
    stdin = io.StringIO(commands)
    original_stdin = sys.stdin
    try:
        sys.stdin = stdin
        interactive.run_interactive_mode(inspector, options)
    finally:
        sys.stdin = original_stdin

    assert "strings" in inspector._calls
    assert "info" in inspector._calls
    assert "pe" in inspector._calls
    assert "imports" in inspector._calls
    assert "exports" in inspector._calls
    assert "sections" in inspector._calls
    assert "analyze" in inspector._calls


def test_show_strings_only() -> None:
    inspector = DummyInspector()
    interactive.show_strings_only(inspector)
    assert inspector._calls == ["strings"]
