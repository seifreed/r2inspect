from __future__ import annotations

import io
import sys

import pytest

from r2inspect.cli import interactive


class DummyInspector:
    def analyze(self, **options):
        return {"file_info": {"name": "sample", "size": 1, "file_type": "PE"}}

    def get_strings(self):
        return ["one", "two"]

    def get_file_info(self):
        return {"name": "sample", "size": 1, "file_type": "PE"}

    def get_pe_info(self):
        return {"imphash": "deadbeef"}

    def get_imports(self):
        return ["KERNEL32.dll"]

    def get_exports(self):
        return ["Exported"]

    def get_sections(self):
        return [{"name": ".text", "size": 10}]


@pytest.mark.unit
def test_interactive_module_commands_roundtrip() -> None:
    inspector = DummyInspector()
    commands = "\n".join(
        [
            "info",
            "strings",
            "pe",
            "imports",
            "exports",
            "sections",
            "help",
            "unknown",
            "quit",
        ]
    )
    original_stdin = sys.stdin
    try:
        sys.stdin = io.StringIO(commands)
        interactive.run_interactive_mode(inspector, options={})
    finally:
        sys.stdin = original_stdin


@pytest.mark.unit
def test_show_strings_only() -> None:
    inspector = DummyInspector()
    interactive.show_strings_only(inspector)
