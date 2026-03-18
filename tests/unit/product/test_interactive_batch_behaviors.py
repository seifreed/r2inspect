from __future__ import annotations

from pathlib import Path

import r2inspect.cli.batch_output as batch_output
import r2inspect.cli.interactive as interactive
import pytest


class _Console:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def print(self, message) -> None:
        self.messages.append(str(message))


class _Inspector:
    def get_strings(self):
        return ["alpha", "beta"]

    def get_file_info(self):
        return {"name": "sample.bin"}

    def get_pe_info(self):
        return {"machine": "x86"}

    def get_imports(self):
        return ["CreateFileA"]

    def get_exports(self):
        return ["Exported"]

    def get_sections(self):
        return [{"name": ".text"}]


class _Formatter:
    def __init__(self, _data) -> None:
        pass

    def format_table(self, data, title):
        return f"{title}:{data}"

    def format_sections(self, sections):
        return f"sections:{sections}"


def test_interactive_mode_handles_known_unknown_and_exit_commands(monkeypatch) -> None:
    console = _Console()
    inspector = _Inspector()
    commands = iter(["strings", "info", "unknown", "quit"])

    monkeypatch.setattr(interactive, "console", console)
    monkeypatch.setattr(interactive, "OutputFormatter", _Formatter)
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(commands))

    interactive.run_interactive_mode(inspector, {})

    rendered = "\n".join(console.messages)
    assert "alpha" in rendered and "beta" in rendered
    assert "File Information" in rendered
    assert "Unknown command: unknown" in rendered
    assert "Exiting interactive mode" in rendered


def test_interactive_mode_runs_analyze_and_help(monkeypatch) -> None:
    console = _Console()
    inspector = _Inspector()
    commands = iter(["help", "analyze", "quit"])
    displayed: list[dict[str, str]] = []

    class _FakeResult:
        def to_dict(self):
            return {"status": "ok"}

    class _UseCase:
        def run(
            self,
            passed_inspector,
            passed_options,
            *,
            reset_stats: bool,
            include_statistics: bool,
            validate_schemas: bool,
        ):
            assert passed_inspector is inspector
            assert passed_options == {"full_analysis": True}
            assert reset_stats is False
            assert include_statistics is False
            assert validate_schemas is False
            return _FakeResult()

    monkeypatch.setattr(interactive, "console", console)
    monkeypatch.setattr(interactive, "OutputFormatter", _Formatter)
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(commands))
    monkeypatch.setattr("r2inspect.application.use_cases.AnalyzeBinaryUseCase", lambda: _UseCase())
    monkeypatch.setattr(
        "r2inspect.cli.display.display_results", lambda result: displayed.append(result)
    )

    interactive.run_interactive_mode(inspector, {"full_analysis": True})

    rendered = "\n".join(console.messages)
    assert "Available commands: analyze" in rendered
    assert displayed == [{"status": "ok"}]


@pytest.mark.parametrize("side_effect", [KeyboardInterrupt(), EOFError()])
def test_interactive_mode_exits_cleanly_on_terminal_interrupts(monkeypatch, side_effect) -> None:
    console = _Console()
    inspector = _Inspector()

    monkeypatch.setattr(interactive, "console", console)
    monkeypatch.setattr(interactive, "OutputFormatter", _Formatter)
    monkeypatch.setattr("builtins.input", lambda _prompt="": (_ for _ in ()).throw(side_effect))

    interactive.run_interactive_mode(inspector, {})

    assert any("Exiting interactive mode" in message for message in console.messages)


def test_batch_output_creates_json_summary_and_csv_rows(tmp_path: Path) -> None:
    all_results = {
        "a.bin": {
            "file_info": {"name": "a.bin", "file_type": "PE32", "size": 10},
            "hashing": {"ssdeep": "abc"},
            "security": {"aslr": True},
            "indicators": [{"type": "Anti-Debug"}],
        }
    }
    failed_files = [("bad.bin", "parse error")]

    summary_path = batch_output.create_batch_summary(
        all_results,
        failed_files,
        tmp_path,
        output_json=True,
        output_csv=True,
    )

    assert summary_path is not None
    csv_files = list(tmp_path.glob("*.csv"))
    assert csv_files
    assert "individual JSONs" in summary_path
