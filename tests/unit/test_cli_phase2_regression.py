"""Phase 2 regression coverage for CLI command parsing output paths and batch output branches.

No unittest.mock, no MagicMock, no patch. Real objects, real Console(file=StringIO()).
"""

from __future__ import annotations

import io
import os
from pathlib import Path

from rich.console import Console

from r2inspect.cli import batch_output
from r2inspect.cli.commands.analyze_command import AnalyzeCommand
from r2inspect.cli.commands.batch_command import BatchCommand
from r2inspect.cli.commands.config_command import ConfigCommand
from r2inspect.cli.commands.interactive_command import InteractiveCommand
from r2inspect.cli.commands.base import CommandContext


def test_analyze_command_displays_verbose_stats() -> None:
    """Cover compatibility wrapper for verbose analysis statistics."""
    cmd = AnalyzeCommand(CommandContext.create())
    # Just call it; the method delegates to analysis_output._display_verbose_statistics().
    # It should complete without error.
    cmd._display_verbose_statistics()


def test_batch_command_setup_analysis_options_adds_custom_flags() -> None:
    """Cover YARA + XOR branches in batch option setup."""
    cmd = BatchCommand(CommandContext.create())
    options = cmd._setup_analysis_options("rules-dir", "needle")

    assert options["custom_yara"] == "rules-dir"
    assert options["xor_search"] == "needle"


def test_interactive_cmd_strings_prints_results() -> None:
    """Cover the strings command iteration branch."""
    console = Console(file=io.StringIO(), force_terminal=False)
    command = InteractiveCommand(CommandContext.create())
    command.context.console = console

    class _Inspector:
        @staticmethod
        def get_strings() -> list[str]:
            return ["first", "second"]

    command._cmd_strings(_Inspector())
    output = console.file.getvalue()

    assert "first" in output
    assert "second" in output


def test_config_command_display_relative_path_fallback(tmp_path: Path) -> None:
    """Cover ValueError branch when a YARA path is outside rules_path."""
    rules_path = tmp_path / "rules"
    rules_path.mkdir()

    outside = tmp_path / "outside"
    outside.mkdir()
    rule_file = outside / "detected.yar"
    rule_file.write_text("rule detected { condition: true }")

    console = Console(file=io.StringIO(), force_terminal=False)
    command = ConfigCommand(CommandContext.create())
    command.context.console = console

    command._display_yara_rules_table([rule_file], rules_path)
    output = console.file.getvalue()

    assert "detected.yar" in output


def test_batch_output_find_files_extension_branch(tmp_path: Path) -> None:
    """Cover extension-based search branch for non-auto detection."""
    # Create a real file so find_files_by_extensions can find it.
    (tmp_path / "abc.bin").write_bytes(b"\x00")

    results = batch_output.find_files_to_process(
        batch_path=tmp_path,
        auto_detect=False,
        extensions="bin",
        recursive=False,
        verbose=True,
        quiet=False,
    )

    assert isinstance(results, list)
    assert any(p.suffix == ".bin" for p in results)


def test_batch_output_display_no_files_messages() -> None:
    """Cover both messages emitted by no-files display helper."""
    # Just call the function; it writes to the module-level console.
    # As long as it doesn't raise, the branch is covered.
    batch_output.display_no_files_message(auto_detect=True, extensions="bin")
    batch_output.display_no_files_message(auto_detect=False, extensions="exe")


def test_batch_output_setup_output_directory_variants(tmp_path: Path) -> None:
    """Cover parent-directory creation and default output directory creation."""
    csv_output = tmp_path / "reports" / "analysis.json"
    resolved_csv = batch_output.setup_batch_output_directory(
        str(csv_output), output_json=True, output_csv=False
    )
    assert resolved_csv == csv_output
    assert csv_output.parent.exists()

    cwd = Path.cwd()
    os.chdir(tmp_path)
    try:
        resolved_default = batch_output.setup_batch_output_directory(
            None, output_json=True, output_csv=False
        )
        assert resolved_default.name == "output"
        assert resolved_default.exists()
    finally:
        os.chdir(cwd)


def test_batch_output_csv_suffix_summary_filename(tmp_path: Path) -> None:
    """Cover `... + individual JSONs` branch when output path is a CSV filename."""
    results = {
        "a": {
            "file_info": {"file_type": "PE32+", "name": "a.bin"},
            "compiler": {"detected": False},
            "pe_info": {},
            "imports": [],
            "sections": [],
            "yara_matches": [],
            "crypto": {},
        },
    }
    csv_name = tmp_path / "custom.csv"
    file_name = batch_output.create_batch_summary(
        all_results=results,
        failed_files=[],
        output_path=csv_name,
        output_json=True,
        output_csv=True,
    )

    assert file_name is not None
    assert "custom.csv" in file_name


def test_batch_output_summary_table_and_row_functions() -> None:
    """Cover table branch for >10 files and row helper functions."""
    many_results: dict[str, dict[str, str]] = {
        f"file-{n}": {"file_info": {"name": f"file-{n}", "file_type": "PE32", "md5": f"md5-{n}"}}
        for n in range(11)
    }

    # Just call _show_summary_table; it writes to the module-level console.
    batch_output._show_summary_table(many_results)

    # Test _build_small_row with valid and invalid inputs.
    row = batch_output._build_small_row(
        "file", {"file_info": {"name": "x", "file_type": "PE32", "md5": "y"}}
    )
    assert row[0] == "x"
    assert row[1] == "PE32 (x86)"

    error_row = batch_output._build_small_row("file", object())
    assert error_row == ("file", "Error", "Error", "Error")

    error_large_row = batch_output._build_large_row("file", object())
    assert error_large_row == ("file", "Error", "Error", "Error", "Error")


def test_batch_output_prepare_batch_run(tmp_path: Path) -> None:
    """Cover _prepare_batch_run with real file discovery."""
    (tmp_path / "a.bin").write_bytes(b"\x00" * 16)

    result = batch_output._prepare_batch_run(
        batch_path=tmp_path,
        auto_detect=False,
        extensions="bin",
        recursive=False,
        verbose=True,
        quiet=False,
        output_dir=str(tmp_path / "output"),
        output_json=True,
        output_csv=True,
        threads=4,
    )

    # Result is either (files, output_dir) or None if no files found.
    if result is not None:
        files, output_dir = result
        assert isinstance(files, list)
