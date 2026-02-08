from __future__ import annotations

import io
import os
import sys
from pathlib import Path

from rich.console import Console

from r2inspect.cli import analysis_runner, batch_output, batch_processing
from r2inspect.cli import display as display_module
from r2inspect.cli import display_base, interactive, presenter
from r2inspect.cli.commands.analyze_command import AnalyzeCommand
from r2inspect.cli.commands.base import CommandContext
from r2inspect.cli.commands.batch_command import BatchCommand
from r2inspect.config import Config


def _console_buffer() -> tuple[Console, io.StringIO]:
    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=False, width=120)
    return console, buffer


def test_display_base_helpers_and_presenter() -> None:
    console, buffer = _console_buffer()
    original_console = display_module.console
    original_pyfiglet = display_base.pyfiglet
    try:
        display_module.console = console

        assert display_base.format_hash_display(None) == "N/A"
        assert display_base.format_hash_display("x" * 40, max_length=8).endswith("...")

        display_base.pyfiglet = None
        display_base.print_banner()
        display_base.pyfiglet = type(
            "Fig",
            (),
            {"figlet_format": staticmethod(lambda *_args, **_kwargs: "banner")},
        )()
        display_base.print_banner()

        display_base.display_validation_errors(["bad"])
        display_base.display_yara_rules_table(
            [{"name": "rule.yar", "size": 2048, "path": "rule.yar"}],
            "rules",
        )

        empty_rules = Path("output") / "empty_rules"
        empty_rules.mkdir(parents=True, exist_ok=True)
        display_base.handle_list_yara_option(config=None, yara=str(empty_rules))

        display_base.display_error_statistics(
            {
                "total_errors": 1,
                "recent_errors": 1,
                "recovery_strategies_available": 1,
                "errors_by_category": {"analysis": 1},
                "errors_by_severity": {"critical": 1, "high": 2, "low": 3},
            }
        )
        display_base.display_performance_statistics(
            {
                "total_retries": 1,
                "successful_retries": 1,
                "failed_after_retries": 0,
                "success_rate": 100.0,
                "commands_retried": {"ij": 1},
            },
            {"opened": 2},
        )

        display_base.display_results({"file_info": {"name": "sample.bin"}})

        normalized = presenter.normalize_display_results({"a": 1})
        assert presenter.get_section(normalized, "missing", {}) == ({}, False)
        assert presenter.get_section({}, "missing", {}) == ({}, False)
    finally:
        display_module.console = original_console
        display_base.pyfiglet = original_pyfiglet

    assert buffer.getvalue()


def test_interactive_mode_real_inputs(tmp_path: Path) -> None:
    console, _buffer = _console_buffer()
    original_console = display_module.console
    original_stdin = sys.stdin
    try:
        display_module.console = console

        class _Inspector:
            def analyze(self, **_kwargs: object) -> dict[str, object]:
                return {"file_info": {"name": "sample.bin"}}

            def get_strings(self) -> list[str]:
                return ["alpha", "beta"]

            def get_file_info(self) -> dict[str, object]:
                return {"name": "sample.bin", "size": 1}

            def get_pe_info(self) -> dict[str, object]:
                return {"format": "PE32", "sections": 2}

            def get_imports(self) -> list[dict[str, object]]:
                return [{"name": "LoadLibraryA"}]

            def get_exports(self) -> list[dict[str, object]]:
                return [{"name": "Exported"}]

            def get_sections(self) -> list[dict[str, object]]:
                return [{"name": ".text", "size": 1, "entropy": 5.2}]

        sys.stdin = io.StringIO(
            "help\ninfo\npe\nimports\nexports\nsections\nstrings\nanalyze\nunknown\nquit\n"
        )
        interactive.run_interactive_mode(_Inspector(), options={})
    finally:
        display_module.console = original_console
        sys.stdin = original_stdin


def test_analysis_runner_and_commands(tmp_path: Path) -> None:
    output = analysis_runner.setup_single_file_output(
        output_json=False,
        output_csv=True,
        output=None,
        filename="sample.bin",
    )
    assert output and str(output).endswith("_analysis.csv")

    console, _buffer = _console_buffer()
    context = CommandContext.create(config=Config())
    context.console = console
    analyze = AnalyzeCommand(context)
    assert analyze._has_circuit_breaker_data({}) is False

    batch = BatchCommand(context)
    args = {
        "batch": str(tmp_path),
        "config": None,
        "yara": None,
        "xor": None,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "extensions": "exe",
        "threads": 1,
        "verbose": False,
        "quiet": False,
    }
    assert batch.execute(args) == 0


def test_batch_output_and_processing_real(tmp_path: Path) -> None:
    console, _buffer = _console_buffer()
    original_console = display_module.console
    try:
        display_module.console = console

        assert (
            batch_output.find_files_to_process(
                tmp_path,
                auto_detect=False,
                extensions=None,
                recursive=False,
                verbose=False,
                quiet=True,
            )
            == []
        )
        assert (
            batch_output.find_files_to_process(
                tmp_path,
                auto_detect=True,
                extensions=None,
                recursive=False,
                verbose=True,
                quiet=False,
            )
            == []
        )

        batch_output.setup_batch_output_directory(None, output_json=False, output_csv=False)
        batch_output._configure_batch_logging(verbose=False, quiet=True)
        prepared = batch_output._prepare_batch_run(
            tmp_path,
            auto_detect=False,
            extensions=None,
            recursive=False,
            verbose=False,
            quiet=True,
            output_dir=None,
            output_json=False,
            output_csv=False,
            threads=1,
        )
        assert prepared is None

        csv_only = batch_output.create_batch_summary(
            {"a": {"file_info": {"file_type": "PE32+", "name": "a.bin"}}},
            [],
            tmp_path,
            output_json=False,
            output_csv=True,
        )
        assert csv_only

        json_and_csv = batch_output.create_batch_summary(
            {"a": {"file_info": {"file_type": "ELF", "name": "a.bin"}}},
            [],
            tmp_path,
            output_json=True,
            output_csv=True,
        )
        assert json_and_csv

        json_only = batch_output.create_batch_summary(
            {"a": {"file_info": {"file_type": "Mach-O", "name": "a.bin"}}},
            [("a.bin", "err")],
            tmp_path,
            output_json=True,
            output_csv=False,
        )
        assert json_only

        assert batch_output._simplify_file_type("PE32+ executable, 3 sections") == "PE32+ (x64)"
        assert batch_output._simplify_file_type("PE32 executable, 2 sections") == "PE32 (x86)"
        assert batch_output._simplify_file_type("ELF 64-bit") == "ELF"
        assert batch_output._simplify_file_type("Mach-O 64-bit") == "Mach-O"
        assert batch_output._simplify_file_type("") == "Unknown"

        assert (
            batch_output._compiler_name({"compiler": {"detected": True, "compiler": "GCC"}})
            == "GCC"
        )
        assert (
            batch_output._compiler_name(
                {"compiler": {"detected": True, "compiler": "GCC", "version": "1.0"}}
            )
            == "GCC 1.0"
        )
        assert batch_output._compiler_name({"compiler": {"detected": False}}) == "Unknown"

        matches = batch_output._collect_yara_matches({"yara_matches": [{"rule": "r1"}, "r2"]})
        assert matches == "r1, r2"

        sample = tmp_path / "tiny.bin"
        sample.write_bytes(b"#!/b")

        assert batch_processing.check_executable_signature(sample) is True
        assert batch_processing.is_script_executable(b"#!") is True
        assert batch_processing.is_macho_executable(b"\xfe\xed\xfa\xcf") is True
        assert batch_processing.is_elf_executable(b"\x7fELF") is True
        assert batch_processing.is_pe_executable(b"MZ" + b"\x00" * 62, io.BytesIO(b"MZ"))

        class _BadFile:
            def seek(self, _offset: int) -> None:
                raise OSError("boom")

            def read(self, _size: int) -> bytes:
                return b""

        assert batch_processing.is_pe_executable(b"MZ" + b"\x00" * 62, _BadFile()) is True
        assert batch_processing.check_executable_signature(tmp_path / "missing.bin") is False

        rate_limiter = batch_processing.setup_rate_limiter(threads=1, verbose=True)
        batch_processing.display_rate_limiter_stats(rate_limiter.get_stats())
        batch_processing.display_failed_files([("a", "err")], verbose=True)
    finally:
        display_module.console = original_console


def test_batch_processing_magic_errors(tmp_path: Path) -> None:
    data = tmp_path / "no_access.bin"
    data.write_bytes(b"MZ" + b"\x00" * 100)
    data.chmod(0)
    try:
        found = batch_processing.find_executable_files_by_magic(
            tmp_path, recursive=False, verbose=True
        )
        assert found == []
    finally:
        data.chmod(0o644)

    os.environ["R2INSPECT_MAX_THREADS"] = "1"
    try:
        assert batch_processing._cap_threads_for_execution(threads=4) == 1
        os.environ["R2INSPECT_MAX_THREADS"] = "bad"
        assert batch_processing._cap_threads_for_execution(threads=4) == 4
        os.environ["R2INSPECT_MAX_THREADS"] = "-1"
        assert batch_processing._cap_threads_for_execution(threads=4) == 4
    finally:
        os.environ.pop("R2INSPECT_MAX_THREADS", None)
