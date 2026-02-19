from __future__ import annotations

import io
import os
import signal
import sys
import threading
import time
from pathlib import Path

import pytest
from rich.console import Console

import r2inspect.cli as cli
from r2inspect.cli import analysis_runner, batch_output, batch_processing, validators
from r2inspect.cli.commands.analyze_command import AnalyzeCommand
from r2inspect.cli.commands.base import (
    Command,
    CommandContext,
    apply_thread_settings,
    configure_logging_levels,
    configure_quiet_logging,
)
from r2inspect.cli.commands.batch_command import BatchCommand
from r2inspect.cli.commands.config_command import ConfigCommand
from r2inspect.cli.commands.interactive_command import InteractiveCommand
from r2inspect.cli.commands.version_command import VersionCommand
from r2inspect.config import Config
from r2inspect.error_handling.policies import ErrorHandlingStrategy, ErrorPolicy
from r2inspect.error_handling.unified_handler import (
    get_circuit_breaker_stats,
    handle_errors,
    reset_circuit_breakers,
)
from r2inspect.utils.error_handler import error_handler, reset_error_stats
from r2inspect.utils.rate_limiter import BatchRateLimiter
from r2inspect.utils.retry_manager import RetryConfig, global_retry_manager, reset_retry_stats

SAMPLES_ROOT = Path(__file__).resolve().parents[2] / "samples" / "fixtures"
SAMPLE_ELF = SAMPLES_ROOT / "hello_elf"


class _Inspector:
    def analyze(self, **_kwargs: object) -> dict[str, object]:
        return {"file_info": {"name": "sample.bin", "file_type": "ELF"}}

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


class _Command(Command):
    def execute(self, _args: dict[str, object]) -> int:
        return 0


def _console_buffer() -> tuple[Console, io.StringIO]:
    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=False, width=120)
    return console, buffer


def _sample_path() -> Path:
    assert SAMPLE_ELF.exists()
    return SAMPLE_ELF


def _run_with_sigint(func: callable) -> int:
    timer = threading.Timer(0.01, signal.raise_signal, args=(signal.SIGINT,))
    timer.start()
    try:
        return func()
    finally:
        timer.cancel()


def test_cli_init_lazy_attrs_and_main() -> None:
    batch_module = cli.batch_output
    assert batch_module is batch_output

    assert cli.create_batch_summary is batch_output.create_batch_summary
    assert cli.display_results is cli.display.display_results

    with pytest.raises(AttributeError):
        _ = cli.missing_attribute

    names = cli.__dir__()
    assert "AnalyzeCommand" in names

    argv = sys.argv
    try:
        sys.argv = ["r2inspect", "--help"]
        with pytest.raises(SystemExit):
            cli.main()
    finally:
        sys.argv = argv


def test_cli_validators_real_inputs(tmp_path: Path) -> None:
    console, _buffer = _console_buffer()
    original_console = validators.console
    validators.console = console
    try:
        empty_file = tmp_path / "empty.bin"
        empty_file.write_bytes(b"")
        large_file = tmp_path / "large.bin"
        large_file.write_bytes(b"x")
        os.truncate(large_file, 1024 * 1024 * 1024 + 1)

        validators.validate_inputs(
            filename=str(empty_file),
            batch=str(tmp_path),
            output=str(tmp_path / "out.txt"),
            yara=None,
            config=None,
            extensions=None,
            threads=None,
        )

        assert validators.validate_file_input(str(tmp_path))  # not a file
        assert validators.validate_file_input(str(empty_file))
        assert validators.validate_file_input(str(large_file))
        assert validators.validate_file_input("nope.bin")

        os.environ["R2INSPECT_TEST_RAISE_FILE_ERROR"] = "1"
        try:
            assert validators.validate_file_input(str(empty_file))
        finally:
            os.environ.pop("R2INSPECT_TEST_RAISE_FILE_ERROR", None)

        blocked_dir = tmp_path / "blocked_dir"
        blocked_dir.mkdir()
        blocked_file = blocked_dir / "blocked.bin"
        blocked_file.write_bytes(b"x")
        blocked_dir.chmod(0)
        try:
            assert validators.validate_file_input(str(blocked_file))
        finally:
            blocked_dir.chmod(0o755)

        batch_dir = tmp_path / "batch"
        batch_dir.mkdir()
        not_dir = tmp_path / "not_dir"
        not_dir.write_bytes(b"x")
        assert validators.validate_batch_input(str(not_dir))
        os.environ["R2INSPECT_TEST_RAISE_BATCH_ERROR"] = "1"
        try:
            assert validators.validate_batch_input(str(batch_dir))
        finally:
            os.environ.pop("R2INSPECT_TEST_RAISE_BATCH_ERROR", None)

        assert validators.validate_batch_input("bad;path")

        output_file = tmp_path / "out.txt"
        output_file.write_text("ok")
        assert validators.validate_output_input(str(output_file)) == []
        output_file.chmod(0o000)
        try:
            assert validators.validate_output_input(str(output_file))
        finally:
            output_file.chmod(0o644)

        parent_file = tmp_path / "parent"
        parent_file.write_text("x")
        assert validators.validate_output_input(str(parent_file / "child"))

        missing_yara = tmp_path / "missing_yara"
        assert validators.validate_yara_input(str(missing_yara))
        yara_file = tmp_path / "rules.yar"
        yara_file.write_text("rule x { condition: true }")
        assert validators.validate_yara_input(str(yara_file))

        missing_config = tmp_path / "config.json"
        assert validators.validate_config_input(str(missing_config))
        config_dir = tmp_path / "config_dir"
        config_dir.mkdir()
        assert validators.validate_config_input(str(config_dir))
        bad_config = tmp_path / "config.bad"
        bad_config.write_text("x")
        assert validators.validate_config_input(str(bad_config))

        assert validators.validate_extensions_input("bad?ext")
        assert validators.validate_extensions_input("thisextensionistoolong")

        assert validators.validate_threads_input(0)
        assert validators.validate_threads_input(51)

        validators.display_validation_errors(["one", "two"])

        with pytest.raises(SystemExit):
            validators.validate_input_mode(None, None)
        with pytest.raises(SystemExit):
            validators.validate_input_mode(str(empty_file), str(batch_dir))
        validators.validate_input_mode(str(empty_file), None)

        with pytest.raises(SystemExit):
            validators.validate_single_file(str(tmp_path / "missing.bin"))
        with pytest.raises(SystemExit):
            validators.validate_single_file(str(batch_dir))

        assert validators.sanitize_xor_string("") is None
        assert validators.sanitize_xor_string("!!") is None
        long_value = "a" * 200
        assert validators.sanitize_xor_string(long_value) == "a" * 100
        assert validators.handle_xor_input("!!") is None
    finally:
        validators.console = original_console


def test_analysis_runner_outputs_and_stats(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    console, _buffer = _console_buffer()
    original_console = analysis_runner.console
    analysis_runner.console = console
    try:
        reset_error_stats()
        reset_retry_stats()
        reset_circuit_breakers()

        @error_handler(fallback_result={"error": "fallback"})
        def _boom() -> dict[str, str]:
            raise RuntimeError("boom")

        _boom()

        attempts = {"count": 0}

        def _retry_once(**_kwargs: object) -> str:
            attempts["count"] += 1
            if attempts["count"] < 2:
                raise TimeoutError("retry timeout")
            return "ok"

        global_retry_manager.retry_operation(
            _retry_once,
            command="ij",
            config=RetryConfig(max_attempts=2, base_delay=0.01, max_delay=0.01),
        )

        policy = ErrorPolicy(strategy=ErrorHandlingStrategy.CIRCUIT_BREAK, circuit_threshold=1)

        @handle_errors(policy)
        def _circuit_fail() -> None:
            raise RuntimeError("fail")

        with pytest.raises(RuntimeError):
            _circuit_fail()

        results: dict[str, object] = {"file_info": {"name": "sample.bin"}}
        analysis_runner.add_statistics_to_results(results)
        assert "error_statistics" in results
        assert "retry_statistics" in results
        assert "circuit_breaker_statistics" in results

        assert analysis_runner.has_circuit_breaker_data({"count": 1}) is True
        assert analysis_runner.has_circuit_breaker_data({"nested": {"count": 1}}) is True
        assert analysis_runner.has_circuit_breaker_data({"nested": {"state": "closed"}}) is False
        assert analysis_runner.has_circuit_breaker_data({}) is False
        assert analysis_runner.has_circuit_breaker_data({"nested": {"state": "open"}}) is True

        analysis_runner.print_status_if_appropriate(False, False, None)
        analysis_runner.print_status_if_appropriate(True, False, tmp_path / "out.json")

        formatter_results = {"file_info": {"name": "sample.bin"}}
        analysis_runner.output_json_results(
            analysis_runner.OutputFormatter(formatter_results), tmp_path / "out.json"
        )
        analysis_runner.output_csv_results(
            analysis_runner.OutputFormatter(formatter_results), tmp_path / "out.csv"
        )
        assert (tmp_path / "out.json").exists()
        assert (tmp_path / "out.csv").exists()

        analysis_runner.output_results(formatter_results, True, False, None, verbose=False)
        analysis_runner.output_results(formatter_results, False, True, None, verbose=False)
        analysis_runner.output_results(formatter_results, False, False, None, verbose=True)

        analysis_runner.setup_single_file_output(True, False, None, "sample.bin")
        analysis_runner.setup_analysis_options("rules", "aa")

        inspector = _Inspector()
        analysis_runner.run_analysis(
            inspector,
            {},
            output_json=False,
            output_csv=False,
            output_file=None,
            verbose=True,
        )

        with pytest.raises(SystemExit):
            analysis_runner.handle_main_error(RuntimeError("boom"), verbose=False)
        with pytest.raises(SystemExit):
            analysis_runner.handle_main_error(RuntimeError("boom"), verbose=True)
    finally:
        analysis_runner.console = original_console

    captured = capsys.readouterr()
    assert "sample.bin" in captured.out


def test_cli_command_base_and_config_version(tmp_path: Path) -> None:
    configure_logging_levels(verbose=False, quiet=True)
    configure_logging_levels(verbose=True, quiet=False)
    configure_quiet_logging(quiet=True)
    configure_quiet_logging(quiet=False)

    config = Config()
    apply_thread_settings(config, 2)
    apply_thread_settings(config, None)
    apply_thread_settings(config, "bad")

    context = CommandContext.create(config=config, verbose=True, quiet=False)
    command = _Command(context)
    assert isinstance(command._get_config(None), Config)
    assert isinstance(command._get_config(str(tmp_path / "config.json")), Config)
    no_config_context = CommandContext(console=Console(), logger=context.logger, config=None)
    command.context = no_config_context
    assert isinstance(command._get_config(None), Config)
    command = _Command()
    assert isinstance(command.context, CommandContext)

    assert command._setup_analysis_options() == {}
    assert command._setup_analysis_options(yara="rules", xor="aa") == {
        "yara_rules_dir": "rules",
        "xor_search": "aa",
    }

    console, _buffer = _console_buffer()
    context.console = console

    version_cmd = VersionCommand(context)
    assert version_cmd.execute({}) == 0

    config_cmd = ConfigCommand(context)
    assert config_cmd.execute({"list_yara": False}) == 0

    missing_rules = tmp_path / "missing"
    assert config_cmd.execute({"list_yara": True, "yara": str(missing_rules), "config": None}) == 1

    empty_rules = tmp_path / "rules"
    empty_rules.mkdir()
    assert config_cmd.execute({"list_yara": True, "yara": str(empty_rules), "config": None}) == 0

    rule_dir = tmp_path / "rules_real"
    rule_dir.mkdir()
    rule_file = rule_dir / "demo.yar"
    rule_file.write_text("rule demo { condition: true }")
    assert config_cmd.execute({"list_yara": True, "yara": str(rule_dir), "config": None}) == 0
    other_rule = tmp_path / "other.yar"
    other_rule.write_text("rule other { condition: true }")
    config_cmd._display_yara_rules_table([other_rule], rule_dir)
    assert config_cmd._format_file_size(1024**3 * 2) == "2.0 GB"


def test_interactive_command_dispatch_and_execute(tmp_path: Path) -> None:
    console, _buffer = _console_buffer()
    context = CommandContext.create(config=Config())
    context.console = console

    command = InteractiveCommand(context)
    inspector = _Inspector()

    original_stdin = sys.stdin
    try:
        sys.stdin = io.StringIO(
            "\nhelp\ninfo\npe\nimports\nexports\nsections\nstrings\nanalyze\nunknown\nquit\n"
        )
        command._run_interactive_mode(inspector, {})
    finally:
        sys.stdin = original_stdin

    assert command._should_exit("quit") is True
    assert command._should_exit("x") is False

    ok_args = {"filename": str(_sample_path()), "config": None, "verbose": False}
    try:
        sys.stdin = io.StringIO("quit\n")
        assert command.execute(ok_args) == 0
    finally:
        sys.stdin = original_stdin

    bad_args = {"filename": str(tmp_path / "missing.bin"), "config": None, "verbose": True}
    assert command.execute(bad_args) == 1

    class _ExplodingInspector(_Inspector):
        def get_strings(self) -> list[str]:
            raise RuntimeError()

    try:
        sys.stdin = io.StringIO("strings\n")
        command._run_interactive_mode(_ExplodingInspector(), {})
    finally:
        sys.stdin = original_stdin

    try:
        sys.stdin = io.StringIO("")
        command._run_interactive_mode(inspector, {})
    finally:
        sys.stdin = original_stdin

    command._handle_error(RuntimeError("boom"), verbose=False)


def test_analyze_command_run_paths(tmp_path: Path) -> None:
    console, _buffer = _console_buffer()
    context = CommandContext.create(config=Config())
    context.console = console

    command = AnalyzeCommand(context)
    inspector = _Inspector()

    reset_error_stats()
    reset_retry_stats()
    reset_circuit_breakers()

    @error_handler(fallback_result={"error": "fallback"})
    def _boom() -> dict[str, str]:
        raise RuntimeError("boom")

    _boom()

    attempts = {"count": 0}

    def _retry_once(**_kwargs: object) -> str:
        attempts["count"] += 1
        if attempts["count"] < 2:
            raise TimeoutError("retry timeout")
        return "ok"

    global_retry_manager.retry_operation(
        _retry_once,
        command="ij",
        config=RetryConfig(max_attempts=2, base_delay=0.01, max_delay=0.01),
    )

    policy = ErrorPolicy(strategy=ErrorHandlingStrategy.CIRCUIT_BREAK, circuit_threshold=1)

    @handle_errors(policy)
    def _circuit_fail() -> None:
        raise RuntimeError("fail")

    with pytest.raises(RuntimeError):
        _circuit_fail()

    command._display_verbose_statistics()

    command._run_analysis(
        inspector,
        {},
        output_json=False,
        output_csv=False,
        output_file=None,
        verbose=True,
    )

    command._run_analysis(
        inspector,
        {},
        output_json=True,
        output_csv=False,
        output_file=tmp_path / "out.json",
        verbose=False,
    )

    command._run_analysis(
        inspector,
        {},
        output_json=False,
        output_csv=True,
        output_file=tmp_path / "out.csv",
        verbose=False,
    )

    command._output_json_results(
        analysis_runner.OutputFormatter({"file_info": {"name": "sample.bin"}}), None
    )
    command._output_csv_results(
        analysis_runner.OutputFormatter({"file_info": {"name": "sample.bin"}}), None
    )

    ok_args = {
        "filename": str(_sample_path()),
        "config": None,
        "yara": None,
        "xor": None,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "verbose": False,
        "threads": 1,
    }
    assert command.execute(ok_args) == 0

    bad_args = {
        "filename": str(tmp_path / "missing.bin"),
        "config": None,
        "yara": None,
        "xor": None,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "verbose": True,
        "threads": 1,
    }
    assert command.execute(bad_args) == 1
    command._handle_error(RuntimeError("boom"), verbose=False)


def test_analyze_command_keyboard_interrupt() -> None:
    console, _buffer = _console_buffer()
    context = CommandContext.create(config=Config())
    context.console = console

    command = AnalyzeCommand(context)
    ok_args = {
        "filename": str(_sample_path()),
        "config": None,
        "yara": None,
        "xor": None,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "verbose": False,
        "threads": 1,
    }
    result = _run_with_sigint(lambda: command.execute(ok_args))
    assert result == 1


def test_batch_command_and_processing_real(tmp_path: Path) -> None:
    console, _buffer = _console_buffer()
    context = CommandContext.create(config=Config())
    context.console = console

    batch_cmd = BatchCommand(context)
    batch_cmd._setup_batch_mode("batch", None, True, False, None)
    batch_cmd._setup_analysis_options(yara="rules", xor="aa")
    batch_cmd._handle_error(RuntimeError("boom"), verbose=False)

    batch_dir = tmp_path / "batch"
    batch_dir.mkdir()
    sample = batch_dir / "hello_elf"
    sample.write_bytes(_sample_path().read_bytes())

    ok_args = {
        "batch": str(batch_dir),
        "config": None,
        "yara": None,
        "xor": None,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "extensions": None,
        "threads": 1,
        "verbose": False,
        "quiet": True,
    }
    os.environ["R2INSPECT_DISABLE_FORCED_EXIT"] = "1"
    try:
        assert batch_cmd.execute(ok_args) == 0
    finally:
        os.environ.pop("R2INSPECT_DISABLE_FORCED_EXIT", None)

    sample_elf = batch_dir / "sample.elf"
    sample_elf.write_bytes(_sample_path().read_bytes())
    bad_args = {
        "batch": str(batch_dir),
        "config": None,
        "yara": None,
        "xor": None,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "extensions": "elf",
        "threads": 0,
        "verbose": True,
        "quiet": False,
    }
    assert batch_cmd.execute(bad_args) == 1


def test_batch_command_keyboard_interrupt(tmp_path: Path) -> None:
    console, _buffer = _console_buffer()
    context = CommandContext.create(config=Config())
    context.console = console

    batch_cmd = BatchCommand(context)
    batch_dir = tmp_path / "batch"
    batch_dir.mkdir()
    sample = batch_dir / "hello_elf"
    sample.write_bytes(_sample_path().read_bytes())

    ok_args = {
        "batch": str(batch_dir),
        "config": None,
        "yara": None,
        "xor": None,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "extensions": None,
        "threads": 1,
        "verbose": False,
        "quiet": True,
    }
    os.environ["R2INSPECT_DISABLE_FORCED_EXIT"] = "1"
    try:
        result = _run_with_sigint(lambda: batch_cmd.execute(ok_args))
    finally:
        os.environ.pop("R2INSPECT_DISABLE_FORCED_EXIT", None)
    assert result == 1


def test_batch_output_and_processing_helpers(tmp_path: Path) -> None:
    console, _buffer = _console_buffer()
    original_console = batch_output.console
    batch_output.console = console
    try:
        batch_output.get_csv_fieldnames()
        csv_path = tmp_path / "summary.csv"
        batch_output.write_csv_results(csv_path, {"f": {"file_info": {"name": "a"}}})
        assert csv_path.exists()

        direct_file = tmp_path / "out.csv"
        csv_file, csv_name = batch_output.determine_csv_file_path(direct_file, "t")
        assert csv_file == direct_file
        assert csv_name == direct_file.name

        csv_dir = tmp_path / "outdir"
        csv_file, csv_name = batch_output.determine_csv_file_path(csv_dir, "t")
        assert csv_file.parent == csv_dir
        assert csv_name.startswith("r2inspect_")

        stats = batch_output.collect_batch_statistics(
            {
                "f": {
                    "packer_info": {"detected": True, "name": "UPX"},
                    "crypto_info": ["aes"],
                    "indicators": [{"type": "anti_vm"}],
                    "file_info": {"file_type": "ELF", "architecture": "x64"},
                    "compiler": {"detected": True, "compiler": "GCC"},
                }
            }
        )
        assert stats["packers_detected"]
        assert stats["crypto_patterns"]
        assert stats["suspicious_indicators"]
        assert stats["file_types"]
        assert stats["architectures"]
        assert stats["compilers"]

        summary = batch_output.create_json_batch_summary(
            {"f": {"file_info": {"name": "a"}}},
            [("a", "err")],
            tmp_path,
            "t",
        )
        assert "r2inspect_batch_t.json" in summary

        auto_files = batch_output.find_files_to_process(
            tmp_path, auto_detect=False, extensions=None, recursive=False, verbose=False, quiet=True
        )
        assert auto_files == []

        ext_file = tmp_path / "one.exe"
        ext_file.write_bytes(b"MZ" + b"\x00" * 64)
        found = batch_output.find_files_to_process(
            tmp_path,
            auto_detect=False,
            extensions="exe",
            recursive=False,
            verbose=False,
            quiet=False,
        )
        assert ext_file in found

        batch_output.display_no_files_message(auto_detect=True, extensions=None)
        batch_output.display_no_files_message(auto_detect=False, extensions="exe")

        batch_output.setup_batch_output_directory(str(tmp_path / "out.json"), True, False)
        batch_output.setup_batch_output_directory(
            str(tmp_path / "newdir" / "out.json"), True, False
        )
        batch_output.setup_batch_output_directory(str(tmp_path / "dir"), True, False)
        batch_output.setup_batch_output_directory(None, True, False)
        batch_output.setup_batch_output_directory(None, False, False)

        batch_output._configure_batch_logging(verbose=False, quiet=True)

        prepared = batch_output._prepare_batch_run(
            tmp_path,
            auto_detect=False,
            extensions="exe",
            recursive=False,
            verbose=False,
            quiet=False,
            output_dir=None,
            output_json=False,
            output_csv=False,
            threads=1,
        )
        assert prepared is not None
        assert batch_output._init_batch_results() == ({}, [])

        batch_output.create_batch_summary(
            {f"f{i}": {"file_info": {"name": f"f{i}", "file_type": "PE32"}} for i in range(11)},
            [],
            tmp_path,
            output_json=False,
            output_csv=True,
        )
        batch_output.create_batch_summary(
            {"f": {"file_info": {"name": "f", "file_type": "ELF"}}},
            [],
            tmp_path / "summary.csv",
            output_json=True,
            output_csv=True,
        )

        assert batch_output._extract_compile_time({}) == "N/A"
        assert batch_output._extract_compile_time({"pe_info": {"compile_time": "today"}}) == "today"
        assert batch_output._compiler_name({"compiler": {"detected": True, "compiler": "GCC"}})
        assert batch_output._collect_yara_matches({"yara_matches": "nope"}) == "None"

        class _Rule:
            rule = "r3"

        assert (
            batch_output._collect_yara_matches({"yara_matches": [{"rule": "r1"}, _Rule(), "r2"]})
            == "r1, r3, r2"
        )

        class _BadResult:
            def get(self, *_args: object, **_kwargs: object) -> object:
                raise RuntimeError("boom")

        assert batch_output._build_small_row("f", _BadResult())[1] == "Error"
        assert batch_output._build_large_row("f", _BadResult())[1] == "Error"

        batch_output.run_batch_analysis(
            batch_dir=str(tmp_path),
            options={},
            output_json=False,
            output_csv=False,
            output_dir=str(tmp_path / "outdir"),
            recursive=False,
            extensions="exe",
            verbose=False,
            config_obj=Config(),
            auto_detect=False,
            threads=1,
            quiet=True,
        )
        empty_dir = tmp_path / "empty_batch"
        empty_dir.mkdir()
        batch_output.run_batch_analysis(
            batch_dir=str(empty_dir),
            options={},
            output_json=False,
            output_csv=False,
            output_dir=None,
            recursive=False,
            extensions="exe",
            verbose=False,
            config_obj=Config(),
            auto_detect=False,
            threads=1,
            quiet=True,
        )
    finally:
        batch_output.console = original_console


def test_batch_processing_core_and_error_paths(tmp_path: Path) -> None:
    console, _buffer = _console_buffer()
    original_console = batch_processing.console
    original_magic = batch_processing.magic
    batch_processing.console = console
    try:
        batch_processing.magic = None
        assert batch_processing.find_executable_files_by_magic(tmp_path) == []

        batch_processing.magic = original_magic

        assert batch_processing._is_executable_signature("application/x-dosexec", "") is True
        assert batch_processing._is_executable_signature("text/plain", "ELF") is True

        nested = tmp_path / "nested"
        nested.mkdir()
        (nested / "a.bin").write_bytes(b"MZ" + b"\x00" * 64)

        small = tmp_path / "small.bin"
        small.write_bytes(b"MZ")

        sample_magic = tmp_path / "sample_magic"
        sample_magic.write_bytes(_sample_path().read_bytes())
        found = batch_processing.find_executable_files_by_magic(
            tmp_path, recursive=False, verbose=True
        )
        assert sample_magic in found

        no_access = tmp_path / "no_access.bin"
        no_access.write_bytes(b"MZ" + b"\x00" * 100)
        no_access.chmod(0)
        try:
            batch_processing.find_executable_files_by_magic(tmp_path, recursive=False, verbose=True)
        finally:
            no_access.chmod(0o644)

        assert batch_processing.check_executable_signature(small) is False
        assert batch_processing.check_executable_signature(tmp_path / "missing.bin") is False

        assert batch_processing.is_pe_executable(b"NO", io.BytesIO(b"NO")) is False
        pe_header = bytearray(b"MZ" + b"\x00" * 62)
        pe_header[60:64] = (64).to_bytes(4, byteorder="little")
        pe_header += b"PE\x00\x00" + b"\x00" * 32
        assert (
            batch_processing.is_pe_executable(bytes(pe_header), io.BytesIO(bytes(pe_header)))
            is True
        )
        assert batch_processing.is_elf_executable(b"\x7fELF") is True
        assert batch_processing.is_macho_executable(b"\xfe\xed\xfa\xcf") is True
        assert batch_processing.is_script_executable(b"#!/bin") is True

        rate_limiter = batch_processing.setup_rate_limiter(threads=1, verbose=True)
        batch_processing.display_rate_limiter_stats(rate_limiter.get_stats())
        batch_processing.display_failed_files([("a", "err")], verbose=False)
        batch_processing.display_failed_files([("a", "err")], verbose=True)

        limiter = batch_processing.setup_rate_limiter(threads=1, verbose=False)
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        file_path = tmp_path / "sample"
        file_path.write_bytes(_sample_path().read_bytes())

        file_key, results, error = batch_processing.process_single_file(
            file_path,
            tmp_path,
            Config(),
            {},
            output_json=True,
            output_path=output_dir,
            rate_limiter=limiter,
        )
        assert file_key == file_path
        assert results is not None
        assert error is None
        assert (output_dir / f"{file_path.stem}_analysis.json").exists()

        class _DenyingRateLimiter(BatchRateLimiter):
            def acquire(self, timeout: float | None = 60.0) -> bool:
                return False

        limited = _DenyingRateLimiter(max_concurrent=1, rate_per_second=1.0)
        file_key, results, error = batch_processing.process_single_file(
            file_path,
            tmp_path,
            Config(),
            {},
            output_json=False,
            output_path=output_dir,
            rate_limiter=limited,
        )
        assert results is None
        assert error

        missing_file = tmp_path / "missing.bin"
        file_key, results, error = batch_processing.process_single_file(
            missing_file,
            tmp_path,
            Config(),
            {},
            output_json=False,
            output_path=output_dir,
            rate_limiter=limiter,
        )
        assert results is None
        assert error

        all_results: dict[str, dict[str, object]] = {}
        failed_files: list[tuple[str, str]] = []
        batch_processing.process_files_parallel(
            [file_path],
            all_results,
            failed_files,
            output_dir,
            tmp_path,
            Config(),
            {},
            output_json=False,
            threads=1,
            rate_limiter=limiter,
        )
        assert all_results

        class _BadOptions:
            def keys(self) -> object:
                raise Exception()

        more_failed: list[tuple[str, str]] = []
        batch_processing.process_files_parallel(
            [file_path],
            {},
            more_failed,
            output_dir,
            tmp_path,
            Config(),
            _BadOptions(),
            output_json=False,
            threads=1,
            rate_limiter=limiter,
        )
        assert more_failed

        os.environ["R2INSPECT_MAX_THREADS"] = "1"
        try:
            assert batch_processing._cap_threads_for_execution(threads=4) == 1
            os.environ["R2INSPECT_MAX_THREADS"] = "bad"
            assert batch_processing._cap_threads_for_execution(threads=4) == 4
            os.environ["R2INSPECT_MAX_THREADS"] = "-1"
            assert batch_processing._cap_threads_for_execution(threads=4) == 4
        finally:
            os.environ.pop("R2INSPECT_MAX_THREADS", None)

        batch_processing.display_batch_results(
            all_results,
            failed_files,
            elapsed_time=1.0,
            files_to_process=[file_path],
            rate_limiter=limiter,
            verbose=True,
            output_filename="summary.csv",
        )

        batch_processing.setup_batch_mode("batch", None, True, False, None)
        batch_processing.setup_single_file_output(True, False, None, "sample.bin")
        batch_processing.setup_single_file_output(False, True, None, "sample.bin")
        batch_processing.setup_analysis_options(None, None)

        with pytest.raises(SystemExit):
            batch_processing.handle_main_error(RuntimeError("boom"), verbose=False)
        with pytest.raises(SystemExit):
            batch_processing.handle_main_error(RuntimeError("boom"), verbose=True)

        batch_processing.display_failed_files([("a", "err")] * 11, verbose=True)

        batch_processing.find_files_to_process(
            tmp_path, auto_detect=True, extensions=None, recursive=False, verbose=False, quiet=False
        )
        batch_processing.setup_batch_output_directory(
            str(tmp_path / "newdir" / "out.csv"), True, False
        )

        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        batch_processing.run_batch_analysis(
            batch_dir=str(empty_dir),
            options={},
            output_json=False,
            output_csv=False,
            output_dir=str(tmp_path / "outdir2"),
            recursive=False,
            extensions="none",
            verbose=False,
            config_obj=Config(),
            auto_detect=False,
            threads=1,
            quiet=False,
        )
        batch_processing.run_batch_analysis(
            batch_dir=str(tmp_path),
            options={},
            output_json=False,
            output_csv=False,
            output_dir=str(tmp_path / "outdir3"),
            recursive=False,
            extensions="bin",
            verbose=False,
            config_obj=Config(),
            auto_detect=False,
            threads=1,
            quiet=False,
        )

        os.environ["R2INSPECT_TEST_SAFE_EXIT"] = "1"
        try:
            linger = threading.Thread(target=lambda: threading.Event().wait(0.2))
            linger.start()
            with pytest.raises(SystemExit):
                batch_processing.ensure_batch_shutdown(timeout=0.01)
            with pytest.raises(SystemExit):
                batch_processing.ensure_batch_shutdown(timeout=0.0)
            batch_processing.schedule_forced_exit(delay=0.01)
            time.sleep(0.05)
            os.environ["PYTEST_CURRENT_TEST"] = "1"
            batch_processing._flush_coverage_data()
            assert batch_processing._pytest_running() is True
            os.environ["R2INSPECT_TEST_COVERAGE_IMPORT_ERROR"] = "1"
            batch_processing._flush_coverage_data()
            os.environ.pop("R2INSPECT_TEST_COVERAGE_IMPORT_ERROR", None)
            os.environ["R2INSPECT_TEST_COVERAGE_CURRENT_ERROR"] = "1"
            batch_processing._flush_coverage_data()
            os.environ.pop("R2INSPECT_TEST_COVERAGE_CURRENT_ERROR", None)
            os.environ["R2INSPECT_TEST_COVERAGE_NONE"] = "1"
            batch_processing._flush_coverage_data()
            os.environ.pop("R2INSPECT_TEST_COVERAGE_NONE", None)
            os.environ["R2INSPECT_TEST_COVERAGE_SAVE_ERROR"] = "1"
            batch_processing._flush_coverage_data()
            os.environ.pop("R2INSPECT_TEST_COVERAGE_SAVE_ERROR", None)
            os.environ.pop("PYTEST_CURRENT_TEST", None)
            saved_pytest = sys.modules.pop("pytest", None)
            os.environ["R2INSPECT_TEST_COVERAGE_DUMMY"] = "1"
            batch_processing._flush_coverage_data()
            os.environ.pop("R2INSPECT_TEST_COVERAGE_DUMMY", None)
            if saved_pytest is not None:
                sys.modules["pytest"] = saved_pytest
            assert batch_processing._pytest_running() is True
        finally:
            os.environ.pop("PYTEST_CURRENT_TEST", None)
            os.environ.pop("R2INSPECT_TEST_SAFE_EXIT", None)
            linger.join()

        original_exit = os._exit
        try:
            os._exit = lambda _code=0: None  # type: ignore[assignment]
            with pytest.raises(SystemExit):
                batch_processing._safe_exit(0)
        finally:
            os._exit = original_exit

        batch_processing.get_csv_fieldnames()
        csv_path = tmp_path / "batch.csv"
        batch_processing.write_csv_results(csv_path, {"f": {"file_info": {"name": "a"}}})
        assert csv_path.exists()

        direct_file = tmp_path / "out.csv"
        csv_file, csv_name = batch_processing.determine_csv_file_path(direct_file, "t")
        assert csv_file == direct_file
        assert csv_name == direct_file.name

        csv_dir = tmp_path / "outdir"
        csv_file, csv_name = batch_processing.determine_csv_file_path(csv_dir, "t")
        assert csv_file.parent == csv_dir
        assert csv_name.startswith("r2inspect_")

        stats = batch_processing.collect_batch_statistics(
            {
                "f": {
                    "packer_info": {"detected": True, "name": "UPX"},
                    "crypto_info": ["aes"],
                    "indicators": [{"type": "anti_vm"}],
                    "file_info": {"file_type": "ELF", "architecture": "x64"},
                    "compiler": {"detected": True, "compiler": "GCC"},
                }
            }
        )
        assert stats["packers_detected"]

        summary = batch_processing.create_json_batch_summary(
            {"f": {"file_info": {"name": "a"}}},
            [("a", "err")],
            tmp_path,
            "t",
        )
        assert "r2inspect_batch_t.json" in summary

        assert (
            batch_processing.find_files_to_process(
                tmp_path,
                auto_detect=False,
                extensions=None,
                recursive=False,
                verbose=False,
                quiet=True,
            )
            == []
        )
        batch_processing.find_files_to_process(
            tmp_path,
            auto_detect=False,
            extensions="exe",
            recursive=False,
            verbose=False,
            quiet=True,
        )

        batch_processing.display_no_files_message(auto_detect=True, extensions=None)
        batch_processing.display_no_files_message(auto_detect=False, extensions="exe")

        batch_processing.setup_batch_output_directory(str(tmp_path / "out.json"), True, False)
        batch_processing.setup_batch_output_directory(str(tmp_path / "dir"), True, False)
        batch_processing.setup_batch_output_directory(None, True, False)
        batch_processing.setup_batch_output_directory(None, False, False)

        ext_file = tmp_path / "sample.bin"
        ext_file.write_bytes(_sample_path().read_bytes())

        batch_processing.run_batch_analysis(
            batch_dir=str(tmp_path),
            options={},
            output_json=False,
            output_csv=False,
            output_dir=str(tmp_path / "outdir"),
            recursive=False,
            extensions="bin",
            verbose=False,
            config_obj=Config(),
            auto_detect=False,
            threads=1,
            quiet=True,
        )
    finally:
        batch_processing.console = original_console
        batch_processing.magic = original_magic
