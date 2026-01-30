import io
import logging

from rich.console import Console

from r2inspect.cli.commands.analyze_command import AnalyzeCommand
from r2inspect.cli.commands.base import (
    Command,
    CommandContext,
    apply_thread_settings,
    configure_quiet_logging,
)
from r2inspect.cli.commands.batch_command import BatchCommand
from r2inspect.cli.commands.config_command import ConfigCommand
from r2inspect.cli.commands.interactive_command import InteractiveCommand
from r2inspect.cli.commands.version_command import VersionCommand
from r2inspect.config import Config
from r2inspect.utils.logger import get_logger


class _DummyCommand(Command):
    def execute(self, args):
        return args.get("code", 0)


class _FakeInspector:
    def __init__(self, analyze_result=None):
        self._analyze_result = analyze_result or {"file_info": {"name": "sample", "size": 1}}

    def analyze(self, **_kwargs):
        return dict(self._analyze_result)

    def get_strings(self):
        return ["one", "two"]

    def get_file_info(self):
        return {"name": "sample.bin", "size": 10}

    def get_pe_info(self):
        return {"compile_time": "now"}

    def get_imports(self):
        return ["kernel32.dll"]

    def get_exports(self):
        return ["ExportedFunc"]

    def get_sections(self):
        return [{"name": ".text", "size": 100}]


def _make_console():
    return Console(file=io.StringIO(), record=True, width=120)


def _make_context(tmp_path, **kwargs):
    config = Config(str(tmp_path / "config.json"))
    return CommandContext(
        console=kwargs.get("console", _make_console()),
        logger=kwargs.get("logger", get_logger()),
        config=config,
        verbose=kwargs.get("verbose", False),
        quiet=kwargs.get("quiet", False),
    )


def test_configure_quiet_logging_sets_levels():
    configure_quiet_logging(True)
    assert logging.getLogger("r2pipe").level == logging.CRITICAL
    assert logging.getLogger("r2inspect").level == logging.WARNING


def test_apply_thread_settings_updates_config(tmp_path):
    config = Config(str(tmp_path / "config.json"))
    apply_thread_settings(config, 1)
    assert config.get("pipeline", "max_workers") == 1
    assert config.get("pipeline", "parallel_execution") is False


def test_command_context_create_uses_config(tmp_path):
    config = Config(str(tmp_path / "config.json"))
    context = CommandContext.create(config=config, verbose=True, quiet=True)
    assert context.config is config
    assert context.verbose is True
    assert context.quiet is True


def test_command_get_config_falls_back_to_context(tmp_path):
    cmd = _DummyCommand(_make_context(tmp_path))
    config = cmd._get_config(None)
    assert isinstance(config, Config)


def test_command_setup_analysis_options(tmp_path):
    cmd = _DummyCommand(_make_context(tmp_path))
    options = cmd._setup_analysis_options(yara="/rules", xor="ff")
    assert options == {"yara_rules_dir": "/rules", "xor_search": "ff"}


def test_analyze_command_run_analysis_writes_json(tmp_path):
    output_file = tmp_path / "result.json"
    context = _make_context(tmp_path)
    cmd = AnalyzeCommand(context)

    inspector = _FakeInspector({"file_info": {"name": "sample", "size": 1}})
    cmd._run_analysis(
        inspector=inspector,
        options={},
        output_json=True,
        output_csv=False,
        output_file=str(output_file),
        verbose=False,
    )

    assert output_file.exists()
    assert "sample" in output_file.read_text()


def test_analyze_command_print_status_when_console_output(tmp_path):
    console = _make_console()
    context = _make_context(tmp_path, console=console)
    cmd = AnalyzeCommand(context)
    cmd._print_status_if_needed(output_json=False, output_csv=False, output_file=None)
    text = console.export_text()
    assert "Starting analysis" in text


def test_batch_command_setup_batch_mode_defaults_output(tmp_path):
    cmd = BatchCommand(_make_context(tmp_path))
    recursive, auto_detect, output = cmd._setup_batch_mode(
        _batch="/tmp",
        extensions=None,
        output_json=True,
        output_csv=False,
        output=None,
    )
    assert recursive is True
    assert auto_detect is True
    assert output == "output"


def test_batch_command_setup_analysis_options(tmp_path):
    cmd = BatchCommand(_make_context(tmp_path))
    options = cmd._setup_analysis_options(yara="/rules", xor="aa")
    assert options["detect_packer"] is True
    assert options["detect_crypto"] is True
    assert options["detect_av"] is True
    assert options["full_analysis"] is True
    assert options["custom_yara"] == "/rules"
    assert options["xor_search"] == "aa"


def test_config_command_list_yara_rules_missing_dir(tmp_path):
    console = _make_console()
    cmd = ConfigCommand(_make_context(tmp_path, console=console))
    missing = tmp_path / "missing"
    status = cmd._list_yara_rules(yara_path=str(missing))
    assert status == 1
    assert "YARA rules directory not found" in console.export_text()


def test_config_command_list_yara_rules(tmp_path):
    rules_path = tmp_path / "rules"
    rules_path.mkdir()
    (rules_path / "one.yar").write_text("rule one {}")
    nested = rules_path / "nested"
    nested.mkdir()
    (nested / "two.yara").write_text("rule two {}")

    console = _make_console()
    cmd = ConfigCommand(_make_context(tmp_path, console=console))
    status = cmd._list_yara_rules(yara_path=str(rules_path))

    assert status == 0
    text = console.export_text()
    assert "one.yar" in text
    assert "two.yara" in text


def test_config_command_format_file_size(tmp_path):
    cmd = ConfigCommand(_make_context(tmp_path))
    assert cmd._format_file_size(1) == "1.0 B"
    assert cmd._format_file_size(1024) == "1.0 KB"


def test_interactive_command_should_exit(tmp_path):
    cmd = InteractiveCommand(_make_context(tmp_path))
    assert cmd._should_exit("quit") is True
    assert cmd._should_exit("exit") is True
    assert cmd._should_exit("q") is True
    assert cmd._should_exit("other") is False


def test_interactive_command_execute_known_commands(tmp_path, monkeypatch):
    console = _make_console()
    context = _make_context(tmp_path, console=console)
    cmd = InteractiveCommand(context)
    inspector = _FakeInspector()

    from r2inspect.cli import display as display_module

    monkeypatch.setattr(display_module, "console", console)

    cmd._execute_interactive_command("strings", inspector, {})
    cmd._execute_interactive_command("info", inspector, {})
    cmd._execute_interactive_command("pe", inspector, {})
    cmd._execute_interactive_command("imports", inspector, {})
    cmd._execute_interactive_command("exports", inspector, {})
    cmd._execute_interactive_command("sections", inspector, {})

    text = console.export_text()
    assert "one" in text
    assert "File Information" in text
    assert "PE Information" in text
    assert "kernel32.dll" in text
    assert "ExportedFunc" in text


def test_interactive_command_unknown_command(tmp_path):
    console = _make_console()
    cmd = InteractiveCommand(_make_context(tmp_path, console=console))
    cmd._execute_interactive_command("unknown", _FakeInspector(), {})
    text = console.export_text()
    assert "Unknown command" in text
    assert "help" in text


def test_version_command_outputs_version(tmp_path):
    console = _make_console()
    cmd = VersionCommand(_make_context(tmp_path, console=console))
    status = cmd.execute({})
    assert status == 0
    text = console.export_text()
    assert "r2inspect" in text
    assert "Author" in text
    assert "License" in text
    assert "Repository" in text
