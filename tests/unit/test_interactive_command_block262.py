from __future__ import annotations

from r2inspect.cli.commands import CommandContext
from r2inspect.cli.commands.interactive_command import InteractiveCommand


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


def test_interactive_command_handlers():
    context = CommandContext.create(quiet=True)
    cmd = InteractiveCommand(context)
    inspector = DummyInspector()
    options = {"detect_packer": False}

    cmd._execute_interactive_command("strings", inspector, options)
    cmd._execute_interactive_command("info", inspector, options)
    cmd._execute_interactive_command("pe", inspector, options)
    cmd._execute_interactive_command("imports", inspector, options)
    cmd._execute_interactive_command("exports", inspector, options)
    cmd._execute_interactive_command("sections", inspector, options)
    cmd._execute_interactive_command("help", inspector, options)
    cmd._execute_interactive_command("analyze", inspector, options)
    cmd._execute_interactive_command("unknown", inspector, options)


def test_interactive_command_error_handler():
    context = CommandContext.create(quiet=True, verbose=False)
    cmd = InteractiveCommand(context)
    cmd._handle_error(RuntimeError("boom"), verbose=False)
    cmd._handle_error(RuntimeError("boom"), verbose=True)


def test_interactive_should_exit():
    context = CommandContext.create(quiet=True)
    cmd = InteractiveCommand(context)
    assert cmd._should_exit("quit") is True
    assert cmd._should_exit("exit") is True
    assert cmd._should_exit("q") is True
    assert cmd._should_exit("no") is False
