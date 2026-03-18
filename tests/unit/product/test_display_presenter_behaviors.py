from __future__ import annotations

import io

from rich.console import Console

from r2inspect.cli import display as display_module
from r2inspect.cli import display_base, presenter


def _console_buffer() -> tuple[Console, io.StringIO]:
    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=False, width=120)
    return console, buffer


def test_display_base_banner_and_validation_errors_render_to_console() -> None:
    console, buffer = _console_buffer()
    original_console = display_module.console
    original_pyfiglet = display_base.pyfiglet
    try:
        display_module.console = console

        display_base.pyfiglet = None
        display_base.print_banner()
        display_base.display_validation_errors(["bad-input"])

        display_base.pyfiglet = type(
            "Fig",
            (),
            {"figlet_format": staticmethod(lambda *_args, **_kwargs: "banner")},
        )()
        display_base.print_banner()
    finally:
        display_module.console = original_console
        display_base.pyfiglet = original_pyfiglet

    rendered = buffer.getvalue()
    assert "bad-input" in rendered
    assert "banner" in rendered or "r2inspect" in rendered


def test_display_base_hash_formatting_and_presenter_helpers_behave_consistently() -> None:
    assert display_base.format_hash_display(None) == "N/A"
    assert display_base.format_hash_display("x" * 40, max_length=8).endswith("...")

    normalized = presenter.normalize_display_results({"file_info": {"name": "sample.bin"}})
    section, present = presenter.get_section(normalized, "file_info", {})
    assert present is True
    assert section["name"] == "sample.bin"

    missing, present_missing = presenter.get_section(normalized, "missing", {})
    assert missing == {}
    assert present_missing is False
