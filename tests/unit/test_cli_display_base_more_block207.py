from __future__ import annotations

from pathlib import Path

from r2inspect.cli import display_base as db


def test_format_hash_display() -> None:
    assert db.format_hash_display(None) == "N/A"
    assert db.format_hash_display("N/A") == "N/A"
    assert db.format_hash_display("abc") == "abc"
    assert db.format_hash_display("x" * 40, max_length=10) == "x" * 10 + "..."


def test_create_info_table() -> None:
    table = db.create_info_table("Test", prop_width=10, value_min_width=20)
    assert table.title == "Test"


def test_print_banner_fallback(capsys) -> None:
    original = db._get_console
    db.pyfiglet = None

    class BadConsole:
        def print(self, *args, **kwargs):
            raise RuntimeError("boom")

    db._get_console = lambda: BadConsole()  # type: ignore[assignment]
    try:
        db.print_banner()
        out = capsys.readouterr().out
        assert "r2inspect" in out
    finally:
        db._get_console = original


def test_display_validation_errors(capsys) -> None:
    db.display_validation_errors(["a", "b"])
    out = capsys.readouterr().out
    assert "Error: a" in out
    assert "Error: b" in out


def test_handle_list_yara_option(tmp_path: Path, capsys) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "rule.yar").write_text("rule test { condition: true }")
    db.handle_list_yara_option({}, str(rules_dir))
    out = capsys.readouterr().out
    assert "Available YARA Rules" in out or "YARA rule file" in out


def test_display_yara_rules_table(capsys) -> None:
    db.display_yara_rules_table(
        [{"name": "a.yar", "path": "/tmp/a.yar", "size": 1024, "relative_path": "a.yar"}],
        "/tmp",
    )
    out = capsys.readouterr().out
    assert "a.yar" in out
