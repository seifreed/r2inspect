from __future__ import annotations

import io
import runpy
import sys
from pathlib import Path

from r2inspect.cli import display_base


def test_format_hash_display():
    assert display_base.format_hash_display(None) == "N/A"
    assert display_base.format_hash_display("N/A") == "N/A"
    assert display_base.format_hash_display("abcd", max_length=2) == "ab..."


def test_print_banner_fallback(monkeypatch):
    display_base.pyfiglet = None
    display_base.print_banner()

    class DummyFig:
        def figlet_format(self, *_args, **_kwargs):
            raise RuntimeError("boom")

    display_base.pyfiglet = DummyFig()
    display_base.print_banner()


def test_display_validation_errors(capsys):
    display_base.display_validation_errors(["a", "b"])
    out = capsys.readouterr().out
    assert "Error" in out


def test_display_yara_rules_table(capsys):
    display_base.display_yara_rules_table(
        [{"name": "r1", "size": 1024, "path": "/tmp/r1", "relative_path": "r1"}],
        "/tmp",
    )
    out = capsys.readouterr().out
    assert "YARA" in out


def test_handle_list_yara_option(tmp_path: Path, capsys):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rule = rules_dir / "test.yar"
    rule.write_text("rule test { condition: true }")

    display_base.handle_list_yara_option(config=None, yara=str(rules_dir))
    out = capsys.readouterr().out
    assert "YARA" in out or "No YARA rules" in out


def test_display_error_statistics(capsys):
    stats = {
        "total_errors": 2,
        "recent_errors": 1,
        "recovery_strategies_available": 0,
        "errors_by_category": {"file_access": 2},
        "errors_by_severity": {"critical": 1, "high": 1, "low": 0},
    }
    display_base.display_error_statistics(stats)
    out = capsys.readouterr().out
    assert "Error Statistics" in out


def test_display_performance_statistics(capsys):
    display_base.display_performance_statistics(
        {
            "total_retries": 1,
            "successful_retries": 1,
            "failed_after_retries": 0,
            "success_rate": 100.0,
            "commands_retried": {"ij": 1},
        },
        {"opened": 1},
    )
    out = capsys.readouterr().out
    assert "Performance Statistics" in out


def test_display_results_basic(capsys):
    display_base.display_results({"file_info": {"name": "x"}})
    out = capsys.readouterr().out
    assert "File Information" in out


def test_main_module_entrypoint():
    main_path = Path(display_base.__file__).parents[1] / "__main__.py"
    old_argv = sys.argv
    sys.argv = ["r2inspect", "--version"]
    try:
        runpy.run_path(str(main_path), run_name="__main__")
    except SystemExit:
        pass
    finally:
        sys.argv = old_argv
