from __future__ import annotations

from pathlib import Path

from r2inspect.cli import display_base


def _minimal_results() -> dict:
    return {
        "file_info": {"name": "sample.exe", "size": 1, "file_type": "PE", "md5": "m"},
        "pe_info": {"compile_time": "2026", "imphash": "h"},
        "security": {"aslr": True},
        "ssdeep": {"hash_value": "ss", "available": True},
        "tlsh": {"binary_tlsh": "bt", "available": True},
        "telfhash": {"telfhash": "th", "available": True},
        "rich_header": {"available": False},
        "impfuzzy": {"available": False},
        "ccbhash": {"available": True},
        "binlex": {"available": False},
        "binbloom": {"available": False},
        "simhash": {"available": False},
        "bindiff": {"available": False},
        "functions": {"total_functions": 0, "machoc_hashes": {}},
        "indicators": [],
    }


def test_format_hash_display_and_table() -> None:
    assert display_base.format_hash_display(None) == "N/A"
    assert display_base.format_hash_display("N/A") == "N/A"
    assert display_base.format_hash_display("x" * 40, max_length=10) == "x" * 10 + "..."
    assert display_base.format_hash_display("short", max_length=10) == "short"

    table = display_base.create_info_table("Info")
    assert table is not None


def test_print_banner_variants(monkeypatch) -> None:
    class DummyFiglet:
        def figlet_format(self, text: str, font: str = "slant") -> str:
            return f"{text}-{font}"

    monkeypatch.setattr(display_base, "pyfiglet", DummyFiglet())
    display_base.print_banner()

    monkeypatch.setattr(display_base, "pyfiglet", None)
    display_base.print_banner()


def test_display_validation_and_yara(tmp_path: Path) -> None:
    display_base.display_validation_errors(["err1", "err2"])

    # rules directory with files
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "test.yar").write_text("rule t { condition: true }")
    display_base.handle_list_yara_option(str(tmp_path / "config.json"), str(rules_dir))

    # rules directory empty
    empty_dir = tmp_path / "empty_rules"
    empty_dir.mkdir()
    display_base.handle_list_yara_option(str(tmp_path / "config2.json"), str(empty_dir))


def test_display_error_and_performance_stats() -> None:
    class Cat:
        value = "input_validation"

    error_stats = {
        "total_errors": 2,
        "recent_errors": 1,
        "errors_by_category": {Cat(): 1, "file_access": 1},
        "errors_by_severity": {"critical": 1, "high": 1, "low": 1},
        "recovery_strategies_available": 1,
    }
    display_base.display_error_statistics(error_stats)

    display_base.display_performance_statistics(
        retry_stats={
            "total_retries": 1,
            "successful_retries": 1,
            "failed_after_retries": 0,
            "success_rate": 100.0,
            "commands_retried": {"ij": 2},
        },
        circuit_stats={"opened": 1},
    )


def test_display_results() -> None:
    display_base.display_results(_minimal_results())
