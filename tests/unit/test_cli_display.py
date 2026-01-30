import io

from rich.console import Console

from r2inspect.cli import display as display_module


def _make_console():
    return Console(file=io.StringIO(), record=True, width=120)


def _get_text(console: Console) -> str:
    return console.export_text()


def test_format_hash_display():
    assert display_module.format_hash_display(None) == "N/A"
    assert display_module.format_hash_display("N/A") == "N/A"
    short = "abcd"
    assert display_module.format_hash_display(short, max_length=8) == short
    long_hash = "a" * 40
    assert display_module.format_hash_display(long_hash, max_length=16) == ("a" * 16 + "...")


def test_create_info_table_columns():
    table = display_module.create_info_table("Info")
    assert table.title == "Info"
    assert len(table.columns) == 2
    assert table.columns[0].header == "Property"
    assert table.columns[1].header == "Value"


def test_display_error_statistics_outputs(monkeypatch):
    console = _make_console()
    monkeypatch.setattr(display_module, "console", console)

    stats = {
        "total_errors": 2,
        "recent_errors": 1,
        "recovery_strategies_available": 3,
        "errors_by_category": {"file_io": 2},
        "errors_by_severity": {"critical": 1, "low": 1},
    }

    display_module.display_error_statistics(stats)
    text = _get_text(console)

    assert "Error Statistics" in text
    assert "Analysis Error Summary" in text
    assert "Total Errors" in text
    assert "File Io" in text
    assert "Critical" in text


def test_display_performance_statistics_outputs(monkeypatch):
    console = _make_console()
    monkeypatch.setattr(display_module, "console", console)

    retry_stats = {
        "total_retries": 2,
        "successful_retries": 1,
        "failed_after_retries": 1,
        "success_rate": 50.0,
        "commands_retried": {"aaa": 2, "bbb": 1},
    }
    circuit_stats = {"open_count": 1, "total_failures": 0}

    display_module.display_performance_statistics(retry_stats, circuit_stats)
    text = _get_text(console)

    assert "Performance Statistics" in text
    assert "Retry Statistics" in text
    assert "Most Retried Commands" in text
    assert "Circuit Breaker" in text
    assert "Open Count" in text


def test_display_results_file_info_only(monkeypatch):
    console = _make_console()
    monkeypatch.setattr(display_module, "console", console)

    results = {
        "file_info": {
            "name": "sample.bin",
            "size": 123,
            "path": "/tmp/sample.bin",
            "mime_type": "application/octet-stream",
            "file_type": "data",
            "md5": "deadbeef",
            "sha1": "beef",
            "sha256": "cafe",
            "sha512": "feed",
            "enhanced_detection": {
                "file_format": "ELF",
                "format_category": "Executable",
                "architecture": "x86",
                "bits": 64,
                "endianness": "Little",
                "confidence": 0.5,
            },
            "threat_level": "Low",
        }
    }

    display_module.display_results(results)
    text = _get_text(console)

    assert "File Information" in text
    assert "sample.bin" in text
    assert "Threat Level" in text
