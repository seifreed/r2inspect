from __future__ import annotations

import io
from enum import Enum
from pathlib import Path

import pytest

from r2inspect.cli import display as display_module
from r2inspect.cli import display_base, display_sections


class _Category(Enum):
    INPUT_VALIDATION = "input_validation"


@pytest.mark.unit
def test_display_base_helpers_and_yara_table(tmp_path: Path) -> None:
    buffer = io.StringIO()
    original_file = display_module.console.file
    try:
        display_module.console.file = buffer

        assert display_base.format_hash_display(None) == "N/A"
        assert display_base.format_hash_display("N/A") == "N/A"
        assert display_base.format_hash_display("a" * 40, max_length=8) == "aaaaaaaa..."

        # Force banner without pyfiglet.
        original_pyfiglet = display_base.pyfiglet
        display_base.pyfiglet = None
        display_base.print_banner()
        display_base.pyfiglet = original_pyfiglet

        display_base.display_validation_errors(["boom"])

        rules = [
            {"name": "demo.yar", "size": 2048, "path": "/tmp/demo.yar", "relative_path": "demo.yar"}
        ]
        display_base.display_yara_rules_table(rules, str(tmp_path))
    finally:
        display_module.console.file = original_file

    output = buffer.getvalue()
    assert "Advanced Malware Analysis Tool" in output
    assert "Error: boom" in output
    assert "demo.yar" in output


@pytest.mark.unit
def test_handle_list_yara_option_no_rules(tmp_path: Path) -> None:
    buffer = io.StringIO()
    original_file = display_module.console.file
    try:
        display_module.console.file = buffer
        display_base.handle_list_yara_option(config=None, yara=str(tmp_path))
    finally:
        display_module.console.file = original_file

    output = buffer.getvalue()
    assert "No YARA rules found" in output


@pytest.mark.unit
def test_handle_list_yara_option_with_rules(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "sample.yar").write_text("rule sample { condition: true }")

    buffer = io.StringIO()
    original_file = display_module.console.file
    try:
        display_module.console.file = buffer
        display_base.handle_list_yara_option(config=None, yara=str(rules_dir))
    finally:
        display_module.console.file = original_file

    output = buffer.getvalue()
    assert "Available YARA Rules" in output or "Available YARA Rules in" in output


@pytest.mark.unit
def test_display_error_and_performance_statistics() -> None:
    buffer = io.StringIO()
    original_file = display_module.console.file
    try:
        display_module.console.file = buffer
        display_base.display_error_statistics(
            {
                "total_errors": 3,
                "recent_errors": 1,
                "recovery_strategies_available": 2,
                "errors_by_category": {_Category.INPUT_VALIDATION: 2, "io_error": 1},
                "errors_by_severity": {"critical": 1, "high": 1, "low": 1},
            }
        )

        display_base.display_performance_statistics(
            {
                "total_retries": 2,
                "successful_retries": 1,
                "failed_after_retries": 1,
                "success_rate": 50.0,
                "commands_retried": {"aa": 3, "ij": 1},
            },
            {"open_failures": 2, "half_open_successes": 1},
        )
    finally:
        display_module.console.file = original_file

    output = buffer.getvalue()
    assert "Error Statistics" in output
    assert "Performance Statistics" in output


@pytest.mark.unit
def test_display_sections_core_variants() -> None:
    buffer = io.StringIO()
    original_file = display_module.console.file
    try:
        display_module.console.file = buffer

        results = {
            "file_info": {
                "size": 1,
                "path": "/tmp/sample.bin",
                "name": "sample.bin",
                "mime_type": "application/octet-stream",
                "file_type": "ELF",
                "md5": "md5",
                "sha1": "sha1",
                "sha256": "sha256",
                "sha512": "sha512",
                "threat_level": "Low",
                "enhanced_detection": {
                    "file_format": "ELF",
                    "format_category": "Executable",
                    "architecture": "x86-64",
                    "bits": 64,
                    "endianness": "Little",
                    "confidence": 0.9,
                },
            },
            "pe_info": {"type": "EXE", "imports": ["kernel32.dll"], "optional": {"skip": True}},
            "security": {"aslr": True, "dep": False},
            "ssdeep": {"available": False, "error": "missing"},
            "tlsh": {"available": False, "error": "missing"},
            "telfhash": {"available": True, "is_elf": False},
        }

        display_sections._display_file_info(results)
        display_sections._display_pe_info(results)
        display_sections._display_security(results)
        display_sections._display_ssdeep(results)
        display_sections._display_tlsh(results)
        display_sections._display_telfhash(results)

        # Cover available branches for hashes.
        results["ssdeep"] = {"available": True, "hash_value": "ssdeep", "method_used": "python"}
        results["tlsh"] = {
            "available": True,
            "binary_tlsh": "TL",
            "text_section_tlsh": None,
            "stats": {"functions_analyzed": 1, "functions_with_tlsh": 0},
        }
        results["telfhash"] = {
            "available": True,
            "is_elf": True,
            "telfhash": "deadbeef",
            "score": 0.5,
            "checksum": "abc",
        }

        display_sections._display_ssdeep(results)
        display_sections._display_tlsh(results)
        display_sections._display_telfhash(results)

        # Trigger not-available path with error.
        results["telfhash"] = {"available": False, "error": "boom"}
        display_sections._display_telfhash(results)
    finally:
        display_module.console.file = original_file

    output = buffer.getvalue()
    assert "File Information" in output
    assert "Security Features" in output
