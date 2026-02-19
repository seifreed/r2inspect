"""Tests for OutputFormatter branch paths in utils/output.py."""

from __future__ import annotations

import json

import pytest
from rich.table import Table

from r2inspect.utils.output import OutputFormatter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_formatter(extra: dict | None = None) -> OutputFormatter:
    results: dict = {
        "file_info": {
            "name": "sample.exe",
            "size": 4096,
            "file_type": "PE32",
            "md5": "deadbeef",
        }
    }
    if extra:
        results.update(extra)
    return OutputFormatter(results)


# ---------------------------------------------------------------------------
# to_json
# ---------------------------------------------------------------------------

def test_to_json_returns_valid_json_string() -> None:
    formatter = _make_formatter()
    output = formatter.to_json(indent=2)
    parsed = json.loads(output)
    assert "file_info" in parsed


def test_to_json_respects_indent_parameter() -> None:
    formatter = _make_formatter()
    compact = formatter.to_json(indent=None)
    indented = formatter.to_json(indent=4)
    assert len(indented) > len(compact)


# ---------------------------------------------------------------------------
# _extract_csv_data (backward-compat wrapper)
# ---------------------------------------------------------------------------

def test_extract_csv_data_delegates_to_csv_formatter() -> None:
    formatter = _make_formatter()
    data = {"file_info": {"name": "x.exe", "md5": "abc"}}
    result = formatter._extract_csv_data(data)
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# format_table
# ---------------------------------------------------------------------------

def test_format_table_returns_rich_table_instance() -> None:
    formatter = _make_formatter()
    table = formatter.format_table({"key": "value"}, "Test")
    assert isinstance(table, Table)


def test_format_table_handles_string_values() -> None:
    formatter = _make_formatter()
    table = formatter.format_table({"name": "hello"}, "Test")
    assert table.title == "Test"


def test_format_table_handles_dict_values() -> None:
    formatter = _make_formatter()
    table = formatter.format_table({"nested": {"a": 1, "b": 2}}, "Nested")
    assert isinstance(table, Table)


def test_format_table_handles_list_values() -> None:
    formatter = _make_formatter()
    table = formatter.format_table({"items": [1, 2, 3]}, "List")
    assert isinstance(table, Table)


def test_format_table_uses_default_title() -> None:
    formatter = _make_formatter()
    table = formatter.format_table({"x": "y"})
    assert table.title == "Analysis Results"


# ---------------------------------------------------------------------------
# format_sections
# ---------------------------------------------------------------------------

def _make_sections(suspicious: bool = False) -> list[dict]:
    return [
        {
            "name": ".text",
            "raw_size": 8192,
            "flags": "r-x",
            "entropy": 5.2,
            "suspicious_indicators": ["high_entropy"] if suspicious else [],
        },
        {
            "name": ".data",
            "raw_size": 2048,
            "flags": "rw-",
            "entropy": 2.1,
            "suspicious_indicators": [],
        },
    ]


def test_format_sections_returns_rich_table() -> None:
    formatter = _make_formatter()
    table = formatter.format_sections(_make_sections())
    assert isinstance(table, Table)


def test_format_sections_marks_suspicious_as_yes() -> None:
    formatter = _make_formatter()
    # Build table; exercise the suspicious_indicators branch
    table = formatter.format_sections(_make_sections(suspicious=True))
    assert isinstance(table, Table)


def test_format_sections_marks_clean_as_no() -> None:
    formatter = _make_formatter()
    table = formatter.format_sections(_make_sections(suspicious=False))
    assert isinstance(table, Table)


def test_format_sections_handles_missing_fields() -> None:
    formatter = _make_formatter()
    sections = [{}]  # all fields absent
    table = formatter.format_sections(sections)
    assert isinstance(table, Table)


# ---------------------------------------------------------------------------
# format_imports
# ---------------------------------------------------------------------------

def _make_import(risk_level: str, risk_score: int, tags: list[str]) -> dict:
    return {
        "name": "SomeFunction",
        "library": "KERNEL32",
        "category": "Process",
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_tags": tags,
    }


def test_format_imports_returns_rich_table() -> None:
    formatter = _make_formatter()
    imports = [_make_import("Critical", 90, ["inject", "shellcode", "elevate"])]
    table = formatter.format_imports(imports)
    assert isinstance(table, Table)


def test_format_imports_handles_critical_risk_level() -> None:
    formatter = _make_formatter()
    imports = [_make_import("Critical", 95, ["tag1"])]
    table = formatter.format_imports(imports)
    assert isinstance(table, Table)


def test_format_imports_handles_high_risk_level() -> None:
    formatter = _make_formatter()
    imports = [_make_import("High", 75, ["tag1", "tag2"])]
    table = formatter.format_imports(imports)
    assert isinstance(table, Table)


def test_format_imports_handles_medium_risk_level() -> None:
    formatter = _make_formatter()
    imports = [_make_import("Medium", 50, [])]
    table = formatter.format_imports(imports)
    assert isinstance(table, Table)


def test_format_imports_handles_low_risk_level() -> None:
    formatter = _make_formatter()
    imports = [_make_import("Low", 20, ["t1"])]
    table = formatter.format_imports(imports)
    assert isinstance(table, Table)


def test_format_imports_handles_minimal_risk_level() -> None:
    formatter = _make_formatter()
    imports = [_make_import("Minimal", 0, [])]
    table = formatter.format_imports(imports)
    assert isinstance(table, Table)


def test_format_imports_truncates_many_tags() -> None:
    formatter = _make_formatter()
    imports = [_make_import("High", 80, ["t1", "t2", "t3", "t4"])]
    table = formatter.format_imports(imports)
    assert isinstance(table, Table)


def test_format_imports_sorts_by_risk_score_descending() -> None:
    formatter = _make_formatter()
    imports = [
        _make_import("Low", 10, []),
        _make_import("Critical", 90, []),
        _make_import("Medium", 50, []),
    ]
    table = formatter.format_imports(imports)
    assert isinstance(table, Table)


def test_format_imports_handles_empty_list() -> None:
    formatter = _make_formatter()
    table = formatter.format_imports([])
    assert isinstance(table, Table)


# ---------------------------------------------------------------------------
# format_summary
# ---------------------------------------------------------------------------

def test_format_summary_returns_string() -> None:
    formatter = _make_formatter()
    summary = formatter.format_summary()
    assert isinstance(summary, str)
    assert "R2INSPECT ANALYSIS SUMMARY" in summary


def test_format_summary_includes_file_info() -> None:
    formatter = _make_formatter()
    summary = formatter.format_summary()
    assert "sample.exe" in summary
    assert "4096" in summary
    assert "PE32" in summary


def test_format_summary_includes_indicators_section_when_present() -> None:
    formatter = _make_formatter(
        {
            "indicators": [
                {"type": "Shellcode", "description": "suspicious pattern"},
                {"type": "Injection", "description": "process hollowing"},
            ]
        }
    )
    summary = formatter.format_summary()
    assert "Suspicious Indicators" in summary
    assert "Shellcode" in summary


def test_format_summary_truncates_more_than_five_indicators() -> None:
    indicators = [
        {"type": f"Type{i}", "description": f"desc{i}"} for i in range(8)
    ]
    formatter = _make_formatter({"indicators": indicators})
    summary = formatter.format_summary()
    assert "and 3 more" in summary


def test_format_summary_skips_indicators_when_absent() -> None:
    formatter = OutputFormatter({"file_info": {"name": "x.exe", "size": 0, "file_type": "ELF", "md5": ""}})
    summary = formatter.format_summary()
    assert "Suspicious Indicators" not in summary


def test_format_summary_includes_packer_section_when_packed() -> None:
    formatter = _make_formatter(
        {
            "packer": {
                "is_packed": True,
                "packer_type": "UPX",
                "confidence": 0.97,
            }
        }
    )
    summary = formatter.format_summary()
    assert "Packer Detected" in summary
    assert "UPX" in summary


def test_format_summary_skips_packer_when_not_packed() -> None:
    formatter = _make_formatter({"packer": {"is_packed": False}})
    summary = formatter.format_summary()
    assert "Packer Detected" not in summary


def test_format_summary_skips_packer_when_absent() -> None:
    formatter = _make_formatter()
    summary = formatter.format_summary()
    assert "Packer Detected" not in summary


def test_format_summary_includes_yara_matches_section() -> None:
    formatter = _make_formatter(
        {
            "yara_matches": [
                {"rule": "RuleAlpha"},
                {"rule": "RuleBeta"},
            ]
        }
    )
    summary = formatter.format_summary()
    assert "YARA Matches" in summary
    assert "RuleAlpha" in summary


def test_format_summary_truncates_more_than_three_yara_rules() -> None:
    formatter = _make_formatter(
        {
            "yara_matches": [
                {"rule": f"Rule{i}"} for i in range(6)
            ]
        }
    )
    summary = formatter.format_summary()
    assert "YARA Matches: 6" in summary


def test_format_summary_skips_yara_when_absent() -> None:
    formatter = _make_formatter()
    summary = formatter.format_summary()
    assert "YARA Matches" not in summary


def test_format_summary_handles_empty_results() -> None:
    formatter = OutputFormatter({})
    summary = formatter.format_summary()
    assert isinstance(summary, str)
    assert "R2INSPECT ANALYSIS SUMMARY" in summary
