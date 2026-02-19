"""Tests for r2inspect/utils/output.py - OutputFormatter."""

from __future__ import annotations

from rich.table import Table

from r2inspect.utils.output import OutputFormatter


# ---------------------------------------------------------------------------
# format_table
# ---------------------------------------------------------------------------

def test_format_table_returns_rich_table() -> None:
    fmt = OutputFormatter({"file_info": {"name": "test.exe"}})
    result = fmt.format_table({"key": "value", "num": 42}, title="Test")
    assert isinstance(result, Table)


def test_format_table_with_dict_value() -> None:
    fmt = OutputFormatter({})
    result = fmt.format_table({"nested": {"a": 1}})
    assert isinstance(result, Table)


def test_format_table_with_list_value() -> None:
    fmt = OutputFormatter({})
    result = fmt.format_table({"items": [1, 2, 3]})
    assert isinstance(result, Table)


def test_format_table_empty_data() -> None:
    fmt = OutputFormatter({})
    result = fmt.format_table({})
    assert isinstance(result, Table)


# ---------------------------------------------------------------------------
# format_sections
# ---------------------------------------------------------------------------

def test_format_sections_normal() -> None:
    sections = [
        {"name": ".text", "raw_size": 4096, "flags": "r-x", "entropy": 6.5, "suspicious_indicators": []},
        {"name": ".data", "raw_size": 512, "flags": "rw-", "entropy": 2.1, "suspicious_indicators": ["high_entropy"]},
    ]
    result = OutputFormatter({}).format_sections(sections)
    assert isinstance(result, Table)


def test_format_sections_empty() -> None:
    result = OutputFormatter({}).format_sections([])
    assert isinstance(result, Table)


def test_format_sections_missing_keys() -> None:
    result = OutputFormatter({}).format_sections([{}])
    assert isinstance(result, Table)


def test_format_sections_suspicious_yes() -> None:
    sections = [{"suspicious_indicators": ["bad"]}]
    result = OutputFormatter({}).format_sections(sections)
    assert isinstance(result, Table)


# ---------------------------------------------------------------------------
# format_imports
# ---------------------------------------------------------------------------

def test_format_imports_normal() -> None:
    imports = [
        {"name": "CreateRemoteThread", "library": "kernel32.dll", "category": "Injection",
         "risk_score": 95, "risk_level": "Critical", "risk_tags": ["Remote Thread Injection"]},
        {"name": "VirtualAlloc", "library": "kernel32.dll", "category": "Memory",
         "risk_score": 50, "risk_level": "Medium", "risk_tags": ["Memory Allocation"]},
    ]
    result = OutputFormatter({}).format_imports(imports)
    assert isinstance(result, Table)


def test_format_imports_all_risk_levels() -> None:
    for level in ["Critical", "High", "Medium", "Low", "Minimal"]:
        imports = [{"name": "SomeFunc", "library": "lib.dll", "category": "X",
                    "risk_score": 10, "risk_level": level, "risk_tags": ["tag1", "tag2", "tag3"]}]
        result = OutputFormatter({}).format_imports(imports)
        assert isinstance(result, Table)


def test_format_imports_empty_tags() -> None:
    imports = [{"name": "Func", "library": "lib.dll", "category": "X",
                "risk_score": 0, "risk_level": "Minimal", "risk_tags": []}]
    result = OutputFormatter({}).format_imports(imports)
    assert isinstance(result, Table)


def test_format_imports_empty_list() -> None:
    result = OutputFormatter({}).format_imports([])
    assert isinstance(result, Table)


def test_format_imports_more_than_two_tags() -> None:
    imports = [{"name": "F", "library": "L", "category": "C",
                "risk_score": 50, "risk_level": "Medium",
                "risk_tags": ["tag1", "tag2", "tag3", "tag4"]}]
    result = OutputFormatter({}).format_imports(imports)
    assert isinstance(result, Table)


# ---------------------------------------------------------------------------
# format_summary
# ---------------------------------------------------------------------------

def test_format_summary_empty_results() -> None:
    result = OutputFormatter({}).format_summary()
    assert "R2INSPECT" in result


def test_format_summary_with_file_info() -> None:
    results = {
        "file_info": {"name": "test.exe", "size": 1024, "file_type": "PE", "md5": "abc123"}
    }
    result = OutputFormatter(results).format_summary()
    assert "test.exe" in result
    assert "1024" in result


def test_format_summary_with_indicators() -> None:
    indicators = [{"type": "suspicious", "description": "bad thing"} for _ in range(7)]
    result = OutputFormatter({"indicators": indicators}).format_summary()
    assert "Suspicious Indicators" in result
    assert "more" in result


def test_format_summary_with_few_indicators() -> None:
    results = {
        "indicators": [{"type": "X", "description": "Y"}]
    }
    result = OutputFormatter(results).format_summary()
    assert "X" in result


def test_format_summary_with_packer() -> None:
    results = {"packer": {"is_packed": True, "packer_type": "UPX", "confidence": 0.95}}
    result = OutputFormatter(results).format_summary()
    assert "UPX" in result


def test_format_summary_packer_not_packed() -> None:
    results = {"packer": {"is_packed": False}}
    result = OutputFormatter(results).format_summary()
    assert "Packer" not in result


def test_format_summary_with_yara_matches() -> None:
    results = {"yara_matches": [{"rule": "Malware_Rule_A"}, {"rule": "Malware_Rule_B"}]}
    result = OutputFormatter(results).format_summary()
    assert "YARA" in result
    assert "Malware_Rule_A" in result


def test_format_summary_with_more_than_three_yara() -> None:
    results = {"yara_matches": [{"rule": f"Rule_{i}"} for i in range(5)]}
    result = OutputFormatter(results).format_summary()
    assert "YARA Matches: 5" in result


def test_format_summary_no_file_info() -> None:
    result = OutputFormatter({"something_else": "val"}).format_summary()
    assert "R2INSPECT" in result


# ---------------------------------------------------------------------------
# to_json / to_csv
# ---------------------------------------------------------------------------

def test_to_json_basic() -> None:
    result = OutputFormatter({"key": "value"}).to_json()
    assert '"key"' in result
    assert '"value"' in result


def test_to_json_indent() -> None:
    result = OutputFormatter({"k": 1}).to_json(indent=4)
    assert isinstance(result, str)


def test_to_csv_basic() -> None:
    result = OutputFormatter({"file_info": {"name": "f.exe", "sha256": "abc"}}).to_csv()
    assert isinstance(result, str)
