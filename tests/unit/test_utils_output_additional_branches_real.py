from __future__ import annotations

from r2inspect.utils.output import OutputFormatter


def test_output_formatter_csv_error_fallback() -> None:
    formatter = OutputFormatter({"file_info": []})
    csv_text = formatter.to_csv()
    assert "CSV Export Failed" in csv_text


def test_output_formatter_extract_names_edges() -> None:
    formatter = OutputFormatter({})
    assert formatter._extract_names_from_list({"imports": "bad"}, "imports") == ""
    names = formatter._extract_names_from_list({"imports": ["one", {"name": "two"}]}, "imports")
    assert names == "one, two"


def test_output_formatter_private_helpers() -> None:
    formatter = OutputFormatter({})
    csv_row = formatter._extract_csv_data({"file_info": []})
    assert "error" in csv_row

    assert formatter._extract_compile_time({"file_info": {"compile_time": "now"}}) == "now"
    assert formatter._count_duplicate_machoc({}) == 0
    assert formatter._format_file_size(10) == "10 B"


def test_output_formatter_tables_and_summary_edges() -> None:
    formatter = OutputFormatter(
        {
            "file_info": {"name": "a", "size": 1, "file_type": "t", "md5": "m"},
            "indicators": [{"type": "t", "description": "d"}] * 6,
            "packer": {"is_packed": True, "packer_type": "x", "confidence": 0.2},
            "yara_matches": [{"rule": "r1"}],
        }
    )

    imports = [
        {"name": "a", "library": "b", "category": "c", "risk_level": "Critical"},
        {"name": "c", "library": "d", "category": "e", "risk_level": "Medium"},
        {"name": "e", "library": "f", "category": "g", "risk_level": "Low"},
    ]
    formatter.format_imports(imports)

    summary = formatter.format_summary()
    assert "Suspicious Indicators" in summary
    assert "Packer Detected" in summary

    no_yara = OutputFormatter({"yara_matches": []})
    summary_lines: list[str] = []
    no_yara._append_yara_summary(summary_lines)
