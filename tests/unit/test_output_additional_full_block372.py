from __future__ import annotations

from r2inspect.utils.output import OutputFormatter


class BadStr:
    def __str__(self) -> str:  # pragma: no cover - intentionally raises
        raise RuntimeError("boom")


def test_output_json_error_path() -> None:
    formatter = OutputFormatter({"bad": BadStr()})
    text = formatter.to_json()
    assert "JSON serialization failed" in text


def test_output_extract_names_and_compile_time() -> None:
    formatter = OutputFormatter({})
    data = {"items": "not-a-list"}
    assert formatter._extract_names_from_list(data, "items") == ""

    names_data = {
        "items": [
            {"name": "A"},
            "B",
            {"name": ""},
            {"name": "C"},
        ]
    }
    assert formatter._extract_names_from_list(names_data, "items") == "A, B, C"

    assert formatter._extract_compile_time({"elf_info": {"compile_time": "elf"}}) == "elf"
    assert formatter._extract_compile_time({"macho_info": {"compile_time": "macho"}}) == "macho"
    assert formatter._extract_compile_time({"file_info": {"compile_time": "file"}}) == "file"
    assert formatter._extract_compile_time({}) == ""


def test_output_extract_imphash_missing() -> None:
    formatter = OutputFormatter({})
    assert formatter._extract_imphash({}) == ""


def test_output_format_file_size_and_clean_type() -> None:
    formatter = OutputFormatter({})
    assert formatter._format_file_size(0) == "0 B"
    assert formatter._format_file_size(1) == "1 B"
    assert formatter._format_file_size(1024) == "1.0 KB"
    assert formatter._format_file_size(1024 * 1024) == "1.0 MB"
    assert formatter._format_file_size("bad") == "bad"

    cleaned = formatter._clean_file_type("PE32+ executable, 7 sections")
    assert "sections" not in cleaned
    assert formatter._clean_file_type(None) is None


def test_output_count_duplicate_machoc_empty() -> None:
    formatter = OutputFormatter({})
    assert formatter._count_duplicate_machoc({}) == 0


def test_output_format_table_and_imports_risk_levels() -> None:
    formatter = OutputFormatter({})
    table = formatter.format_table({"a": {"k": "v"}, "b": [1, 2]})
    assert table is not None

    imports = [
        {"name": "A", "library": "L", "category": "C", "risk_score": 10, "risk_level": "Low"},
        {
            "name": "B",
            "library": "L",
            "category": "C",
            "risk_score": 90,
            "risk_level": "Critical",
            "risk_tags": ["x", "y", "z"],
        },
        {"name": "C", "library": "L", "category": "C", "risk_score": 70, "risk_level": "High"},
        {"name": "D", "library": "L", "category": "C", "risk_score": 50, "risk_level": "Medium"},
        {"name": "E", "library": "L", "category": "C", "risk_score": 1, "risk_level": "Minimal"},
    ]
    imports_table = formatter.format_imports(imports)
    assert imports_table is not None


def test_output_summary_branches() -> None:
    formatter = OutputFormatter({})
    summary = formatter.format_summary()
    assert "R2INSPECT" in summary

    results = {
        "file_info": {"name": "a", "size": 1, "file_type": "x", "md5": "m"},
        "indicators": [
            {"type": "t", "description": "d"},
            {"type": "t", "description": "d"},
            {"type": "t", "description": "d"},
            {"type": "t", "description": "d"},
            {"type": "t", "description": "d"},
            {"type": "t", "description": "d"},
        ],
        "packer": {"is_packed": False},
        "yara_matches": [],
    }
    formatter2 = OutputFormatter(results)
    summary2 = formatter2.format_summary()
    assert "... and" in summary2
