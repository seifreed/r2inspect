from __future__ import annotations

import json

from r2inspect.utils.output import OutputFormatter


def test_json_and_csv_fallback():
    formatter = OutputFormatter({"file_info": {"name": "x"}})
    json_out = formatter.to_json()
    assert json.loads(json_out)["file_info"]["name"] == "x"

    csv_out = formatter.to_csv()
    assert "name" in csv_out


def test_extract_names_and_csv_data():
    data = {
        "imports": [{"name": "CreateFile"}, {"name": "OpenProcess"}],
        "exports": ["exp1"],
        "sections": [{"name": ".text"}],
        "ssdeep": {"hash_value": "abc"},
        "tlsh": {"binary_tlsh": "t"},
        "telfhash": {"telfhash": "tf"},
        "rich_header": {"xor_key": 10, "checksum": 11, "compilers": []},
        "functions": {"total_functions": 2, "machoc_hashes": {"a": "h1", "b": "h1"}},
    }
    formatter = OutputFormatter(data)
    csv_row = formatter._extract_csv_data(data)
    assert csv_row["ssdeep_hash"] == "abc"
    assert csv_row["tlsh_binary"] == "t"
    assert csv_row["telfhash"] == "tf"
    assert csv_row["rich_header_xor_key"] == "0xa"
    assert csv_row["num_duplicate_functions"] == 1


def test_format_file_size_and_clean_file_type():
    formatter = OutputFormatter({})
    assert formatter._format_file_size(0) == "0 B"
    assert formatter._format_file_size(1024) == "1.0 KB"
    assert formatter._clean_file_type("PE32, 7 sections") == "PE32"


def test_format_table_and_sections_imports():
    formatter = OutputFormatter({})
    table = formatter.format_table({"hello": "world"}, title="T")
    assert table.title == "T"
    assert len(table.rows) == 1

    sections = [
        {"name": ".text", "raw_size": 10, "flags": "r-x", "entropy": 6.5},
        {"name": ".data", "raw_size": 2, "flags": "rw-", "entropy": 1.0},
    ]
    sec_table = formatter.format_sections(sections)
    assert len(sec_table.rows) == 2

    imports = [
        {
            "name": "CreateFile",
            "library": "KERNEL32.dll",
            "category": "file",
            "risk_score": 80,
            "risk_level": "High",
            "risk_tags": ["fs", "io", "extra"],
        }
    ]
    imp_table = formatter.format_imports(imports)
    assert len(imp_table.rows) == 1
