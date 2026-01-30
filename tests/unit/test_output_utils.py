import csv
import json

from r2inspect.utils.output import OutputFormatter


def test_to_json_round_trip():
    results = {"file_info": {"name": "sample", "size": 10}}
    formatter = OutputFormatter(results)
    payload = formatter.to_json(indent=2)
    loaded = json.loads(payload)
    assert loaded["file_info"]["name"] == "sample"


def test_to_csv_contains_expected_fields():
    results = {
        "file_info": {
            "name": "sample.bin",
            "size": 1024,
            "file_type": "PE32, 7 sections",
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256",
            "sha512": "sha512",
        },
        "imports": [{"name": "CreateFileW"}],
        "exports": [{"name": "Export1"}],
        "sections": [{"name": ".text"}],
        "anti_analysis": {"anti_debug": True, "anti_vm": False, "anti_sandbox": True},
        "compiler": {"compiler": "MSVC", "version": "19.0", "confidence": 0.9},
        "functions": {"total_functions": 2, "machoc_hashes": {"f1": "a", "f2": "a"}},
    }

    formatter = OutputFormatter(results)
    csv_text = formatter.to_csv()
    rows = list(csv.DictReader(csv_text.splitlines()))
    assert len(rows) == 1
    row = rows[0]
    assert row["name"] == "sample.bin"
    assert row["size"] == "1.0 KB"
    assert row["file_type"] == "PE32"
    assert row["imports"] == "CreateFileW"
    assert row["exports"] == "Export1"
    assert row["sections"] == ".text"
    assert row["anti_debug"] in {"True", "true", "1"}
    assert row["num_duplicate_functions"] == "1"


def test_format_file_size_and_clean_file_type():
    formatter = OutputFormatter({})
    assert formatter._format_file_size(0) == "0 B"
    assert formatter._format_file_size(1024) == "1.0 KB"
    assert formatter._clean_file_type("PE32, 7 sections") == "PE32"


def test_flatten_results_handles_nested_structures():
    formatter = OutputFormatter({})
    data = {"a": {"b": [1, {"c": "d"}]}}
    rows = formatter._flatten_results(data)
    fields = {row["field"] for row in rows}
    assert "a.b[0]" in fields
    assert "a.b[1].c" in fields


def test_format_summary_includes_basic_sections():
    results = {
        "file_info": {"name": "sample", "size": 1, "file_type": "PE", "md5": "x"},
        "indicators": [{"type": "Suspicious", "description": "bad"}],
        "packer": {"is_packed": True, "packer_type": "UPX", "confidence": 0.7},
        "yara_matches": [{"rule": "rule1"}],
    }
    formatter = OutputFormatter(results)
    summary = formatter.format_summary()
    assert "R2INSPECT ANALYSIS SUMMARY" in summary
    assert "Packer Detected" in summary
    assert "YARA Matches" in summary
