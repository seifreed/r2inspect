from __future__ import annotations

from dataclasses import dataclass

from r2inspect.utils.output import OutputFormatter


@dataclass
class BadStr:
    def __str__(self) -> str:  # pragma: no cover - used by json
        raise RuntimeError("boom")


def test_output_formatter_json_and_csv() -> None:
    formatter = OutputFormatter({"value": BadStr()})
    json_text = formatter.to_json()
    assert "JSON serialization failed" in json_text

    results = {
        "file_info": {
            "name": "sample",
            "size": 1024,
            "file_type": "PE32+ executable, 7 sections",
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256",
            "sha512": "sha512",
        },
        "pe_info": {"compile_time": "now", "imphash": "imp"},
        "ssdeep": {"hash_value": "ss"},
        "tlsh": {
            "binary_tlsh": "bt",
            "text_section_tlsh": "tt",
            "stats": {"functions_with_tlsh": 2},
        },
        "telfhash": {"telfhash": "th", "filtered_symbols": 1},
        "rich_header": {
            "xor_key": 1,
            "checksum": 2,
            "richpe_hash": "rh",
            "compilers": [{"compiler_name": "c", "count": 1}],
        },
        "imports": [{"name": "imp1"}],
        "exports": ["exp1"],
        "sections": [{"name": ".text"}],
        "anti_analysis": {"anti_debug": True, "anti_vm": False, "anti_sandbox": True},
        "yara_matches": [{"rule": "r1"}],
        "compiler": {"compiler": "gcc", "version": "1", "confidence": 0.9},
        "functions": {"total_functions": 2, "machoc_hashes": {"f1": "h", "f2": "h"}},
    }
    csv_text = OutputFormatter(results).to_csv()
    assert "name" in csv_text
    assert "sample" in csv_text


def test_output_formatter_helpers() -> None:
    formatter = OutputFormatter({"file_info": {"size": 0, "file_type": "PE32, 7 sections"}})
    assert formatter._format_file_size(0) == "0 B"
    assert formatter._format_file_size(1536).endswith("KB")
    assert formatter._format_file_size("bad") == "bad"

    cleaned = formatter._clean_file_type("PE32+ executable, 7 sections")
    assert "sections" not in cleaned

    formatter = OutputFormatter({})
    table = formatter.format_table({"a": 1, "b": {"c": 2}}, title="Table")
    assert table.title == "Table"

    sections_table = formatter.format_sections(
        [
            {
                "name": ".text",
                "raw_size": 10,
                "flags": 1,
                "entropy": 1.23,
                "suspicious_indicators": [],
            },
            {
                "name": ".data",
                "raw_size": 20,
                "flags": 2,
                "entropy": 2.34,
                "suspicious_indicators": ["x"],
            },
        ]
    )
    assert sections_table.title == "Section Analysis"

    imports_table = formatter.format_imports(
        [
            {
                "name": "VirtualAlloc",
                "library": "kernel32",
                "category": "memory",
                "risk_score": 80,
                "risk_level": "High",
                "risk_tags": ["alloc", "exec", "tag3"],
            }
        ]
    )
    assert imports_table.title == "Import Analysis"


def test_output_formatter_summary() -> None:
    formatter = OutputFormatter(
        {
            "file_info": {"name": "sample", "size": 10, "file_type": "PE", "md5": "md5"},
            "indicators": [
                {"type": "Anti-VM", "description": "x"},
                {"type": "Anti-Debug", "description": "y"},
                {"type": "Packer", "description": "z"},
                {"type": "Other", "description": "a"},
                {"type": "Other", "description": "b"},
                {"type": "Other", "description": "c"},
            ],
            "packer": {"is_packed": True, "packer_type": "UPX", "confidence": 0.5},
            "yara_matches": [{"rule": "r1"}, {"rule": "r2"}, {"rule": "r3"}, {"rule": "r4"}],
        }
    )
    summary = formatter.format_summary()
    assert "R2INSPECT ANALYSIS SUMMARY" in summary
    assert "Packer Detected" in summary
    assert "YARA Matches" in summary
