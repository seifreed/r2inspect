from __future__ import annotations

from r2inspect.utils.output import OutputFormatter


def test_output_formatter_json_and_csv_paths() -> None:
    results = {
        "file_info": {
            "name": "sample.exe",
            "size": 2048,
            "file_type": "PE32+ executable, 7 sections",
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256",
            "sha512": "sha512",
        },
        "pe_info": {"compile_time": "2026-01-30", "imphash": "imphash"},
        "ssdeep": {"hash_value": "ss"},
        "tlsh": {
            "binary_tlsh": "bt",
            "text_section_tlsh": "tt",
            "stats": {"functions_with_tlsh": 2},
        },
        "telfhash": {"telfhash": "th", "filtered_symbols": 5},
        "rich_header": {
            "xor_key": 0x1234,
            "checksum": 0x1234,
            "richpe_hash": "rh",
            "compilers": [{"compiler_name": "MSVC", "count": 2}],
        },
        "imports": [{"name": "CreateFileA"}],
        "exports": [{"name": "Exported"}],
        "sections": [{"name": ".text"}],
        "anti_analysis": {"anti_debug": True, "anti_vm": False, "anti_sandbox": True},
        "yara_matches": [{"rule": "Rule1"}, {"rule": "Rule2"}],
        "compiler": {"compiler": "MSVC", "version": "19", "confidence": 0.8},
        "functions": {"total_functions": 5, "machoc_hashes": {"a": "h1", "b": "h1"}},
        "imports_processed": [],
    }

    formatter = OutputFormatter(results)
    json_text = formatter.to_json()
    assert "sample.exe" in json_text

    csv_text = formatter.to_csv()
    assert "sample.exe" in csv_text
    assert "imphash" in csv_text
    assert "ss" in csv_text
    assert "MSVC" in csv_text

    # Format table/sections/imports should return Rich Table instances
    table = formatter.format_table({"a": 1, "b": {"c": 2}})
    assert table is not None
    sections_table = formatter.format_sections(
        [{"name": ".text", "raw_size": 10, "flags": "r-x", "entropy": 6.2}]
    )
    assert sections_table is not None
    imports_table = formatter.format_imports(
        [
            {
                "name": "f",
                "library": "k32",
                "category": "file",
                "risk_score": 99,
                "risk_level": "High",
                "risk_tags": ["file", "io"],
            },
            {
                "name": "g",
                "library": "k32",
                "category": "net",
                "risk_score": 1,
                "risk_level": "Minimal",
                "risk_tags": [],
            },
        ]
    )
    assert imports_table is not None


class _Boom:
    def __init__(self) -> None:
        self.ref = self

    def __str__(self) -> str:
        raise ValueError("boom")


def test_output_formatter_error_paths() -> None:
    # Circular reference triggers JSON exception
    formatter = OutputFormatter({"bad": _Boom()})
    error_json = formatter.to_json()
    assert "JSON serialization failed" in error_json

    # Trigger CSV fallback by overriding extractor to raise
    class BadFormatter(OutputFormatter):
        def _extract_csv_data(self, data):  # type: ignore[override]
            raise ValueError("boom")

    bad = BadFormatter({})
    csv_text = bad.to_csv()
    assert "CSV Export Failed" in csv_text

    # _clean_file_type should handle non-string
    cleaned = formatter._clean_file_type({"not": "string"})  # type: ignore[arg-type]
    assert isinstance(cleaned, dict)

    # _format_file_size handles invalid types gracefully
    assert formatter._format_file_size("bad") == "bad"  # type: ignore[arg-type]
