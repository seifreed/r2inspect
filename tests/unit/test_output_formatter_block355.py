from __future__ import annotations

import json

from r2inspect.utils.output import OutputFormatter


def test_output_formatter_json_and_csv() -> None:
    results = {
        "file_info": {
            "name": "sample.exe",
            "size": 1024,
            "file_type": "PE32",
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256",
            "sha512": "sha512",
        },
        "pe_info": {"compile_time": "2024-01-01", "imphash": "imphash"},
        "ssdeep": {"hash_value": "3:abc:def"},
        "tlsh": {
            "binary_tlsh": "T1",
            "text_section_tlsh": "T2",
            "stats": {"functions_with_tlsh": 5},
        },
        "telfhash": {"telfhash": "telf", "filtered_symbols": 3},
        "rich_header": {
            "xor_key": 1,
            "checksum": 2,
            "richpe_hash": "rich",
            "compilers": [{"compiler_name": "MSVC", "count": 2}],
        },
        "imports": [{"name": "CreateFileA"}],
        "exports": [{"name": "Export1"}],
        "sections": [{"name": ".text"}],
        "anti_analysis": {"anti_debug": True, "anti_vm": False, "anti_sandbox": False},
        "yara_matches": [{"rule": "Rule1"}],
        "compiler": {"compiler": "GCC", "compiler_version": "12.1.0", "confidence": 0.9},
        "functions": {"count": 10},
        "function_analysis": {"num_unique_machoc": 5, "num_duplicate_functions": 2},
    }
    formatter = OutputFormatter(results)
    json_text = formatter.to_json(indent=2)
    assert json.loads(json_text)["file_info"]["name"] == "sample.exe"

    csv_text = formatter.to_csv()
    assert "sample.exe" in csv_text
    assert "imphash" in csv_text


def test_output_formatter_handles_bad_values() -> None:
    class _Bad:
        def __str__(self) -> str:
            raise ValueError("boom")

    formatter = OutputFormatter({"bad": _Bad()})
    json_text = formatter.to_json()
    payload = json.loads(json_text)
    assert "error" in payload

    class _BadDict(dict):
        def get(self, *args, **kwargs):  # type: ignore[override]
            raise RuntimeError("csv fail")

    csv_text = OutputFormatter(_BadDict()).to_csv()
    assert "CSV Export Failed" in csv_text
