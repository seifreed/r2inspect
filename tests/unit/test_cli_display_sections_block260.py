from __future__ import annotations

import io

from r2inspect.cli import display_sections as ds


def _base_results() -> dict:
    return {
        "file_info": {
            "size": 123,
            "path": "/tmp/sample.bin",
            "name": "sample.bin",
            "mime_type": "application/octet-stream",
            "file_type": "PE32+ executable",
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256",
            "sha512": "sha512",
            "threat_level": "High",
            "enhanced_detection": {
                "file_format": "PE",
                "format_category": "Executable",
                "architecture": "x86-64",
                "bits": 64,
                "endianness": "Little",
                "confidence": 0.95,
            },
        },
        "pe_info": {
            "type": "EXE",
            "compiler": "MSVC",
            "compile_time": "2025-01-01",
            "imports": ["a", "b"],
            "headers": {"skip": True},
        },
        "security": {"aslr": True, "dep": False},
        "ssdeep": {"available": True, "hash_value": "aa:bb", "method_used": "lib"},
        "tlsh": {
            "available": True,
            "binary_tlsh": "T1ABC",
            "text_section_tlsh": None,
            "stats": {"functions_analyzed": 10, "functions_with_tlsh": 4},
        },
        "telfhash": {
            "available": True,
            "is_elf": True,
            "telfhash": "deadbeef",
            "symbol_count": 10,
            "filtered_symbols": 3,
            "symbols_used": ["sym1", "sym2", "sym3", "sym4", "sym5", "sym6"],
        },
        "rich_header": {
            "available": True,
            "is_pe": True,
            "xor_key": 1,
            "checksum": 2,
            "richpe_hash": "hash",
            "compilers": [
                {"compiler_name": "MSVC", "count": 2, "build_number": 123},
                {"compiler_name": "LINK", "count": 1, "build_number": 456},
            ],
        },
        "impfuzzy": {
            "available": True,
            "impfuzzy_hash": "imp",
            "import_count": 20,
            "dll_count": 5,
            "imports_processed": [f"imp{i}" for i in range(12)],
        },
        "ccbhash": {
            "available": True,
            "binary_ccbhash": "ccbhashvalue",
            "total_functions": 10,
            "analyzed_functions": 8,
            "unique_hashes": 2,
            "similar_functions": [
                {
                    "count": 3,
                    "functions": ["f1", "f2", "f3", "f4"],
                }
            ],
        },
        "binlex": {
            "available": True,
            "total_functions": 10,
            "analyzed_functions": 7,
            "ngram_sizes": [2, 3],
            "unique_signatures": {2: 4, 3: 2},
            "similar_functions": {2: [{"count": 2}]},
            "binary_signature": {2: "beef", 3: "cafe"},
            "top_ngrams": {2: [("aa", 5), ("bb", 3), ("cc", 1)]},
        },
        "binbloom": {
            "available": True,
            "total_functions": 6,
            "analyzed_functions": 6,
            "capacity": 1000,
            "error_rate": 0.01,
            "unique_signatures": 2,
            "function_signatures": {
                "f1": {"instruction_count": 5, "unique_instructions": 3, "signature": "abcd"},
                "f2": {"instruction_count": 7, "unique_instructions": 4, "signature": "efgh"},
            },
            "similar_functions": [
                {
                    "count": 2,
                    "signature": "abcd",
                    "functions": ["func_one", "func_two", "func_three"],
                }
            ],
            "binary_signature": "deadbeef",
            "bloom_stats": {"average_fill_rate": 0.5, "total_filters": 2},
        },
        "simhash": {
            "available": True,
            "feature_stats": {
                "total_features": 100,
                "total_strings": 80,
                "total_opcodes": 20,
                "feature_diversity": 0.3,
                "most_common_features": [("STR:abc", 10), ("OP:add", 7)],
            },
            "combined_simhash": {"hex": "a" * 64, "feature_count": 100},
            "strings_simhash": {"hex": "b" * 16},
            "opcodes_simhash": {"hex": "c" * 16},
            "function_simhashes": {"f1": "h1"},
            "total_functions": 3,
            "analyzed_functions": 2,
            "similarity_groups": [
                {
                    "count": 2,
                    "representative_hash": "h" * 32,
                    "functions": ["f1", "f2", "f3", "f4", "f5", "f6"],
                }
            ],
        },
        "bindiff": {
            "comparison_ready": True,
            "filename": "sample.bin",
            "structural_features": {
                "file_type": "PE",
                "file_size": 123,
                "section_count": 2,
                "section_names": [
                    ".text",
                    ".rdata",
                    ".data",
                    ".rsrc",
                    ".reloc",
                    ".tls",
                    ".pdata",
                    ".extra",
                ],
                "import_count": 4,
                "export_count": 1,
            },
            "function_features": {"function_count": 3, "cfg_features": [1, 2]},
            "string_features": {"total_strings": 5, "categorized_strings": {"api": [], "url": []}},
            "signatures": {"structural": "s", "function": "f", "string": "N/A"},
        },
        "functions": {"total_functions": 4, "machoc_hashes": {"f1": "h", "f2": "h"}},
        "indicators": [
            {"type": "Anti-VM", "description": "vm", "severity": "High"},
        ],
    }


def test_display_sections_full_flow(capsys) -> None:
    results = _base_results()

    ds._display_retry_statistics(
        {
            "total_retries": 2,
            "successful_retries": 1,
            "failed_after_retries": 1,
            "success_rate": 50.0,
            "commands_retried": {"ij": 2, "i": 1},
        }
    )
    ds._display_circuit_breaker_statistics({"opened": 1, "half_open": 0})

    ds._display_file_info(results)
    ds._display_pe_info(results)
    ds._display_security(results)
    ds._display_ssdeep(results)
    ds._display_tlsh(results)
    ds._display_telfhash(results)
    ds._display_rich_header(results)
    ds._display_impfuzzy(results)
    ds._display_ccbhash(results)
    ds._display_binlex(results)
    ds._display_binbloom(results)
    ds._display_simhash(results)
    ds._display_bindiff(results)
    ds._display_machoc_functions(results)
    ds._display_indicators(results)

    out = capsys.readouterr().out
    assert "File Information" in out


def test_display_sections_unavailable_branches(capsys) -> None:
    results = {
        "ssdeep": {"available": False, "error": "missing"},
        "tlsh": {"available": False, "error": "missing"},
        "telfhash": {"available": True, "is_elf": False},
        "rich_header": {"available": True, "is_pe": False},
        "impfuzzy": {"available": False, "error": "missing", "library_available": False},
        "ccbhash": {"available": False, "error": "no"},
        "binlex": {"available": False, "error": "no"},
        "binbloom": {"available": False, "library_available": False},
        "simhash": {"available": False, "library_available": False},
        "bindiff": {"comparison_ready": False, "error": "no"},
        "indicators": [],
    }
    ds._display_ssdeep(results)
    ds._display_tlsh(results)
    ds._display_telfhash(results)
    ds._display_rich_header(results)
    ds._display_impfuzzy(results)
    ds._display_ccbhash(results)
    ds._display_binlex(results)
    ds._display_binbloom(results)
    ds._display_simhash(results)
    ds._display_bindiff(results)
    ds._display_indicators(results)

    out = capsys.readouterr().out
    assert "Not Available" in out or "not installed" in out
