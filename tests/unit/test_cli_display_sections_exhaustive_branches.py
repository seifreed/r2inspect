from __future__ import annotations

from r2inspect.cli import display_sections as ds
from r2inspect.cli.presenter import normalize_display_results


def _wrap_results(payload: dict) -> dict:
    return normalize_display_results(payload)


def test_display_sections_exhaustive_branches() -> None:
    retry_stats = {
        "total_retries": 3,
        "successful_retries": 2,
        "failed_after_retries": 1,
        "success_rate": 66.6,
        "commands_retried": {"i": 2, "ij": 1},
    }
    ds._display_retry_statistics(retry_stats)

    ds._display_circuit_breaker_statistics({"open_count": 2, "close_count": 1})
    ds._display_circuit_breaker_statistics({})

    results = _wrap_results(
        {
            "file_info": {
                "size": 123,
                "path": "/tmp/sample.bin",
                "name": "sample.bin",
                "mime_type": "application/octet-stream",
                "file_type": "PE",
                "md5": "md5",
                "sha1": "sha1",
                "sha256": "sha256",
                "sha512": "sha512",
                "enhanced_detection": {
                    "file_format": "PE32+",
                    "format_category": "Executable",
                    "architecture": "x64",
                    "bits": 64,
                    "endianness": "LE",
                    "confidence": 0.99,
                },
                "threat_level": "low",
            },
            "pe_info": {
                "subsystem": "windows",
                "imports": ["kernel32.dll", "user32.dll"],
                "arch": "x64",
                "machine": "amd64",
                "security_features": {"dep": True},
                "flags": {"aslr": True},
            },
            "security": {"aslr": True, "nx": False},
            "ssdeep": {"available": True, "hash_value": "abcd", "method_used": "python"},
            "tlsh": {
                "available": True,
                "binary_tlsh": "T1",
                "text_section_tlsh": "",
                "stats": {"functions_analyzed": 2, "functions_with_tlsh": 1},
            },
            "telfhash": {
                "available": True,
                "is_elf": True,
                "telfhash": "tf",
                "symbol_count": 5,
                "filtered_symbols": 2,
                "symbols_used": ["a", "b", "c", "d", "e", "f"],
            },
            "rich_header": {
                "available": True,
                "is_pe": True,
                "xor_key": 1,
                "checksum": 2,
                "richpe_hash": "rh",
                "compilers": [
                    {"compiler_name": "MSVC", "count": 1, "build_number": 100},
                    {"compiler_name": "CL", "count": 2, "build_number": 101},
                    {"compiler_name": "LINK", "count": 3, "build_number": 102},
                    {"compiler_name": "ML", "count": 4, "build_number": 103},
                    {"compiler_name": "RC", "count": 5, "build_number": 104},
                    {"compiler_name": "CVTRES", "count": 6, "build_number": 105},
                ],
            },
            "impfuzzy": {
                "available": True,
                "impfuzzy_hash": "imph",
                "import_count": 3,
                "dll_count": 2,
                "imports_processed": [f"imp{i}" for i in range(12)],
                "library_available": True,
            },
            "ccbhash": {
                "available": True,
                "binary_ccbhash": "ccbh",
                "total_functions": 5,
                "analyzed_functions": 4,
                "unique_hashes": 3,
                "similar_functions": [
                    {
                        "count": 4,
                        "functions": [
                            "func1",
                            "func2",
                            "func3",
                            "func4",
                            "func5",
                        ],
                    }
                ],
            },
            "binlex": {
                "available": True,
                "total_functions": 4,
                "analyzed_functions": 3,
                "ngram_sizes": [2, 3],
                "unique_signatures": {2: 10, 3: 8},
                "similar_functions": {2: [{"count": 2}], 3: [{"count": 3}]},
                "binary_signature": {2: "sig2", 3: "sig3"},
                "top_ngrams": {
                    2: [("aa", 2), ("bb", 1)],
                    3: [("ccc", 3)],
                },
            },
            "binbloom": {
                "available": True,
                "total_functions": 10,
                "analyzed_functions": 9,
                "capacity": 1024,
                "error_rate": 0.01,
                "unique_signatures": 3,
                "function_signatures": {
                    "func_a": {
                        "signature": "hash_a",
                        "instruction_count": 3,
                        "unique_instructions": 2,
                    },
                    "func_b": {
                        "signature": "hash_b",
                        "instruction_count": 2,
                        "unique_instructions": 2,
                    },
                    "func_c": {
                        "signature": "hash_a",
                        "instruction_count": 4,
                        "unique_instructions": 3,
                    },
                },
                "similar_functions": [
                    {
                        "count": 2,
                        "signature": "sig",
                        "functions": ["f1", "f2", "f3", "f4", "f5", "f6"],
                    },
                    {"count": 1, "signature": "sig2", "functions": ["g1"]},
                    {"count": 1, "signature": "sig3", "functions": ["h1"]},
                    {"count": 1, "signature": "sig4", "functions": ["i1"]},
                ],
                "binary_signature": "binsig",
                "bloom_stats": {"average_fill_rate": 0.5, "total_filters": 2},
                "library_available": True,
            },
            "simhash": {
                "available": True,
                "feature_stats": {
                    "total_features": 10,
                    "total_strings": 5,
                    "total_opcodes": 5,
                    "feature_diversity": 0.9,
                    "most_common_features": [
                        ("STR:example", 3),
                        ("OP:mov", 2),
                        ("OPTYPE:arith", 1),
                    ],
                },
                "combined_simhash": {"hex": "a" * 40, "feature_count": 10},
                "strings_simhash": {"hex": "b" * 16},
                "opcodes_simhash": {"hex": "c" * 16},
                "function_simhashes": {"f": {"simhash": "1"}},
                "total_functions": 3,
                "analyzed_functions": 2,
                "similarity_groups": [
                    {
                        "count": 2,
                        "representative_hash": "h" * 30,
                        "functions": ["x", "y", "z", "w", "v", "u"],
                    },
                    {"count": 1, "representative_hash": "h2", "functions": ["a"]},
                    {"count": 1, "representative_hash": "h3", "functions": ["b"]},
                    {"count": 1, "representative_hash": "h4", "functions": ["c"]},
                ],
                "library_available": True,
            },
            "bindiff": {
                "comparison_ready": True,
                "filename": "sample.bin",
                "structural_features": {
                    "file_type": "pe",
                    "file_size": 1234,
                    "section_count": 8,
                    "section_names": [
                        ".text",
                        ".rdata",
                        ".data",
                        ".bss",
                        ".rsrc",
                        ".tls",
                        ".reloc",
                        ".debug",
                    ],
                    "import_count": 10,
                    "export_count": 1,
                },
                "function_features": {"function_count": 5, "cfg_features": {"f": {}}},
                "string_features": {"total_strings": 4, "categorized_strings": {"url": []}},
                "signatures": {"structural": "s", "function": "f", "string": "t"},
            },
            "functions": {"total_functions": 5, "machoc_hashes": {"a": "h1", "b": "h1", "c": "h2"}},
            "indicators": [
                {"type": "suspicious", "description": "desc", "severity": "high"},
            ],
        }
    )

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

    ds._format_simhash_hex("1" * 40)

    negative = _wrap_results(
        {
            "ssdeep": {"available": False, "error": "no"},
            "tlsh": {"available": False, "error": "no"},
            "telfhash": {"available": True, "is_elf": False},
            "rich_header": {"available": True, "is_pe": False},
            "impfuzzy": {"available": False, "error": "no", "library_available": False},
            "ccbhash": {"available": False, "error": "no"},
            "binlex": {"available": False, "error": "no"},
            "binbloom": {"available": False, "library_available": False},
            "simhash": {"available": False, "library_available": False},
            "bindiff": {"comparison_ready": False, "error": "no"},
        }
    )

    ds._display_ssdeep(negative)
    ds._display_tlsh(negative)
    ds._display_telfhash(negative)
    ds._display_rich_header(negative)
    ds._display_impfuzzy(negative)
    ds._display_ccbhash(negative)
    ds._display_binlex(negative)
    ds._display_binbloom(negative)
    ds._display_simhash(negative)
    ds._display_bindiff(negative)
