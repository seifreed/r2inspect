from __future__ import annotations

from r2inspect.cli import display_base, display_sections


def _rich_results() -> dict:
    return {
        "file_info": {
            "size": 123,
            "path": "/tmp/sample",
            "name": "sample",
            "mime_type": "application/octet-stream",
            "file_type": "PE32",
            "md5": "m",
            "sha1": "s1",
            "sha256": "s256",
            "sha512": "s512",
            "enhanced_detection": {
                "file_format": "PE32",
                "format_category": "Executable",
                "architecture": "x86-64",
                "bits": 64,
                "endianness": "Little",
                "confidence": 0.9,
            },
            "threat_level": "High",
        },
        "pe_info": {"compile_time": "2026", "imphash": "imphash", "list": ["a", "b"]},
        "security": {"aslr": True, "dep": False},
        "ssdeep": {"available": True, "hash_value": "ss", "method_used": "ssdeep"},
        "tlsh": {
            "available": True,
            "binary_tlsh": "bt",
            "text_section_tlsh": "tt",
            "stats": {"functions_with_tlsh": 1},
        },
        "telfhash": {
            "available": True,
            "is_elf": True,
            "telfhash": "th",
            "symbol_count": 10,
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
                {"compiler_name": "A", "build_number": 1, "count": 2},
                {"compiler_name": "B", "build_number": 2, "count": 3},
                {"compiler_name": "C", "build_number": 3, "count": 4},
                {"compiler_name": "D", "build_number": 4, "count": 5},
                {"compiler_name": "E", "build_number": 5, "count": 6},
                {"compiler_name": "F", "build_number": 6, "count": 7},
            ],
        },
        "impfuzzy": {
            "available": True,
            "impfuzzy_hash": "ih",
            "import_count": 10,
            "dll_count": 2,
            "imports_processed": ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"],
        },
        "ccbhash": {
            "available": True,
            "binary_ccbhash": "cb",
            "total_functions": 5,
            "analyzed_functions": 4,
            "unique_hashes": 3,
            "similar_functions": [{"count": 2, "functions": ["f1", "f2", "f3", "f4"]}],
        },
        "binlex": {
            "available": True,
            "total_functions": 10,
            "analyzed_functions": 8,
            "ngram_sizes": [2, 3],
            "unique_signatures": {2: 5, 3: 4},
            "similar_functions": {2: [{"count": 2}], 3: []},
            "binary_signature": {2: "b2", 3: "b3"},
            "top_ngrams": {2: [("aa", 3), ("bb", 2)], 3: [("cc", 1)]},
        },
        "binbloom": {
            "available": True,
            "total_functions": 5,
            "analyzed_functions": 4,
            "capacity": 100,
            "error_rate": 0.01,
            "unique_signatures": 2,
            "function_signatures": {
                "f1": {"instruction_count": 10, "unique_instructions": 6, "signature": "s1"},
                "f2": {"instruction_count": 8, "unique_instructions": 5, "signature": "s2"},
            },
            "similar_functions": [
                {"count": 2, "signature": "sig1", "functions": ["a", "b", "c", "d", "e", "f"]}
            ],
            "binary_signature": "bin",
            "bloom_stats": {"average_fill_rate": 0.5, "total_filters": 2},
        },
        "simhash": {
            "available": True,
            "feature_stats": {
                "total_features": 10,
                "total_strings": 4,
                "total_opcodes": 6,
                "feature_diversity": 0.5,
                "most_common_features": [
                    ("STR:abcdefghijklmnop", 5),
                    ("OP:mov", 3),
                ],
            },
            "combined_simhash": {"hex": "a" * 64, "feature_count": 10},
            "strings_simhash": {"hex": "b" * 16},
            "opcodes_simhash": {"hex": "c" * 16},
            "function_simhashes": {"f1": "x"},
            "total_functions": 5,
            "analyzed_functions": 4,
            "similarity_groups": [
                {"count": 2, "representative_hash": "abcd" * 8, "functions": ["f1", "f2"]}
            ],
        },
        "bindiff": {
            "comparison_ready": True,
            "filename": "a.bin",
            "structural_features": {
                "file_type": "PE",
                "file_size": 10,
                "section_count": 2,
                "section_names": ["a", "b", "c", "d", "e", "f", "g", "h"],
                "import_count": 1,
                "export_count": 0,
            },
            "function_features": {"function_count": 2, "cfg_features": {"a": 1}},
            "string_features": {"total_strings": 2, "categorized_strings": {"url": []}},
            "signatures": {"structural": "s", "function": "f", "string": "str"},
        },
        "functions": {"total_functions": 2, "machoc_hashes": {"a": "h1", "b": "h1"}},
        "indicators": [{"type": "api", "description": "x", "severity": "High"}],
    }


def test_display_sections_full_branches() -> None:
    results = _rich_results()
    display_sections._display_file_info(results)
    display_sections._display_pe_info(results)
    display_sections._display_security(results)
    display_sections._display_ssdeep(results)
    display_sections._display_tlsh(results)
    display_sections._display_telfhash(results)
    display_sections._display_rich_header(results)
    display_sections._display_impfuzzy(results)
    display_sections._display_ccbhash(results)
    display_sections._display_binlex(results)
    display_sections._display_binbloom(results)
    display_sections._display_simhash(results)
    display_sections._display_bindiff(results)
    display_sections._display_machoc_functions(results)
    display_sections._display_indicators(results)


def test_display_sections_unavailable_and_missing() -> None:
    results = {
        "ssdeep": {"available": False, "error": "missing"},
        "tlsh": {"available": False, "error": "missing"},
        "telfhash": {"available": True, "is_elf": False},
        "rich_header": {"available": True, "is_pe": False},
        "impfuzzy": {"available": False, "error": "missing", "library_available": False},
        "ccbhash": {"available": False, "error": "missing"},
        "binlex": {"available": False, "error": "missing"},
        "binbloom": {"available": False, "library_available": False},
        "simhash": {"available": False, "library_available": False},
        "bindiff": {"comparison_ready": False, "error": "missing"},
        "indicators": [],
    }
    display_sections._display_ssdeep(results)
    display_sections._display_tlsh(results)
    display_sections._display_telfhash(results)
    display_sections._display_rich_header(results)
    display_sections._display_impfuzzy(results)
    display_sections._display_ccbhash(results)
    display_sections._display_binlex(results)
    display_sections._display_binbloom(results)
    display_sections._display_simhash(results)
    display_sections._display_bindiff(results)
    display_sections._display_indicators(results)

    display_sections._display_retry_statistics({"total_retries": 0, "commands_retried": {}})
    display_sections._display_retry_statistics(
        {
            "total_retries": 2,
            "successful_retries": 1,
            "failed_after_retries": 1,
            "success_rate": 50.0,
            "commands_retried": {"i": 2, "aa": 1},
        }
    )
    display_sections._display_circuit_breaker_statistics({})
    display_sections._display_circuit_breaker_statistics({"opened": 0})
    display_sections._display_circuit_breaker_statistics({"opened": 1, "failures": 2})

    display_sections._display_file_info({})
    display_sections._display_pe_info({})
    display_sections._display_security({})
    display_sections._display_machoc_functions({})


def test_display_base_helpers() -> None:
    assert display_base.format_hash_display(None) == "N/A"
    assert display_base.format_hash_display("abcd", max_length=2) == "ab..."
    table = display_base.create_info_table("t", prop_width=5, value_min_width=5)
    assert table is not None
    display_base.print_banner()
    display_base.display_validation_errors(["x", "y"])
    display_base.display_yara_rules_table(
        [{"name": "r", "size": 1024, "path": "/tmp/r", "relative_path": "r"}], "/tmp"
    )
    display_base.display_error_statistics(
        {
            "total_errors": 1,
            "recent_errors": 1,
            "recovery_strategies_available": 1,
            "errors_by_category": {},
            "errors_by_severity": {"critical": 1},
        }
    )
    display_base.display_performance_statistics(
        {"total_retries": 0, "commands_retried": {}}, {"opened": 0}
    )
    display_base.display_results(_rich_results())
