from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO

from r2inspect.cli import display_sections


def _run_silent(func, *args) -> None:
    with redirect_stdout(StringIO()):
        func(*args)


def test_display_sections_branches_more() -> None:
    _run_silent(
        display_sections._display_retry_statistics,
        {
            "total_retries": 0,
            "successful_retries": 0,
            "failed_after_retries": 0,
            "success_rate": 0.0,
            "commands_retried": {},
        },
    )
    _run_silent(
        display_sections._display_retry_statistics,
        {
            "total_retries": 3,
            "successful_retries": 2,
            "failed_after_retries": 1,
            "success_rate": 66.7,
            "commands_retried": {"pd 10": 2, "iz": 1},
        },
    )
    _run_silent(display_sections._display_circuit_breaker_statistics, {})
    _run_silent(
        display_sections._display_circuit_breaker_statistics,
        {"opened_count": 2, "half_open_count": 0, "reset_count": 1},
    )

    results = {
        "file_info": {
            "size": 1234,
            "path": "/tmp/sample.bin",
            "name": "sample.bin",
            "mime_type": "application/octet-stream",
            "file_type": "data",
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256",
            "sha512": "sha512",
            "enhanced_detection": {
                "file_format": "PE",
                "format_category": "Executable",
                "architecture": "x86",
                "bits": 64,
                "endianness": "little",
                "confidence": 0.99,
            },
            "threat_level": "low",
        },
        "pe_info": {
            "machine": "x86",
            "format": "PE32+",
            "image_base": "0x400000",
            "subsystem": "Windows GUI",
            "sections": ["text", "data"],
            "imports": {"kernel32.dll": ["ExitProcess"]},
            "entry_point": "0x401000",
        },
        "security": {"aslr": True, "dep": False},
        "ssdeep": {"available": True, "hash_value": "3:abc:abc", "method_used": "ssdeep"},
        "tlsh": {
            "available": True,
            "binary_tlsh": "T1",
            "text_section_tlsh": "",
            "stats": {"functions_analyzed": 2, "functions_with_tlsh": 1},
        },
        "telfhash": {
            "available": True,
            "is_elf": True,
            "telfhash": "t",
            "symbol_count": 4,
            "filtered_symbols": 1,
            "symbols_used": ["a", "b", "c", "d", "e", "f"],
        },
        "rich_header": {
            "available": True,
            "is_pe": True,
            "xor_key": 1,
            "checksum": 2,
            "richpe_hash": "hash",
            "compilers": [
                {"compiler_name": "MSVC", "count": 2, "build_number": 123},
                {"compiler_name": "Linker", "count": 1, "build_number": 124},
                {"compiler_name": "Lib", "count": 1, "build_number": 125},
                {"compiler_name": "Tool", "count": 1, "build_number": 126},
                {"compiler_name": "Other", "count": 1, "build_number": 127},
                {"compiler_name": "Extra", "count": 1, "build_number": 128},
            ],
        },
        "impfuzzy": {
            "available": True,
            "impfuzzy_hash": "imp",
            "import_count": 12,
            "dll_count": 2,
            "imports_processed": [f"imp{i}" for i in range(12)],
        },
        "ccbhash": {
            "available": True,
            "binary_ccbhash": "a" * 80,
            "total_functions": 5,
            "analyzed_functions": 4,
            "unique_hashes": 3,
            "similar_functions": [
                {"count": 4, "functions": ["f1", "f2", "f3", "f4", "f5"]},
                {"count": 2, "functions": ["g1", "g2"]},
            ],
        },
        "binlex": {
            "available": True,
            "total_functions": 3,
            "analyzed_functions": 2,
            "ngram_sizes": [2, 3],
            "unique_signatures": {2: 1, 3: 2},
            "similar_functions": {2: [{"count": 2}], 3: []},
            "binary_signature": {2: "b" * 80, 3: "c" * 40},
            "top_ngrams": {2: [("aa", 3), ("bb", 2), ("cc", 1), ("dd", 1)]},
        },
        "binbloom": {
            "available": True,
            "total_functions": 4,
            "analyzed_functions": 4,
            "capacity": 100,
            "error_rate": 0.01,
            "unique_signatures": 2,
            "function_signatures": {
                "func1": {"instruction_count": 10, "unique_instructions": 8, "signature": "sig1"},
                "func2": {"instruction_count": 12, "unique_instructions": 9, "signature": "sig2"},
                "func3": {"instruction_count": 9, "unique_instructions": 7, "signature": "sig1"},
            },
            "similar_functions": [
                {
                    "count": 3,
                    "signature": "s" * 40,
                    "functions": ["f1", "f2", "f3", "f4", "f5", "f6"],
                },
                {"count": 2, "signature": "t" * 20, "functions": ["g1"]},
                {"count": 1, "signature": "u" * 10, "functions": []},
                {"count": 1, "signature": "v" * 10, "functions": ["h1"]},
            ],
            "binary_signature": "z" * 80,
            "bloom_stats": {"average_fill_rate": 0.5, "total_filters": 2},
        },
        "simhash": {
            "available": True,
            "library_available": True,
            "feature_stats": {
                "total_features": 10,
                "total_strings": 4,
                "total_opcodes": 6,
                "feature_diversity": 0.5,
                "most_common_features": [("STR:hello", 3), ("OP:mov", 2), ("OPTYPE:arith", 1)],
            },
            "combined_simhash": {"hex": "a" * 40, "feature_count": 10},
            "strings_simhash": {"hex": "b" * 16},
            "opcodes_simhash": {"hex": "c" * 16},
            "function_simhashes": {"f1": "h1"},
            "total_functions": 2,
            "analyzed_functions": 1,
            "similarity_groups": [
                {
                    "count": 2,
                    "representative_hash": "h" * 40,
                    "functions": ["f1", "f2", "f3", "f4", "f5", "f6"],
                },
                {"count": 1, "representative_hash": "i" * 8, "functions": ["g1"]},
                {"count": 1, "representative_hash": "j" * 8, "functions": []},
                {"count": 1, "representative_hash": "k" * 8, "functions": ["x"]},
            ],
        },
        "bindiff": {
            "comparison_ready": True,
            "filename": "sample.bin",
            "structural_features": {
                "file_type": "PE",
                "file_size": 1234,
                "section_count": 8,
                "section_names": ["a", "b", "c", "d", "e", "f", "g", "h"],
                "import_count": 3,
                "export_count": 1,
            },
            "function_features": {"function_count": 5, "cfg_features": [1, 2]},
            "string_features": {
                "total_strings": 9,
                "categorized_strings": {"paths": ["a"], "urls": ["b"]},
            },
            "signatures": {"structural": "s", "function": "N/A", "string": "t"},
        },
        "functions": {"total_functions": 3, "machoc_hashes": {"f1": "h1", "f2": "h1", "f3": "h2"}},
        "indicators": [
            {"type": "suspicious", "description": "found", "severity": "high"},
            {"type": "info", "description": "note", "severity": "low"},
        ],
    }

    _run_silent(display_sections._display_file_info, results)
    _run_silent(display_sections._display_pe_info, results)
    _run_silent(display_sections._display_security, results)
    _run_silent(display_sections._display_ssdeep, results)
    _run_silent(display_sections._display_tlsh, results)
    _run_silent(display_sections._display_telfhash, results)
    _run_silent(display_sections._display_rich_header, results)
    _run_silent(display_sections._display_impfuzzy, results)
    _run_silent(display_sections._display_ccbhash, results)
    _run_silent(display_sections._display_binlex, results)
    _run_silent(display_sections._display_binbloom, results)
    _run_silent(display_sections._display_simhash, results)
    _run_silent(display_sections._display_bindiff, results)
    _run_silent(display_sections._display_machoc_functions, results)
    _run_silent(display_sections._display_indicators, results)

    _run_silent(
        display_sections._display_ssdeep,
        {"ssdeep": {"available": False, "error": "nope"}},
    )
    _run_silent(
        display_sections._display_tlsh,
        {"tlsh": {"available": False, "error": "nope"}},
    )
    _run_silent(
        display_sections._display_telfhash,
        {"telfhash": {"available": True, "is_elf": False}},
    )
    _run_silent(
        display_sections._display_telfhash,
        {"telfhash": {"available": False, "error": "nope"}},
    )
    _run_silent(
        display_sections._display_rich_header,
        {"rich_header": {"available": True, "is_pe": False}},
    )
    _run_silent(
        display_sections._display_rich_header,
        {"rich_header": {"available": False, "error": "nope"}},
    )
    _run_silent(
        display_sections._display_impfuzzy,
        {"impfuzzy": {"available": False, "error": "nope", "library_available": False}},
    )
    _run_silent(
        display_sections._display_ccbhash,
        {"ccbhash": {"available": True, "similar_functions": []}},
    )
    _run_silent(
        display_sections._display_ccbhash,
        {"ccbhash": {"available": False, "error": "missing"}},
    )
    _run_silent(
        display_sections._display_ccbhash,
        {
            "ccbhash": {
                "available": True,
                "binary_ccbhash": "x" * 64,
                "total_functions": 1,
                "analyzed_functions": 1,
                "unique_hashes": 1,
                "similar_functions": [{}],
            }
        },
    )
    _run_silent(
        display_sections._display_binlex,
        {"binlex": {"available": False, "error": "nope"}},
    )
    _run_silent(
        display_sections._display_binbloom,
        {"binbloom": {"available": False, "library_available": False}},
    )
    _run_silent(
        display_sections._display_binbloom,
        {"binbloom": {"available": False, "error": "missing"}},
    )
    _run_silent(
        display_sections._display_simhash,
        {"simhash": {"available": False, "library_available": False}},
    )
    _run_silent(
        display_sections._display_bindiff,
        {"bindiff": {"comparison_ready": False, "error": "nope"}},
    )
    _run_silent(display_sections._display_indicators, {"indicators": []})

    _run_silent(display_sections._display_most_retried_commands, {"commands_retried": {}})
    _run_silent(display_sections._display_circuit_breaker_statistics, {"opened": 0})
    _run_silent(display_sections._display_file_info, {})
    _run_silent(display_sections._display_pe_info, {})
    _run_silent(display_sections._display_security, {})
    _run_silent(display_sections._display_ssdeep, {})
    _run_silent(display_sections._display_tlsh, {})
    _run_silent(display_sections._display_telfhash, {})
    _run_silent(display_sections._display_rich_header, {})
    _run_silent(display_sections._display_impfuzzy, {})
    _run_silent(display_sections._display_ccbhash, {})
    _run_silent(display_sections._display_binlex, {})
    _run_silent(display_sections._display_binbloom, {})
    _run_silent(display_sections._display_simhash, {})
    _run_silent(display_sections._display_bindiff, {})
    _run_silent(display_sections._display_machoc_functions, {})

    _run_silent(
        display_sections._display_binlex,
        {
            "binlex": {
                "available": True,
                "total_functions": 1,
                "analyzed_functions": 1,
                "ngram_sizes": [4],
                "top_ngrams": {4: [("a" * 80, 1)]},
            }
        },
    )
    _run_silent(
        display_sections._display_binbloom,
        {
            "binbloom": {
                "available": True,
                "total_functions": 0,
                "analyzed_functions": 0,
                "unique_signatures": 1,
                "function_signatures": {},
                "similar_functions": [],
                "bloom_stats": {},
            }
        },
    )
    _run_silent(
        display_sections._display_simhash,
        {
            "simhash": {
                "available": False,
                "error": "failed",
                "library_available": True,
            }
        },
    )
    _run_silent(
        display_sections._display_simhash,
        {
            "simhash": {
                "available": True,
                "feature_stats": {"most_common_features": []},
                "function_simhashes": {},
            }
        },
    )
    _run_silent(
        display_sections._display_simhash,
        {
            "simhash": {
                "available": True,
                "feature_stats": {"most_common_features": [("STR:" + "b" * 60, 2)]},
                "function_simhashes": {"f": "h"},
                "similarity_groups": [],
            }
        },
    )
    _run_silent(
        display_sections._display_bindiff,
        {
            "bindiff": {
                "comparison_ready": True,
                "structural_features": {
                    "file_type": "ELF",
                    "file_size": 1,
                    "section_count": 2,
                    "section_names": ["a", "b"],
                    "import_count": 0,
                    "export_count": 0,
                },
                "function_features": {},
                "string_features": {},
                "signatures": {},
            }
        },
    )
    _run_silent(
        display_sections._display_bindiff,
        {
            "bindiff": {
                "comparison_ready": True,
                "structural_features": {},
                "function_features": {},
                "string_features": {},
                "signatures": {},
            }
        },
    )
