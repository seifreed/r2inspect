from __future__ import annotations

from rich.console import Console

from r2inspect.cli import display
from r2inspect.cli.display_base import create_info_table
from r2inspect.cli.display_sections import (
    _add_binbloom_bloom_stats,
    _add_binbloom_group,
    _add_binbloom_similar_groups,
    _add_binbloom_stats,
    _add_bindiff_entries,
    _add_bindiff_signatures,
    _add_bindiff_structural,
    _add_binlex_entries,
    _add_ccbhash_entries,
    _add_rich_header_entries,
    _add_simhash_function_analysis,
    _add_simhash_similarity_group,
    _add_simhash_similarity_groups,
    _add_simhash_top_features,
    _add_telfhash_entries,
    _display_binbloom,
    _display_binbloom_signature_details,
    _display_bindiff,
    _display_binlex,
    _display_ccbhash,
    _display_circuit_breaker_statistics,
    _display_file_info,
    _display_impfuzzy,
    _display_indicators,
    _display_machoc_functions,
    _display_most_retried_commands,
    _display_pe_info,
    _display_retry_statistics,
    _display_rich_header,
    _display_security,
    _display_simhash,
    _display_ssdeep,
    _display_telfhash,
    _display_tlsh,
    _format_simhash_hex,
)


def _install_console() -> Console:
    console = Console(record=True, width=140)
    display.console = console
    return console


def test_display_sections_many_branches() -> None:
    console = _install_console()

    results = {
        "file_info": {
            "size": 512,
            "path": "/tmp/sample.exe",
            "name": "sample.exe",
            "mime_type": "application/octet-stream",
            "file_type": "PE32+ executable, 7 sections",
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256",
            "sha512": "sha512",
            "enhanced_detection": {
                "file_format": "PE",
                "format_category": "Executable",
                "architecture": "x86-64",
                "bits": 64,
                "endianness": "Little",
                "confidence": 0.95,
            },
            "threat_level": "High",
        },
        "pe_info": {
            "compile_time": "2026-01-30",
            "imphash": "imphash",
            "libraries": ["KERNEL32"],
            "skip_dict": {"a": 1},
            "is_executable": True,
        },
        "security": {"aslr": True, "dep": False},
        "ssdeep": {"available": True, "hash_value": "hash", "method_used": "py"},
        "tlsh": {
            "available": True,
            "binary_tlsh": "bt",
            "text_section_tlsh": "",
            "stats": {"functions_analyzed": 4, "functions_with_tlsh": 2},
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
            "xor_key": 0x1,
            "checksum": 0x2,
            "richpe_hash": "rh",
            "compilers": [
                {"compiler_name": "MSVC", "count": 2, "build_number": 19},
                {"compiler_name": "GCC", "count": 1, "build_number": 12},
                {"compiler_name": "CLANG", "count": 1, "build_number": 13},
                {"compiler_name": "TCC", "count": 1, "build_number": 10},
                {"compiler_name": "ICC", "count": 1, "build_number": 11},
                {"compiler_name": "OTHER", "count": 1, "build_number": 9},
            ],
        },
        "impfuzzy": {
            "available": True,
            "impfuzzy_hash": "if",
            "import_count": 2,
            "dll_count": 1,
            "imports_processed": ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"],
        },
        "ccbhash": {
            "available": True,
            "binary_ccbhash": "cc",
            "total_functions": 3,
            "analyzed_functions": 3,
            "unique_hashes": 2,
            "similar_functions": [{"count": 3, "functions": ["f1", "f2", "f3", "f4"]}],
        },
        "binlex": {
            "available": True,
            "total_functions": 2,
            "analyzed_functions": 2,
            "ngram_sizes": [3],
            "unique_signatures": {3: 2},
            "similar_functions": {3: [{"count": 2}]},
            "binary_signature": {3: "abcd"},
            "top_ngrams": {3: [("a" * 60, 2)]},
        },
        "binbloom": {
            "available": True,
            "total_functions": 3,
            "analyzed_functions": 3,
            "capacity": 100,
            "error_rate": 0.01,
            "unique_signatures": 2,
            "function_signatures": {
                "f1": {"instruction_count": 10, "unique_instructions": 5, "signature": "h1"},
                "f2": {"instruction_count": 20, "unique_instructions": 10, "signature": "h2"},
            },
            "similar_functions": [
                {
                    "count": 2,
                    "signature": "s" * 40,
                    "functions": ["f1", "f2", "f3", "f4", "f5", "f6"],
                }
            ],
            "binary_signature": "sig",
            "bloom_stats": {"average_fill_rate": 0.5, "total_filters": 2},
        },
        "simhash": {
            "available": True,
            "feature_stats": {
                "total_features": 10,
                "total_strings": 8,
                "total_opcodes": 2,
                "feature_diversity": 0.25,
                "most_common_features": [("STR:abc", 2), ("OP:add", 1)],
            },
            "combined_simhash": {"hex": "0x" + "f" * 40, "feature_count": 10},
            "strings_simhash": {"hex": "0x1"},
            "opcodes_simhash": {"hex": "0x2"},
            "total_functions": 2,
            "analyzed_functions": 2,
            "similarity_groups": [
                {
                    "count": 2,
                    "representative_hash": "a" * 32,
                    "functions": ["f1", "f2", "f3", "f4", "f5", "f6"],
                }
            ],
        },
        "bindiff": {
            "comparison_ready": True,
            "filename": "sample.exe",
            "structural_features": {
                "file_type": "PE",
                "file_size": 10,
                "section_count": 8,
                "section_names": [
                    ".text",
                    ".data",
                    ".rdata",
                    ".rsrc",
                    ".reloc",
                    ".tls",
                    ".pdata",
                    ".xdata",
                ],
                "import_count": 1,
                "export_count": 0,
            },
            "function_features": {"function_count": 2, "cfg_features": [1, 2]},
            "string_features": {"total_strings": 1, "categorized_strings": {"ascii": 1}},
            "signatures": {"structural": "s", "function": "f", "string": "t"},
        },
        "functions": {"total_functions": 3, "machoc_hashes": {"a": "h1", "b": "h1"}},
        "indicators": [{"type": "Anti-Debug", "description": "Detected", "severity": "High"}],
    }

    _display_file_info(results)
    _display_pe_info(results)
    _display_security(results)
    _display_ssdeep(results)
    _display_tlsh(results)
    _display_telfhash(results)
    _display_rich_header(results)
    _display_impfuzzy(results)
    _display_ccbhash(results)
    _display_binlex(results)
    _display_binbloom(results)
    _display_simhash(results)
    _display_bindiff(results)
    _display_machoc_functions(results)
    _display_indicators(results)

    output = console.export_text()
    assert "File Information" in output
    assert "PE Analysis" in output
    assert "Binbloom" in output


def test_display_sections_error_branches() -> None:
    console = _install_console()

    results = {
        "ssdeep": {"available": False, "error": "nope"},
        "tlsh": {"available": False, "error": "nope"},
        "telfhash": {"available": True, "is_elf": False},
        "rich_header": {"available": True, "is_pe": False},
        "impfuzzy": {"available": False, "error": "nope", "library_available": False},
        "ccbhash": {"available": False, "error": "nope"},
        "binlex": {"available": False, "error": "nope"},
        "binbloom": {"available": False, "error": "nope", "library_available": False},
        "simhash": {"available": False, "error": "nope", "library_available": False},
        "bindiff": {"comparison_ready": False, "error": "nope"},
        "functions": {"total_functions": 0},
    }

    _display_ssdeep(results)
    _display_tlsh(results)
    _display_telfhash(results)
    _display_rich_header(results)
    _display_impfuzzy(results)
    _display_ccbhash(results)
    _display_binlex(results)
    _display_binbloom(results)
    _display_simhash(results)
    _display_bindiff(results)
    _display_machoc_functions(results)

    output = console.export_text()
    assert "Not Available" in output


def test_display_helpers_misc() -> None:
    console = _install_console()

    _display_retry_statistics(
        {
            "total_retries": 0,
            "successful_retries": 0,
            "failed_after_retries": 0,
            "success_rate": 0.0,
            "commands_retried": {},
        }
    )
    _display_retry_statistics(
        {
            "total_retries": 2,
            "successful_retries": 1,
            "failed_after_retries": 1,
            "success_rate": 50.0,
            "commands_retried": {"ij": 2, "iSj": 1},
        }
    )
    _display_most_retried_commands({"commands_retried": {"ij": 1}})
    _display_circuit_breaker_statistics({})
    _display_circuit_breaker_statistics({"open_count": 0, "half_open_count": 1})

    output = console.export_text()
    assert "Retry Statistics" in output
    assert "Circuit Breaker Statistics" in output


def test_display_sections_missing_branches() -> None:
    console = _install_console()

    # Missing sections should return early
    _display_file_info({})
    _display_pe_info({})
    _display_security({})
    _display_ssdeep({})
    _display_tlsh({})
    _display_telfhash({})
    _display_rich_header({})
    _display_impfuzzy({})
    _display_ccbhash({})
    _display_binlex({})
    _display_binbloom({})
    _display_simhash({})
    _display_bindiff({})
    _display_machoc_functions({})
    _display_indicators({})

    # Explicit empty branches
    _display_most_retried_commands({"commands_retried": {}})
    _display_circuit_breaker_statistics({"open_count": 0, "half_open_count": 0})

    output = console.export_text()
    assert output == ""

    # _add_simhash_function_analysis with similarity groups present
    _add_simhash_function_analysis(
        create_info_table("sim"),
        {
            "function_simhashes": {"a": 1},
            "total_functions": 1,
            "analyzed_functions": 1,
            "similarity_groups": [{"count": 1, "representative_hash": "a", "functions": []}],
        },
    )


def test_display_sections_edge_cases() -> None:
    console = _install_console()

    # Trigger error branches and empty structures
    _display_ssdeep({"ssdeep": {"available": False}})
    _display_tlsh({"tlsh": {"available": False}})
    _display_telfhash({"telfhash": {"available": False}})
    _display_rich_header({"rich_header": {"available": False}})
    _display_impfuzzy({"impfuzzy": {"available": False, "library_available": True}})
    _display_ccbhash({"ccbhash": {"available": True, "similar_functions": []}})
    _display_binlex({"binlex": {"available": False}})
    _display_binbloom({"binbloom": {"available": False, "library_available": False}})
    _display_simhash({"simhash": {"available": False, "library_available": False}})
    _display_bindiff({"bindiff": {"comparison_ready": False}})

    # Binbloom signature details early exits
    _display_binbloom_signature_details({"available": True, "unique_signatures": 1})

    # Simhash function analysis early exits
    _add_simhash_function_analysis(create_info_table("t"), {"function_simhashes": {}})
    _add_simhash_function_analysis(create_info_table("t"), {"function_simhashes": {"a": 1}})
    _add_simhash_similarity_groups(create_info_table("t"), [{"count": 1, "functions": []}])

    # Bindiff structural with <=7 section names
    table = create_info_table("bindiff")
    _add_bindiff_structural(
        table,
        {
            "section_names": [".text", ".data"],
            "file_type": "PE",
            "file_size": 1,
            "section_count": 2,
        },
    )

    output = console.export_text()
    assert "Not Available" in output or output == ""


def test_display_sections_remaining_lines() -> None:
    console = _install_console()

    # _display_pe_info excluded key path
    _display_pe_info({"pe_info": {"architecture": "x86", "bits": 64, "value": "ok"}})

    # _display_telfhash error branch
    _display_telfhash({"telfhash": {"available": False, "error": "bad"}})

    # _display_rich_header error branch
    _display_rich_header({"rich_header": {"available": False, "error": "bad"}})

    # _add_ccbhash_entries with falsy largest_group
    table = create_info_table("ccb")
    _add_ccbhash_entries(
        table,
        {
            "binary_ccbhash": "cc",
            "total_functions": 1,
            "analyzed_functions": 1,
            "unique_hashes": 1,
            "similar_functions": [None],
        },
    )

    # _add_binbloom_stats return on empty function_signatures
    _add_binbloom_stats(create_info_table("bb"), {"function_signatures": {}})

    # _add_binbloom_similar_groups branches
    _add_binbloom_similar_groups(create_info_table("bb"), {"similar_functions": []})
    _add_binbloom_similar_groups(
        create_info_table("bb"),
        {"similar_functions": [{"count": 1}] * 4},
    )

    # _add_binbloom_bloom_stats return on empty
    _add_binbloom_bloom_stats(create_info_table("bb"), {"bloom_stats": {}})

    # _add_simhash_function_analysis with no similarity groups
    table_sim = create_info_table("sim")
    _add_simhash_function_analysis(
        table_sim,
        {"function_simhashes": {"a": 1}, "total_functions": 1, "analyzed_functions": 1},
    )

    # _add_simhash_similarity_groups with >3 groups
    _add_simhash_similarity_groups(
        create_info_table("sim"),
        [{"count": 1, "representative_hash": "a", "functions": []}] * 4,
    )

    # _add_simhash_similarity_group with >5 functions
    _add_simhash_similarity_group(
        create_info_table("sim"),
        1,
        {
            "count": 6,
            "representative_hash": "a" * 40,
            "functions": ["f1", "f2", "f3", "f4", "f5", "f6"],
        },
    )

    # _add_simhash_top_features empty and long feature
    _add_simhash_top_features(create_info_table("sim"), {"most_common_features": []})
    _add_simhash_top_features(
        create_info_table("sim"),
        {"most_common_features": [("STR:" + ("x" * 60), 1)]},
    )

    output = console.export_text()
    assert output


def test_additional_helper_paths() -> None:
    console = _install_console()

    table = create_info_table("test")
    _add_rich_header_entries(table, {"xor_key": 0x1, "checksum": 0x2, "compilers": []})

    _add_ccbhash_entries(
        table,
        {
            "binary_ccbhash": "cc",
            "total_functions": 1,
            "analyzed_functions": 1,
            "unique_hashes": 1,
            "similar_functions": [],
        },
    )

    _add_binlex_entries(
        table,
        {
            "total_functions": 1,
            "analyzed_functions": 1,
            "ngram_sizes": [3, 4],
            "unique_signatures": {3: 2},
            "similar_functions": {4: [{"count": 2}]},
            "binary_signature": {3: "abcd"},
            "top_ngrams": {3: [("abc", 2)]},
        },
    )

    _add_binbloom_group(table, 1, {"count": 0, "signature": "", "functions": []})

    _add_telfhash_entries(table, {"telfhash": "", "symbol_count": 0, "filtered_symbols": 0})

    _add_simhash_similarity_groups(table, [])
    assert _format_simhash_hex("0x" + "f" * 40).count("\n") == 1

    _add_bindiff_entries(
        table,
        {
            "filename": "file",
            "structural_features": {},
            "function_features": {},
            "string_features": {},
            "signatures": {},
        },
    )
    _add_bindiff_signatures(table, {"structural": "N/A", "function": "N/A", "string": "N/A"})

    assert console.export_text() == ""
