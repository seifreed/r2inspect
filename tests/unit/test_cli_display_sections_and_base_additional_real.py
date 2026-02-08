from __future__ import annotations

import tempfile
from enum import Enum
from pathlib import Path

import pytest

from r2inspect.cli import display_base
from r2inspect.cli import display_sections as ds
from r2inspect.cli.presenter import get_section, normalize_display_results

pytestmark = pytest.mark.unit


class _Category(Enum):
    io = "io"


def _build_full_results() -> dict[str, object]:
    return {
        "file_info": {
            "size": 123,
            "path": "/tmp/sample.bin",
            "name": "sample.bin",
            "mime_type": "application/octet-stream",
            "file_type": "PE32",
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256",
            "sha512": "sha512",
            "threat_level": "Low",
            "enhanced_detection": {
                "file_format": "PE32",
                "format_category": "Executable",
                "architecture": "x86",
                "bits": 32,
                "endianness": "little",
                "confidence": 0.9,
            },
        },
        "pe_info": {
            "compile_time": "now",
            "warnings": ["one", "two"],
            "resources": {"skip": True},
            "architecture": "x86",
            "bits": 32,
            "format": "PE",
            "security_features": {"aslr": True},
            "machine": "x86",
            "endian": "little",
        },
        "security": {"aslr": True, "dep": False},
        "ssdeep": {"available": True, "hash_value": "abc", "method_used": "ssdeep"},
        "tlsh": {
            "available": True,
            "binary_tlsh": "",
            "text_section_tlsh": "tt",
            "stats": {"functions_analyzed": 1, "functions_with_tlsh": 0},
        },
        "telfhash": {
            "available": True,
            "is_elf": True,
            "telfhash": "t",
            "symbol_count": 2,
            "filtered_symbols": 1,
            "symbols_used": ["a", "b", "c", "d", "e", "f"],
        },
        "rich_header": {
            "available": True,
            "is_pe": True,
            "xor_key": 1,
            "checksum": 2,
            "richpe_hash": "rh",
            "compilers": [
                {"compiler_name": "MSC", "count": 1, "build_number": 100},
                {"compiler_name": "MSC", "count": 2, "build_number": 101},
                {"compiler_name": "MSC", "count": 3, "build_number": 102},
                {"compiler_name": "MSC", "count": 4, "build_number": 103},
                {"compiler_name": "MSC", "count": 5, "build_number": 104},
                {"compiler_name": "MSC", "count": 6, "build_number": 105},
            ],
        },
        "impfuzzy": {
            "available": True,
            "impfuzzy_hash": "ih",
            "import_count": 3,
            "dll_count": 2,
            "imports_processed": ["imp"] * 12,
        },
        "ccbhash": {
            "available": True,
            "binary_ccbhash": "h" * 80,
            "total_functions": 4,
            "analyzed_functions": 3,
            "unique_hashes": 2,
            "similar_functions": [{"count": 2, "functions": ["a&nbsp;b", "c&amp;d", "e", "f"]}],
        },
        "binlex": {
            "available": True,
            "total_functions": 2,
            "analyzed_functions": 2,
            "ngram_sizes": [3],
            "unique_signatures": {3: 4},
            "similar_functions": {3: [{"count": 2}]},
            "binary_signature": {3: "sig"},
            "top_ngrams": {3: [("STR:abc", 2), ("OP:" + "x" * 80, 1)]},
        },
        "binbloom": {
            "available": True,
            "total_functions": 3,
            "analyzed_functions": 2,
            "capacity": 10,
            "error_rate": 0.01,
            "unique_signatures": 2,
            "function_signatures": {
                "f1": {"instruction_count": 5, "unique_instructions": 3, "signature": "sig1"},
                "f2": {"instruction_count": 7, "unique_instructions": 4, "signature": "sig2"},
            },
            "similar_functions": [
                {
                    "count": 2,
                    "signature": "s" * 40,
                    "functions": ["func1", "func2", "func3", "func4", "func5", "func6"],
                },
                {"count": 1, "signature": "s2", "functions": []},
                {"count": 1, "signature": "s3", "functions": []},
                {"count": 1, "signature": "s4", "functions": []},
            ],
            "binary_signature": "b" * 70,
            "bloom_stats": {"average_fill_rate": 0.2, "total_filters": 2},
        },
        "simhash": {
            "available": True,
            "feature_stats": {
                "total_features": 10,
                "total_strings": 5,
                "total_opcodes": 5,
                "feature_diversity": 0.5,
                "most_common_features": [("STR:abc", 3), ("OP:" + "x" * 50, 2)],
            },
            "combined_simhash": {"hex": "a" * 40, "feature_count": 5},
            "strings_simhash": {"hex": "b" * 10},
            "opcodes_simhash": {"hex": "c" * 10},
            "function_simhashes": {"f1": {"hex": "d"}},
            "total_functions": 2,
            "analyzed_functions": 1,
            "similarity_groups": [
                {
                    "count": 2,
                    "representative_hash": "h" * 40,
                    "functions": ["f1", "f2", "f3", "f4", "f5", "f6"],
                },
                {"count": 1, "representative_hash": "h2", "functions": []},
                {"count": 1, "representative_hash": "h3", "functions": []},
                {"count": 1, "representative_hash": "h4", "functions": []},
            ],
        },
        "bindiff": {
            "comparison_ready": True,
            "filename": "file.bin",
            "structural_features": {
                "file_type": "PE",
                "file_size": 123,
                "section_count": 2,
                "section_names": ["a", "b", "c", "d", "e", "f", "g", "h"],
                "import_count": 1,
                "export_count": 2,
            },
            "function_features": {"function_count": 3, "cfg_features": {"f": 1}},
            "string_features": {"total_strings": 5, "categorized_strings": {"a": 1}},
            "signatures": {"structural": "N/A", "function": "f", "string": "N/A"},
        },
        "functions": {"total_functions": 3, "machoc_hashes": {"a": "h1", "b": "h1", "c": "h2"}},
        "indicators": [{"type": "test", "description": "desc", "severity": "High"}],
    }


def test_display_sections_full_available() -> None:
    results = _build_full_results()
    display_base.display_results(results)


def test_display_sections_exhaustive_branches() -> None:
    ds._display_retry_statistics(
        {
            "total_retries": 0,
            "successful_retries": 0,
            "failed_after_retries": 0,
            "success_rate": 0.0,
            "commands_retried": {},
        }
    )
    ds._display_most_retried_commands({"commands_retried": {}})
    ds._display_circuit_breaker_statistics({})
    ds._display_circuit_breaker_statistics({"failures": 0, "timeouts": 0.0})
    ds._display_circuit_breaker_statistics({"failures": 2, "timeouts": 1.5})

    ds._display_file_info({})
    ds._display_file_info(
        {
            "file_info": {
                "size": 1,
                "path": "/tmp/sample.bin",
                "name": "sample.bin",
                "mime_type": "application/octet-stream",
                "file_type": "DATA",
                "md5": "md5",
                "sha1": "sha1",
                "sha256": "sha256",
                "sha512": "sha512",
                "threat_level": "Low",
                "enhanced_detection": {
                    "file_format": "BIN",
                    "format_category": "Unknown",
                    "architecture": "x86",
                    "bits": 32,
                    "endianness": "little",
                    "confidence": 0.5,
                },
            }
        }
    )

    ds._display_pe_info({})
    ds._display_pe_info(
        {
            "pe_info": {
                "compile_time": "now",
                "warnings": ["one", "two"],
                "resources": {"skip": True},
                "architecture": "x86",
                "bits": 32,
                "format": "PE",
                "security_features": {"aslr": True},
                "machine": "x86",
                "endian": "little",
            }
        }
    )

    ds._display_security({})
    ds._display_security({"security": {"aslr": True, "dep": False}})

    ds._display_ssdeep({})
    ds._display_ssdeep(
        {"ssdeep": {"available": True, "hash_value": "abc", "method_used": "ssdeep"}}
    )
    ds._display_ssdeep({"ssdeep": {"available": False, "error": "boom"}})

    ds._display_tlsh({})
    ds._display_tlsh(
        {
            "tlsh": {
                "available": True,
                "binary_tlsh": "",
                "text_section_tlsh": "tt",
                "stats": {"functions_analyzed": 1, "functions_with_tlsh": 0},
            }
        }
    )
    ds._display_tlsh({"tlsh": {"available": False, "error": "nope"}})

    ds._display_telfhash({})
    ds._display_telfhash(
        {
            "telfhash": {
                "available": True,
                "is_elf": True,
                "telfhash": "t",
                "symbol_count": 2,
                "filtered_symbols": 1,
                "symbols_used": ["a", "b", "c", "d", "e", "f"],
            }
        }
    )
    ds._display_telfhash({"telfhash": {"available": True, "is_elf": False}})
    ds._display_telfhash({"telfhash": {"available": False, "error": "nope"}})

    ds._display_rich_header({})
    ds._display_rich_header(
        {
            "rich_header": {
                "available": True,
                "is_pe": True,
                "xor_key": 1,
                "checksum": 2,
                "richpe_hash": "rh",
                "compilers": [
                    {"compiler_name": "MSC", "count": 1, "build_number": 100},
                    {"compiler_name": "MSC", "count": 2, "build_number": 101},
                    {"compiler_name": "MSC", "count": 3, "build_number": 102},
                    {"compiler_name": "MSC", "count": 4, "build_number": 103},
                    {"compiler_name": "MSC", "count": 5, "build_number": 104},
                    {"compiler_name": "MSC", "count": 6, "build_number": 105},
                ],
            }
        }
    )
    ds._display_rich_header({"rich_header": {"available": True, "is_pe": False}})
    ds._display_rich_header({"rich_header": {"available": False, "error": "nope"}})

    ds._display_impfuzzy({})
    ds._display_impfuzzy(
        {
            "impfuzzy": {
                "available": True,
                "impfuzzy_hash": "ih",
                "import_count": 3,
                "dll_count": 2,
                "imports_processed": ["imp"] * 12,
            }
        }
    )
    ds._display_impfuzzy(
        {"impfuzzy": {"available": False, "error": "nope", "library_available": False}}
    )

    ds._display_ccbhash({})
    ds._display_ccbhash({"ccbhash": {"available": True, "similar_functions": []}})
    ds._display_ccbhash({"ccbhash": {"available": True, "similar_functions": [None]}})
    ds._display_ccbhash(
        {
            "ccbhash": {
                "available": True,
                "binary_ccbhash": "h" * 80,
                "total_functions": 4,
                "analyzed_functions": 3,
                "unique_hashes": 2,
                "similar_functions": [{"count": 2, "functions": ["a&nbsp;b", "c&amp;d", "e", "f"]}],
            }
        }
    )

    ds._display_binlex({})
    ds._display_binlex({"binlex": {"available": False, "error": "nope"}})
    ds._display_binlex(
        {
            "binlex": {
                "available": True,
                "total_functions": 2,
                "analyzed_functions": 2,
                "ngram_sizes": [2, 3],
                "unique_signatures": {2: 1},
                "similar_functions": {3: [{"count": 2}]},
                "binary_signature": {2: "sig"},
                "top_ngrams": {2: [("STR:abc", 2), ("OP:" + "x" * 80, 1)]},
            }
        }
    )

    ds._display_binbloom({})
    ds._display_binbloom({"binbloom": {"available": False, "error": "nope"}})
    ds._display_binbloom(
        {"binbloom": {"available": False, "library_available": False, "error": ""}}
    )
    ds._display_binbloom({"binbloom": {"available": True, "unique_signatures": 1}})
    ds._display_binbloom(
        {
            "binbloom": {
                "available": True,
                "total_functions": 3,
                "analyzed_functions": 2,
                "capacity": 10,
                "error_rate": 0.01,
                "unique_signatures": 2,
                "function_signatures": {
                    "f1": {"instruction_count": 5, "unique_instructions": 3, "signature": "sig1"},
                    "f2": {"instruction_count": 7, "unique_instructions": 4, "signature": "sig2"},
                },
                "similar_functions": [
                    {
                        "count": 2,
                        "signature": "s" * 40,
                        "functions": ["func1", "func2", "func3", "func4", "func5", "func6"],
                    },
                    {"count": 1, "signature": "s2", "functions": []},
                    {"count": 1, "signature": "s3", "functions": []},
                    {"count": 1, "signature": "s4", "functions": []},
                ],
                "binary_signature": "b" * 70,
                "bloom_stats": {"average_fill_rate": 0.2, "total_filters": 2},
            }
        }
    )

    ds._display_simhash({})
    ds._display_simhash({"simhash": {"available": False, "error": "nope"}})
    ds._display_simhash({"simhash": {"available": False, "library_available": False}})
    ds._display_simhash(
        {
            "simhash": {
                "available": True,
                "feature_stats": {},
                "function_simhashes": {},
            }
        }
    )
    ds._display_simhash(
        {
            "simhash": {
                "available": True,
                "feature_stats": {
                    "total_features": 10,
                    "total_strings": 5,
                    "total_opcodes": 5,
                    "feature_diversity": 0.5,
                    "most_common_features": [("STR:" + "x" * 80, 2)],
                },
                "combined_simhash": {"hex": "a" * 40, "feature_count": 5},
                "strings_simhash": {"hex": "b" * 10},
                "opcodes_simhash": {"hex": "c" * 10},
                "function_simhashes": {"f1": {"hex": "d"}},
                "total_functions": 2,
                "analyzed_functions": 1,
                "similarity_groups": [
                    {
                        "count": 2,
                        "representative_hash": "h" * 40,
                        "functions": ["f1", "f2", "f3", "f4", "f5", "f6"],
                    },
                    {"count": 1, "representative_hash": "h2", "functions": []},
                    {"count": 1, "representative_hash": "h3", "functions": []},
                    {"count": 1, "representative_hash": "h4", "functions": []},
                ],
            }
        }
    )

    ds._display_bindiff({})
    ds._display_bindiff({"bindiff": {"comparison_ready": False, "error": "nope"}})
    ds._display_bindiff(
        {
            "bindiff": {
                "comparison_ready": True,
                "filename": "f",
                "structural_features": {},
                "function_features": {},
                "string_features": {},
                "signatures": {},
            }
        }
    )
    ds._display_bindiff(
        {
            "bindiff": {
                "comparison_ready": True,
                "filename": "f",
                "structural_features": {
                    "file_type": "PE",
                    "file_size": 1,
                    "section_count": 1,
                    "section_names": ["a", "b", "c"],
                    "import_count": 0,
                    "export_count": 0,
                },
                "function_features": {"function_count": 1, "cfg_features": {"f": 1}},
                "string_features": {"total_strings": 1, "categorized_strings": {"a": 1}},
                "signatures": {"structural": "x", "function": "y", "string": "z"},
            }
        }
    )
    ds._display_bindiff(
        {
            "bindiff": {
                "comparison_ready": True,
                "filename": "f",
                "structural_features": {
                    "file_type": "PE",
                    "file_size": 1,
                    "section_count": 1,
                    "section_names": ["a", "b", "c", "d", "e", "f", "g", "h"],
                    "import_count": 0,
                    "export_count": 0,
                },
                "function_features": {},
                "string_features": {},
                "signatures": {},
            }
        }
    )

    ds._display_machoc_functions({})
    ds._display_machoc_functions({"functions": {"total_functions": 1, "machoc_hashes": {}}})
    ds._display_machoc_functions(
        {"functions": {"total_functions": 3, "machoc_hashes": {"a": "h1", "b": "h1"}}}
    )

    ds._display_indicators({})
    ds._display_indicators(
        {"indicators": [{"type": "test", "description": "desc", "severity": "High"}]}
    )


def test_display_sections_unavailable_branches() -> None:
    results = {
        "ssdeep": {"available": False, "error": "nope"},
        "tlsh": {"available": False, "error": "nope"},
        "telfhash": {"available": False, "error": "nope"},
        "rich_header": {"available": False, "error": "nope"},
        "impfuzzy": {"available": False, "error": "nope", "library_available": False},
        "ccbhash": {"available": False, "error": "nope"},
        "binlex": {"available": False, "error": "nope"},
        "binbloom": {"available": False, "library_available": False},
        "simhash": {"available": False, "library_available": False},
        "bindiff": {"comparison_ready": False, "error": "nope"},
        "indicators": [],
    }
    display_base.display_results(results)

    ds._display_telfhash({"telfhash": {"available": True, "is_elf": False}})
    ds._display_rich_header({"rich_header": {"available": True, "is_pe": False}})
    ds._display_binbloom({"binbloom": {"available": True, "unique_signatures": 1}})
    ds._display_simhash({"simhash": {"available": False, "error": "nope"}})
    ds._display_ssdeep({})
    ds._display_tlsh({})
    ds._display_telfhash({})
    ds._display_rich_header({})
    ds._display_impfuzzy({})
    ds._display_ccbhash({"ccbhash": {"available": True, "similar_functions": []}})
    ds._display_ccbhash({"ccbhash": {"available": True, "similar_functions": [None]}})
    ds._display_ccbhash({})
    ds._display_binlex({})
    ds._display_binbloom({})
    ds._display_binbloom({"binbloom": {"available": False, "error": "nope"}})
    ds._display_simhash({})

    ds._display_simhash(
        {
            "simhash": {
                "available": True,
                "feature_stats": {},
                "function_simhashes": {},
            }
        }
    )
    ds._display_simhash(
        {
            "simhash": {
                "available": True,
                "feature_stats": {"most_common_features": []},
                "function_simhashes": {"f": {"hex": "1"}},
                "total_functions": 1,
                "analyzed_functions": 1,
                "similarity_groups": [],
            }
        }
    )

    ds._display_bindiff({})
    ds._display_bindiff(
        {
            "bindiff": {
                "comparison_ready": True,
                "filename": "f",
                "structural_features": {},
                "function_features": {},
                "string_features": {},
                "signatures": {},
            }
        }
    )
    ds._display_bindiff(
        {
            "bindiff": {
                "comparison_ready": True,
                "filename": "f",
                "structural_features": {
                    "file_type": "PE",
                    "file_size": 1,
                    "section_count": 1,
                    "section_names": ["a", "b", "c"],
                    "import_count": 0,
                    "export_count": 0,
                },
                "function_features": {},
                "string_features": {},
                "signatures": {},
            }
        }
    )


def test_display_sections_retry_and_circuit_stats() -> None:
    ds._display_retry_statistics(
        {
            "total_retries": 1,
            "successful_retries": 1,
            "failed_after_retries": 0,
            "success_rate": 100.0,
            "commands_retried": {"aa": 2, "ab": 1},
        }
    )
    ds._display_retry_statistics(
        {
            "total_retries": 0,
            "successful_retries": 0,
            "failed_after_retries": 0,
            "success_rate": 0.0,
            "commands_retried": {},
        }
    )
    ds._display_most_retried_commands({"commands_retried": {}})
    ds._display_circuit_breaker_statistics({})
    ds._display_circuit_breaker_statistics({"failures": 2, "zero": 0})
    ds._display_circuit_breaker_statistics({"failures": 0})


def test_display_base_helpers() -> None:
    assert display_base.format_hash_display("", max_length=8) == "N/A"
    assert display_base.format_hash_display("N/A", max_length=8) == "N/A"
    assert display_base.format_hash_display("short", max_length=8) == "short"
    assert display_base.format_hash_display("a" * 20, max_length=8) == "aaaaaaaa..."

    display_base.display_validation_errors(["bad"])

    display_base.display_yara_rules_table(
        [{"name": "r", "size": 1024, "path": "/tmp/r.yar"}], "/tmp"
    )

    display_base.display_error_statistics(
        {
            "total_errors": 1,
            "recent_errors": 1,
            "recovery_strategies_available": 0,
            "errors_by_category": {_Category.io: 1},
            "errors_by_severity": {"critical": 1, "high": 1, "low": 1},
        }
    )

    original_pyfiglet = display_base.pyfiglet
    try:

        class DummyFiglet:
            def figlet_format(self, _text: str, font: str = "slant") -> str:
                return "banner"

        display_base.pyfiglet = DummyFiglet()
        display_base.print_banner()
        display_base.pyfiglet = None
        display_base.print_banner()
    finally:
        display_base.pyfiglet = original_pyfiglet

    with tempfile.TemporaryDirectory() as tempdir:
        empty_dir = Path(tempdir) / "empty"
        empty_dir.mkdir()
        rules_dir = Path(tempdir) / "rules"
        rules_dir.mkdir()
        (rules_dir / "rule.yar").write_text("rule test { condition: true }", encoding="utf-8")
        single_file = Path(tempdir) / "single.yar"
        single_file.write_text("rule single { condition: true }", encoding="utf-8")

        display_base.handle_list_yara_option({}, str(empty_dir))
        display_base.handle_list_yara_option({}, str(rules_dir))
        display_base.handle_list_yara_option({}, str(single_file))

    display_base.display_performance_statistics(
        {
            "total_retries": 0,
            "successful_retries": 0,
            "failed_after_retries": 0,
            "success_rate": 0.0,
            "commands_retried": {},
        },
        {"failures": 1},
    )


def test_presenter_section_logic() -> None:
    results = normalize_display_results({"file_info": {"name": "x"}})
    section, present = get_section(results, "file_info", {})
    assert present is True
    assert section["name"] == "x"

    section, present = get_section(results, "missing", {})
    assert present is False

    section, present = get_section({"file_info": {}}, "file_info", {})
    assert present is True

    section, present = get_section({"file_info": {}}, "missing", {})
    assert present is False
