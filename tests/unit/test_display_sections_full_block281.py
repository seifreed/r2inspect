from __future__ import annotations

import pytest

from r2inspect.cli import display_sections as ds


@pytest.mark.unit
def test_display_retry_and_circuit_stats() -> None:
    ds._display_retry_statistics(
        {
            "total_retries": 2,
            "successful_retries": 1,
            "failed_after_retries": 1,
            "success_rate": 50.0,
            "commands_retried": {"ij": 2},
        }
    )
    ds._display_circuit_breaker_statistics({"total_calls": 3, "state": "open"})


@pytest.mark.unit
def test_display_file_info_and_pe_info() -> None:
    results = {
        "file_info": {
            "size": 10,
            "path": "/tmp/a",
            "name": "a",
            "mime_type": "application/octet-stream",
            "file_type": "PE",
            "md5": "a",
            "sha1": "b",
            "sha256": "c",
            "sha512": "d",
            "threat_level": "Low",
            "enhanced_detection": {
                "file_format": "PE",
                "format_category": "Executable",
                "architecture": "x86",
                "bits": 64,
                "endianness": "Little",
                "confidence": 0.9,
            },
        },
        "pe_info": {"entry_point": 1, "subsystem": "GUI", "flags": ["A", "B"]},
        "security": {"aslr": True, "dep": False},
    }
    ds._display_file_info(results)
    ds._display_pe_info(results)
    ds._display_security(results)


@pytest.mark.unit
def test_display_hash_sections_variants() -> None:
    results = {
        "ssdeep": {"available": True, "hash_value": "ss", "method_used": "python"},
        "tlsh": {
            "available": True,
            "binary_tlsh": "t1",
            "text_section_tlsh": "t2",
            "stats": {"functions_with_tlsh": 1, "total_functions": 2},
        },
        "telfhash": {
            "available": True,
            "telfhash": "tf",
            "symbols_used": 2,
            "filtered_symbols": 1,
        },
    }
    ds._display_ssdeep(results)
    ds._display_tlsh(results)
    ds._display_telfhash(results)

    results = {
        "ssdeep": {"available": False, "error": "missing"},
        "tlsh": {"available": False, "error": "missing"},
        "telfhash": {"available": False, "error": "missing"},
    }
    ds._display_ssdeep(results)
    ds._display_tlsh(results)
    ds._display_telfhash(results)


@pytest.mark.unit
def test_display_rich_impfuzzy_ccbhash() -> None:
    results = {
        "rich_header": {
            "available": True,
            "xor_key": 4660,
            "checksum": 22136,
            "richpe_hash": "rh",
            "compilers": [{"compiler_name": "MSVC", "count": 2}],
        },
        "impfuzzy": {"available": True, "hash_value": "imp", "method_used": "pefile"},
        "ccbhash": {
            "available": True,
            "binary_ccbhash": "cc",
            "total_functions": 2,
            "analyzed_functions": 2,
            "unique_hashes": 1,
            "similar_groups": [
                {"count": 2, "functions": ["f1", "f2"]},
            ],
        },
    }
    ds._display_rich_header(results)
    ds._display_impfuzzy(results)
    ds._display_ccbhash(results)


@pytest.mark.unit
def test_display_binlex_binbloom_simhash_bindiff_and_indicators() -> None:
    results = {
        "binlex": {
            "available": True,
            "total_functions": 2,
            "analyzed_functions": 2,
            "ngram_sizes": [2],
            "unique_signatures": {2: 1},
            "similar_functions": {2: [{"count": 2}]},
            "binary_signature": {2: "abcd"},
            "top_ngrams": {2: [("ng&nbspam", 3)]},
        },
        "binbloom": {
            "available": True,
            "total_functions": 2,
            "analyzed_functions": 2,
            "capacity": 100,
            "error_rate": 0.01,
            "unique_signatures": 1,
            "function_signatures": {
                "f1": {"instruction_count": 10, "unique_instructions": 5},
                "f2": {"instruction_count": 20, "unique_instructions": 10},
            },
            "similar_functions": [{"count": 2, "signature": "abcdef", "functions": ["f1", "f2"]}],
            "binary_signature": "sig",
            "bloom_filter": {"bits": 100, "hashes": 3},
        },
        "simhash": {
            "available": True,
            "combined_simhash": {"hex": "0x1", "feature_count": 10},
            "strings_simhash": {"hex": "0x2"},
            "opcodes_simhash": {"hex": "0x3"},
            "feature_stats": {
                "total_features": 10,
                "total_strings": 10,
                "total_opcodes": 0,
                "feature_diversity": 0.5,
                "top_features": [("a", 2)],
            },
            "function_simhashes": {"f1": "0x4"},
            "total_functions": 2,
            "analyzed_functions": 2,
            "similarity_groups": [{"count": 2, "functions": ["f1", "f2"], "simhash": "0x4"}],
        },
        "bindiff": {
            "available": True,
            "total_functions": 2,
            "unique_functions": 1,
            "similar_functions": 1,
            "function_similarity": [
                {"function": "f1", "similarity": 0.9, "size": 10, "matches": 9}
            ],
        },
        "machoc_analysis": {
            "total_functions": 2,
            "unique_hashes": 1,
            "duplicate_functions": 1,
        },
        "indicators": [{"type": "Anti-Debug", "description": "Detected", "severity": "High"}],
    }
    ds._display_binlex(results)
    ds._display_binbloom(results)
    ds._display_simhash(results)
    ds._display_bindiff(results)
    ds._display_machoc_functions(results)
    ds._display_indicators(results)


@pytest.mark.unit
def test_display_sections_not_available_branches() -> None:
    results = {
        "binlex": {"available": False, "error": "missing"},
        "binbloom": {"available": False, "library_available": False},
        "simhash": {"available": False, "error": "missing"},
        "bindiff": {"available": False, "error": "missing"},
        "impfuzzy": {"available": False, "error": "missing"},
        "ccbhash": {"available": False, "error": "missing"},
        "rich_header": {"available": False, "error": "missing"},
    }
    ds._display_binlex(results)
    ds._display_binbloom(results)
    ds._display_simhash(results)
    ds._display_bindiff(results)
    ds._display_impfuzzy(results)
    ds._display_ccbhash(results)
    ds._display_rich_header(results)
