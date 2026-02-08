from __future__ import annotations

import io

import pytest

from r2inspect.cli import display as display_module
from r2inspect.cli import display_sections


@pytest.mark.unit
def test_display_sections_full_coverage() -> None:
    buffer = io.StringIO()
    original_file = display_module.console.file
    try:
        display_module.console.file = buffer

        results = {
            "rich_header": {
                "available": True,
                "is_pe": True,
                "xor_key": 0x11223344,
                "checksum": 0x55667788,
                "richpe_hash": "abc",
                "compilers": [
                    {"compiler_name": "MSVC", "count": 1, "build_number": 111},
                    {"compiler_name": "Clang", "count": 2, "build_number": 222},
                    {"compiler_name": "GCC", "count": 3, "build_number": 333},
                    {"compiler_name": "ICC", "count": 4, "build_number": 444},
                    {"compiler_name": "LLVM", "count": 5, "build_number": 555},
                    {"compiler_name": "TinyCC", "count": 6, "build_number": 666},
                ],
            },
            "impfuzzy": {
                "available": True,
                "impfuzzy_hash": "imp",
                "import_count": 10,
                "dll_count": 2,
                "imports_processed": [f"imp{i}" for i in range(12)],
            },
            "ccbhash": {
                "available": True,
                "binary_ccbhash": "a" * 80,
                "total_functions": 10,
                "analyzed_functions": 8,
                "unique_hashes": 5,
                "similar_functions": [
                    {"count": 4, "functions": ["f1", "f2", "f3", "f4"]},
                ],
            },
            "binlex": {
                "available": True,
                "total_functions": 5,
                "analyzed_functions": 4,
                "ngram_sizes": [3, 4],
                "unique_signatures": {3: 2, 4: 1},
                "similar_functions": {3: [{"count": 2}], 4: [{"count": 3}]},
                "binary_signature": {3: "h3", 4: "h4"},
                "top_ngrams": {3: [("A" * 60, 1), ("B", 2)]},
            },
            "binbloom": {
                "available": True,
                "total_functions": 5,
                "analyzed_functions": 5,
                "capacity": 100,
                "error_rate": 0.01,
                "unique_signatures": 2,
                "function_signatures": {
                    "f1": {"instruction_count": 10, "unique_instructions": 5, "signature": "sig1"},
                    "f2": {"instruction_count": 20, "unique_instructions": 10, "signature": "sig2"},
                },
                "similar_functions": [
                    {
                        "count": 6,
                        "signature": "s" * 40,
                        "functions": ["func1", "func2", "func3", "func4", "func5", "func6"],
                    },
                    {"count": 2, "signature": "sig2", "functions": []},
                    {"count": 1, "signature": "sig3", "functions": ["f"]},
                    {"count": 1, "signature": "sig4", "functions": ["f"]},
                ],
                "binary_signature": "b" * 70,
                "bloom_stats": {"average_fill_rate": 0.5, "total_filters": 2},
            },
            "simhash": {
                "available": True,
                "feature_stats": {
                    "total_features": 3,
                    "total_strings": 2,
                    "total_opcodes": 1,
                    "feature_diversity": 0.123,
                    "most_common_features": [("STR:abc", 5), ("OPTYPE:xyz", 2)],
                },
                "combined_simhash": {"hex": "a" * 40, "feature_count": 10},
                "strings_simhash": {"hex": "b" * 10},
                "opcodes_simhash": {"hex": "c" * 10},
                "function_simhashes": {"f1": "x"},
                "total_functions": 5,
                "analyzed_functions": 4,
                "similarity_groups": [
                    {
                        "count": 6,
                        "representative_hash": "h" * 30,
                        "functions": ["func1", "func2", "func3", "func4", "func5", "func6"],
                    },
                    {"count": 1, "representative_hash": "h2", "functions": []},
                    {"count": 1, "representative_hash": "h3", "functions": []},
                    {"count": 1, "representative_hash": "h4", "functions": []},
                ],
            },
            "bindiff": {
                "comparison_ready": True,
                "filename": "sample.bin",
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
                        ".x",
                        ".y",
                    ],
                    "import_count": 2,
                    "export_count": 1,
                },
                "function_features": {"function_count": 5, "cfg_features": [1, 2]},
                "string_features": {
                    "total_strings": 10,
                    "categorized_strings": {"api": [], "url": []},
                },
                "signatures": {"structural": "abc", "function": "N/A", "string": "def"},
            },
            "functions": {
                "total_functions": 10,
                "machoc_hashes": {"f1": "h1", "f2": "h1", "f3": "h2"},
            },
            "indicators": [
                {"type": "Anti-VM", "description": "Detected", "severity": "High"},
            ],
        }

        display_sections._display_rich_header(results)
        display_sections._display_impfuzzy(results)
        display_sections._display_ccbhash(results)
        display_sections._display_binlex(results)
        display_sections._display_binbloom(results)
        display_sections._display_simhash(results)
        display_sections._display_bindiff(results)
        display_sections._display_machoc_functions(results)
        display_sections._display_indicators(results)

        # Exercise unavailable/error branches.
        results["rich_header"] = {"available": False, "error": "missing"}
        results["impfuzzy"] = {"available": False, "error": "missing", "library_available": False}
        results["ccbhash"] = {"available": False, "error": "missing"}
        results["binlex"] = {"available": False, "error": "missing"}
        results["binbloom"] = {"available": False, "library_available": False}
        results["simhash"] = {"available": False, "library_available": False}
        results["bindiff"] = {"comparison_ready": False, "error": "missing"}

        display_sections._display_rich_header(results)
        display_sections._display_impfuzzy(results)
        display_sections._display_ccbhash(results)
        display_sections._display_binlex(results)
        display_sections._display_binbloom(results)
        display_sections._display_simhash(results)
        display_sections._display_bindiff(results)
    finally:
        display_module.console.file = original_file

    output = buffer.getvalue()
    assert "Rich Header" in output
    assert "Binbloom" in output
