#!/usr/bin/env python3
"""
Comprehensive tests for r2inspect/cli/display_sections_similarity.py module.
Tests similarity display rendering, table generation, and formatting.
Coverage target: 100% (currently 18%)
"""

from typing import Any

import pytest
from rich.table import Table

from r2inspect.cli.display_sections_similarity import (
    _add_binbloom_binary_signature,
    _add_binbloom_bloom_stats,
    _add_binbloom_group,
    _add_binbloom_similar_groups,
    _add_binbloom_stats,
    _add_binlex_basic_stats,
    _add_binlex_binary_signatures,
    _add_binlex_entries,
    _add_binlex_similarity_groups,
    _add_binlex_top_ngrams,
    _add_binlex_unique_signatures,
    _display_bindiff,
    _display_binbloom,
    _display_binbloom_signature_details,
    _display_binlex,
    _display_machoc_functions,
    _display_simhash,
)


def test_display_binlex_available():
    """Test binlex display when data is available"""
    results = {
        "binlex": {
            "available": True,
            "total_functions": 100,
            "analyzed_functions": 95,
            "ngram_sizes": [3, 4, 5],
            "unique_signatures": {3: 50, 4: 60, 5: 70},
            "similar_functions": {
                3: [{"count": 5, "signature": "abc"}],
                4: [{"count": 3, "signature": "def"}]
            },
            "binary_signature": {3: "sig3", 4: "sig4"},
            "top_ngrams": {
                3: [("ngram1", 10), ("ngram2", 8)],
                4: [("ngram3", 15)]
            }
        }
    }
    _display_binlex(results)


def test_display_binlex_not_available():
    """Test binlex display when not available"""
    results = {
        "binlex": {
            "available": False,
            "error": "Binlex library not found"
        }
    }
    _display_binlex(results)


def test_display_binlex_missing():
    """Test binlex display when section is missing"""
    results = {}
    _display_binlex(results)


def test_add_binlex_entries():
    """Test adding binlex entries to table"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    binlex_info = {
        "total_functions": 100,
        "analyzed_functions": 95,
        "ngram_sizes": [3, 4],
        "unique_signatures": {3: 50, 4: 60},
        "similar_functions": {},
        "binary_signature": {},
        "top_ngrams": {}
    }
    _add_binlex_entries(table, binlex_info)
    assert table.row_count > 0


def test_add_binlex_basic_stats():
    """Test adding binlex basic statistics"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    binlex_info = {
        "total_functions": 100,
        "analyzed_functions": 95,
        "ngram_sizes": [3, 4, 5]
    }
    ngram_sizes = _add_binlex_basic_stats(table, binlex_info)
    
    assert ngram_sizes == [3, 4, 5]
    assert table.row_count == 3


def test_add_binlex_unique_signatures():
    """Test adding binlex unique signatures"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    _add_binlex_unique_signatures(table, [3, 4], {3: 50, 4: 60})
    assert table.row_count == 2


def test_add_binlex_unique_signatures_missing():
    """Test adding binlex unique signatures with missing data"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    _add_binlex_unique_signatures(table, [3, 4, 5], {3: 50})
    assert table.row_count == 1


def test_add_binlex_similarity_groups():
    """Test adding binlex similarity groups"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    similar_functions = {
        3: [{"count": 5, "signature": "abc"}],
        4: [{"count": 3, "signature": "def"}]
    }
    _add_binlex_similarity_groups(table, [3, 4], similar_functions)
    assert table.row_count > 0


def test_add_binlex_similarity_groups_empty():
    """Test adding binlex similarity groups when empty"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    _add_binlex_similarity_groups(table, [3, 4], {})
    assert table.row_count == 0


def test_add_binlex_binary_signatures():
    """Test adding binlex binary signatures"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    binary_signature = {
        3: "a" * 100,
        4: "b" * 100
    }
    _add_binlex_binary_signatures(table, [3, 4], binary_signature)
    assert table.row_count == 2


def test_add_binlex_top_ngrams():
    """Test adding binlex top ngrams"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    top_ngrams = {
        3: [("ngram1", 10), ("ngram2", 8), ("ngram3", 5)],
        4: [("long_ngram_" + "x" * 100, 15)]
    }
    _add_binlex_top_ngrams(table, [3, 4], top_ngrams)
    assert table.row_count == 2


def test_add_binlex_top_ngrams_with_html():
    """Test adding binlex top ngrams with HTML entities"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    top_ngrams = {
        3: [("ngram&nbsp;test", 10), ("ngram&amp;test", 8)]
    }
    _add_binlex_top_ngrams(table, [3], top_ngrams)
    assert table.row_count == 1


def test_display_binbloom_available():
    """Test binbloom display when available"""
    results = {
        "binbloom": {
            "available": True,
            "total_functions": 100,
            "analyzed_functions": 95,
            "capacity": 1000,
            "error_rate": 0.01,
            "unique_signatures": 90,
            "function_signatures": {
                "func1": {"instruction_count": 10, "unique_instructions": 8},
                "func2": {"instruction_count": 15, "unique_instructions": 12}
            },
            "similar_functions": [
                {"count": 5, "signature": "sig1", "functions": ["f1", "f2", "f3"]}
            ],
            "binary_signature": "binary_sig_hash",
            "bloom_stats": {
                "average_fill_rate": 0.5,
                "total_filters": 10
            }
        }
    }
    _display_binbloom(results)


def test_display_binbloom_not_available():
    """Test binbloom display when not available"""
    results = {
        "binbloom": {
            "available": False,
            "library_available": False
        }
    }
    _display_binbloom(results)


def test_display_binbloom_with_error():
    """Test binbloom display with error message"""
    results = {
        "binbloom": {
            "available": False,
            "error": "Analysis failed"
        }
    }
    _display_binbloom(results)


def test_add_binbloom_stats():
    """Test adding binbloom statistics"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    binbloom_info = {
        "total_functions": 100,
        "analyzed_functions": 95,
        "capacity": 1000,
        "error_rate": 0.01,
        "unique_signatures": 90,
        "function_signatures": {
            "func1": {"instruction_count": 10, "unique_instructions": 8},
            "func2": {"instruction_count": 15, "unique_instructions": 12}
        }
    }
    _add_binbloom_stats(table, binbloom_info)
    assert table.row_count > 5


def test_add_binbloom_stats_no_signatures():
    """Test adding binbloom stats without function signatures"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    binbloom_info = {
        "total_functions": 100,
        "analyzed_functions": 95,
        "capacity": 1000,
        "error_rate": 0.01,
        "unique_signatures": 90,
        "function_signatures": {}
    }
    _add_binbloom_stats(table, binbloom_info)
    assert table.row_count >= 4


def test_add_binbloom_similar_groups():
    """Test adding binbloom similar groups"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    binbloom_info = {
        "similar_functions": [
            {"count": 5, "signature": "sig1", "functions": ["f1", "f2"]},
            {"count": 3, "signature": "sig2", "functions": ["f3", "f4"]}
        ]
    }
    _add_binbloom_similar_groups(table, binbloom_info)
    assert table.row_count > 0


def test_add_binbloom_similar_groups_empty():
    """Test adding binbloom similar groups when empty"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    binbloom_info = {"similar_functions": []}
    _add_binbloom_similar_groups(table, binbloom_info)
    assert table.row_count == 1


def test_add_binbloom_similar_groups_many():
    """Test adding binbloom similar groups with many groups"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    similar_functions = [
        {"count": i, "signature": f"sig{i}", "functions": [f"f{i}"]}
        for i in range(5)
    ]
    binbloom_info = {"similar_functions": similar_functions}
    _add_binbloom_similar_groups(table, binbloom_info)
    assert table.row_count > 0


def test_add_binbloom_group():
    """Test adding single binbloom group"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    group = {
        "count": 5,
        "signature": "a" * 100,
        "functions": ["func1", "func2", "func3", "func4", "func5", "func6"]
    }
    _add_binbloom_group(table, 1, group)
    assert table.row_count > 0


def test_add_binbloom_group_no_functions():
    """Test adding binbloom group without functions"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    group = {
        "count": 5,
        "signature": "sig1",
        "functions": []
    }
    _add_binbloom_group(table, 1, group)
    assert table.row_count == 2


def test_add_binbloom_binary_signature():
    """Test adding binbloom binary signature"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    binbloom_info = {"binary_signature": "a" * 100}
    _add_binbloom_binary_signature(table, binbloom_info)
    assert table.row_count == 1


def test_add_binbloom_binary_signature_missing():
    """Test adding binbloom binary signature when missing"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    _add_binbloom_binary_signature(table, {})
    assert table.row_count == 0


def test_add_binbloom_bloom_stats():
    """Test adding binbloom bloom statistics"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    binbloom_info = {
        "bloom_stats": {
            "average_fill_rate": 0.5,
            "total_filters": 10
        }
    }
    _add_binbloom_bloom_stats(table, binbloom_info)
    assert table.row_count == 2


def test_add_binbloom_bloom_stats_missing():
    """Test adding binbloom bloom stats when missing"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    _add_binbloom_bloom_stats(table, {})
    assert table.row_count == 0


def test_display_binbloom_signature_details():
    """Test displaying binbloom signature details"""
    binbloom_info = {
        "available": True,
        "unique_signatures": 3,
        "function_signatures": {
            "func1": {"signature": "sig1"},
            "func2": {"signature": "sig2"},
            "func3": {"signature": "sig1"}
        }
    }
    _display_binbloom_signature_details(binbloom_info)


def test_display_binbloom_signature_details_not_available():
    """Test displaying signature details when not available"""
    binbloom_info = {"available": False}
    _display_binbloom_signature_details(binbloom_info)


def test_display_binbloom_signature_details_few_signatures():
    """Test displaying signature details with few signatures"""
    binbloom_info = {
        "available": True,
        "unique_signatures": 1,
        "function_signatures": {"func1": {"signature": "sig1"}}
    }
    _display_binbloom_signature_details(binbloom_info)


def test_display_simhash_available():
    """Test simhash display when available"""
    results = {
        "simhash": {
            "available": True,
            "feature_stats": {
                "total_features": 100,
                "total_strings": 50,
                "total_opcodes": 50,
                "feature_diversity": 0.8,
                "most_common_features": [("feat1", 10), ("feat2", 8)]
            },
            "combined_simhash": {"hex": "abc123", "feature_count": 100},
            "strings_simhash": {"hex": "def456"},
            "opcodes_simhash": {"hex": "ghi789"},
            "function_simhashes": {"func1": "hash1"},
            "total_functions": 10,
            "analyzed_functions": 9,
            "similarity_groups": [
                {"count": 3, "representative_hash": "hash1", "functions": ["f1", "f2"]}
            ]
        }
    }
    _display_simhash(results)


def test_display_simhash_not_available():
    """Test simhash display when not available"""
    results = {
        "simhash": {
            "available": False,
            "library_available": False
        }
    }
    _display_simhash(results)


def test_display_simhash_with_error():
    """Test simhash display with error"""
    results = {
        "simhash": {
            "available": False,
            "error": "SimHash analysis failed"
        }
    }
    _display_simhash(results)


def test_display_bindiff_ready():
    """Test bindiff display when comparison ready"""
    results = {
        "bindiff": {
            "comparison_ready": True,
            "filename": "test.exe",
            "structural_features": {
                "file_type": "PE32",
                "file_size": 10240,
                "section_count": 5,
                "section_names": [".text", ".data", ".rdata"],
                "import_count": 20,
                "export_count": 5
            },
            "function_features": {
                "function_count": 100,
                "cfg_features": {"func1": {}, "func2": {}}
            },
            "string_features": {
                "total_strings": 50,
                "categorized_strings": {"urls": 5, "paths": 10}
            },
            "signatures": {
                "imphash": "abc123",
                "richpe": "def456"
            }
        }
    }
    _display_bindiff(results)


def test_display_bindiff_not_ready():
    """Test bindiff display when not ready"""
    results = {
        "bindiff": {
            "comparison_ready": False,
            "error": "BinDiff analysis failed"
        }
    }
    _display_bindiff(results)


def test_display_bindiff_missing():
    """Test bindiff display when section missing"""
    results = {}
    _display_bindiff(results)


def test_display_machoc_functions():
    """Test displaying machoc function analysis"""
    results = {
        "functions": {
            "total_functions": 100,
            "machoc_hashes": {
                "func1": "hash1",
                "func2": "hash2",
                "func3": "hash1",
                "func4": "hash3"
            }
        }
    }
    _display_machoc_functions(results)


def test_display_machoc_functions_no_hashes():
    """Test displaying machoc functions without hashes"""
    results = {
        "functions": {
            "total_functions": 100,
            "machoc_hashes": {}
        }
    }
    _display_machoc_functions(results)


def test_display_machoc_functions_missing():
    """Test displaying machoc functions when section missing"""
    results = {}
    _display_machoc_functions(results)
