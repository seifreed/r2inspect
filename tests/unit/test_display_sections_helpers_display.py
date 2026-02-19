#!/usr/bin/env python3
"""
Comprehensive tests for r2inspect/cli/display_sections_helpers.py module.
Tests helper functions for display section rendering.
Coverage target: 100% (currently 14%)
"""

from typing import Any

import pytest
from rich.table import Table

from r2inspect.cli.display_sections_helpers import (
    _add_bindiff_entries,
    _add_bindiff_functions,
    _add_bindiff_signatures,
    _add_bindiff_strings,
    _add_bindiff_structural,
    _add_simhash_feature_stats,
    _add_simhash_function_analysis,
    _add_simhash_hashes,
    _add_simhash_similarity_group,
    _add_simhash_similarity_groups,
    _add_simhash_top_features,
    _format_simhash_hex,
)


def test_add_simhash_feature_stats_complete():
    """Test adding complete simhash feature statistics"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    feature_stats = {
        "total_features": 100,
        "total_strings": 50,
        "total_opcodes": 50,
        "feature_diversity": 0.85
    }
    _add_simhash_feature_stats(table, feature_stats)
    
    assert table.row_count == 4


def test_add_simhash_feature_stats_partial():
    """Test adding partial simhash feature statistics"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    feature_stats = {
        "total_features": 100,
        "feature_diversity": 0.75
    }
    _add_simhash_feature_stats(table, feature_stats)
    
    assert table.row_count == 4


def test_add_simhash_feature_stats_zero_values():
    """Test adding simhash feature stats with zero values"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    feature_stats = {
        "total_features": 0,
        "total_strings": 0,
        "total_opcodes": 0,
        "feature_diversity": 0.0
    }
    _add_simhash_feature_stats(table, feature_stats)
    
    assert table.row_count == 4


def test_format_simhash_hex_short():
    """Test formatting short simhash hex string"""
    hex_str = "abc123def456"
    result = _format_simhash_hex(hex_str)
    assert result == "abc123def456"
    assert "\n" not in result


def test_format_simhash_hex_long():
    """Test formatting long simhash hex string"""
    hex_str = "a" * 64
    result = _format_simhash_hex(hex_str)
    assert "\n" in result
    assert result.startswith("a" * 32)


def test_format_simhash_hex_exactly_32():
    """Test formatting simhash hex string of exactly 32 characters"""
    hex_str = "a" * 32
    result = _format_simhash_hex(hex_str)
    assert result == hex_str
    assert "\n" not in result


def test_format_simhash_hex_33_chars():
    """Test formatting simhash hex string with 33 characters"""
    hex_str = "a" * 33
    result = _format_simhash_hex(hex_str)
    assert "\n" in result


def test_add_simhash_hashes_all_types():
    """Test adding all simhash hash types"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    simhash_info = {
        "combined_simhash": {"hex": "abc123def456", "feature_count": 100},
        "strings_simhash": {"hex": "ghi789jkl012"},
        "opcodes_simhash": {"hex": "mno345pqr678"}
    }
    _add_simhash_hashes(table, simhash_info)
    
    assert table.row_count == 4


def test_add_simhash_hashes_combined_only():
    """Test adding only combined simhash"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    simhash_info = {
        "combined_simhash": {"hex": "abc123", "feature_count": 50}
    }
    _add_simhash_hashes(table, simhash_info)
    
    assert table.row_count == 2


def test_add_simhash_hashes_strings_only():
    """Test adding only strings simhash"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    simhash_info = {
        "strings_simhash": {"hex": "def456"}
    }
    _add_simhash_hashes(table, simhash_info)
    
    assert table.row_count == 1


def test_add_simhash_hashes_opcodes_only():
    """Test adding only opcodes simhash"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    simhash_info = {
        "opcodes_simhash": {"hex": "ghi789"}
    }
    _add_simhash_hashes(table, simhash_info)
    
    assert table.row_count == 1


def test_add_simhash_hashes_none():
    """Test adding simhash hashes when none present"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    _add_simhash_hashes(table, {})
    
    assert table.row_count == 0


def test_add_simhash_hashes_long():
    """Test adding simhash hashes with long hex strings"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    simhash_info = {
        "combined_simhash": {"hex": "a" * 64, "feature_count": 100}
    }
    _add_simhash_hashes(table, simhash_info)
    
    assert table.row_count == 2


def test_add_simhash_function_analysis_complete():
    """Test adding complete simhash function analysis"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    simhash_info = {
        "function_simhashes": {"func1": "hash1", "func2": "hash2"},
        "total_functions": 100,
        "analyzed_functions": 95,
        "similarity_groups": [
            {"count": 3, "representative_hash": "hash1", "functions": ["f1", "f2"]}
        ]
    }
    _add_simhash_function_analysis(table, simhash_info)
    
    assert table.row_count > 2


def test_add_simhash_function_analysis_no_groups():
    """Test adding function analysis without similarity groups"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    simhash_info = {
        "function_simhashes": {"func1": "hash1"},
        "total_functions": 10,
        "analyzed_functions": 10,
        "similarity_groups": []
    }
    _add_simhash_function_analysis(table, simhash_info)
    
    assert table.row_count == 3


def test_add_simhash_function_analysis_no_functions():
    """Test adding function analysis without function simhashes"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    simhash_info = {
        "function_simhashes": {},
        "total_functions": 0,
        "analyzed_functions": 0
    }
    _add_simhash_function_analysis(table, simhash_info)
    
    assert table.row_count == 0


def test_add_simhash_similarity_groups_single():
    """Test adding single similarity group"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    similarity_groups = [
        {"count": 5, "representative_hash": "hash1", "functions": ["f1", "f2", "f3"]}
    ]
    _add_simhash_similarity_groups(table, similarity_groups)
    
    assert table.row_count > 1


def test_add_simhash_similarity_groups_multiple():
    """Test adding multiple similarity groups"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    similarity_groups = [
        {"count": 5, "representative_hash": "hash1", "functions": ["f1", "f2"]},
        {"count": 3, "representative_hash": "hash2", "functions": ["f3", "f4"]},
        {"count": 2, "representative_hash": "hash3", "functions": ["f5", "f6"]}
    ]
    _add_simhash_similarity_groups(table, similarity_groups)
    
    assert table.row_count > 3


def test_add_simhash_similarity_groups_many():
    """Test adding many similarity groups (more than 3)"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    similarity_groups = [
        {"count": i, "representative_hash": f"hash{i}", "functions": [f"f{i}"]}
        for i in range(5)
    ]
    _add_simhash_similarity_groups(table, similarity_groups)
    
    assert table.row_count > 0


def test_add_simhash_similarity_group_basic():
    """Test adding basic similarity group"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    group = {
        "count": 5,
        "representative_hash": "abc123def456",
        "functions": ["func1", "func2", "func3"]
    }
    _add_simhash_similarity_group(table, 1, group)
    
    assert table.row_count == 3


def test_add_simhash_similarity_group_long_hash():
    """Test adding similarity group with long hash"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    group = {
        "count": 5,
        "representative_hash": "a" * 100,
        "functions": ["func1"]
    }
    _add_simhash_similarity_group(table, 1, group)
    
    assert table.row_count == 3


def test_add_simhash_similarity_group_short_hash():
    """Test adding similarity group with short hash"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    group = {
        "count": 2,
        "representative_hash": "abc",
        "functions": ["func1", "func2"]
    }
    _add_simhash_similarity_group(table, 2, group)
    
    assert table.row_count == 3


def test_add_simhash_similarity_group_many_functions():
    """Test adding similarity group with many functions"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    functions = [f"function_{i}" for i in range(10)]
    group = {
        "count": 10,
        "representative_hash": "hash123",
        "functions": functions
    }
    _add_simhash_similarity_group(table, 1, group)
    
    assert table.row_count == 3


def test_add_simhash_similarity_group_long_function_names():
    """Test adding similarity group with long function names"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    group = {
        "count": 2,
        "representative_hash": "hash",
        "functions": ["very_long_function_name_" + "x" * 50]
    }
    _add_simhash_similarity_group(table, 1, group)
    
    assert table.row_count == 3


def test_add_simhash_similarity_group_no_functions():
    """Test adding similarity group without functions"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    group = {
        "count": 0,
        "representative_hash": "hash123",
        "functions": []
    }
    _add_simhash_similarity_group(table, 1, group)
    
    assert table.row_count == 2


def test_add_simhash_top_features_complete():
    """Test adding complete top features"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    feature_stats = {
        "most_common_features": [
            ("STR:string1", 10),
            ("OP:mov", 8),
            ("OPTYPE:arithmetic", 6)
        ]
    }
    _add_simhash_top_features(table, feature_stats)
    
    assert table.row_count == 1


def test_add_simhash_top_features_many():
    """Test adding many top features"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    feature_stats = {
        "most_common_features": [
            (f"STR:feature{i}", 10 - i) for i in range(10)
        ]
    }
    _add_simhash_top_features(table, feature_stats)
    
    assert table.row_count == 1


def test_add_simhash_top_features_long_names():
    """Test adding top features with long names"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    feature_stats = {
        "most_common_features": [
            ("STR:" + "x" * 100, 10)
        ]
    }
    _add_simhash_top_features(table, feature_stats)
    
    assert table.row_count == 1


def test_add_simhash_top_features_none():
    """Test adding top features when none present"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    _add_simhash_top_features(table, {})
    
    assert table.row_count == 0


def test_add_simhash_top_features_empty_list():
    """Test adding empty top features list"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    feature_stats = {"most_common_features": []}
    _add_simhash_top_features(table, feature_stats)
    
    assert table.row_count == 0


def test_add_bindiff_entries_complete():
    """Test adding complete bindiff entries"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    bindiff_info = {
        "filename": "test.exe",
        "structural_features": {"file_type": "PE32"},
        "function_features": {"function_count": 100},
        "string_features": {"total_strings": 50},
        "signatures": {"imphash": "abc123"}
    }
    _add_bindiff_entries(table, bindiff_info)
    
    assert table.row_count > 0


def test_add_bindiff_entries_minimal():
    """Test adding minimal bindiff entries"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    bindiff_info = {
        "filename": "test.exe",
        "structural_features": {},
        "function_features": {},
        "string_features": {},
        "signatures": {}
    }
    _add_bindiff_entries(table, bindiff_info)
    
    assert table.row_count == 1


def test_add_bindiff_structural_complete():
    """Test adding complete structural features"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    structural = {
        "file_type": "PE32",
        "file_size": 10240,
        "section_count": 5,
        "section_names": [".text", ".data", ".rdata", ".reloc", ".rsrc"],
        "import_count": 20,
        "export_count": 10
    }
    _add_bindiff_structural(table, structural)
    
    assert table.row_count == 6


def test_add_bindiff_structural_few_sections():
    """Test adding structural features with few sections"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    structural = {
        "file_type": "ELF",
        "file_size": 20480,
        "section_count": 3,
        "section_names": [".text", ".data", ".bss"],
        "import_count": 15,
        "export_count": 5
    }
    _add_bindiff_structural(table, structural)
    
    assert table.row_count == 6


def test_add_bindiff_structural_many_sections():
    """Test adding structural features with many sections"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    structural = {
        "file_type": "PE32+",
        "file_size": 102400,
        "section_count": 12,
        "section_names": [f".section{i}" for i in range(12)],
        "import_count": 50,
        "export_count": 20
    }
    _add_bindiff_structural(table, structural)
    
    assert table.row_count > 5


def test_add_bindiff_structural_no_sections():
    """Test adding structural features without section names"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    structural = {
        "file_type": "PE32",
        "file_size": 10240,
        "section_count": 5,
        "import_count": 20,
        "export_count": 10
    }
    _add_bindiff_structural(table, structural)
    
    assert table.row_count == 5


def test_add_bindiff_functions_complete():
    """Test adding complete function features"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    function_features = {
        "function_count": 150,
        "cfg_features": {
            "func1": {"blocks": 10},
            "func2": {"blocks": 15}
        }
    }
    _add_bindiff_functions(table, function_features)
    
    assert table.row_count == 2


def test_add_bindiff_functions_no_cfg():
    """Test adding function features without CFG"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    function_features = {
        "function_count": 100
    }
    _add_bindiff_functions(table, function_features)
    
    assert table.row_count == 1


def test_add_bindiff_strings_complete():
    """Test adding complete string features"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    string_features = {
        "total_strings": 100,
        "categorized_strings": {
            "urls": 10,
            "paths": 20,
            "registry": 5
        }
    }
    _add_bindiff_strings(table, string_features)
    
    assert table.row_count == 2


def test_add_bindiff_strings_no_categories():
    """Test adding string features without categories"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    string_features = {
        "total_strings": 50
    }
    _add_bindiff_strings(table, string_features)
    
    assert table.row_count == 1


def test_add_bindiff_signatures_complete():
    """Test adding complete signatures"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    signatures = {
        "imphash": "abc123def456",
        "richpe": "ghi789jkl012",
        "ssdeep": "mno345pqr678"
    }
    _add_bindiff_signatures(table, signatures)
    
    assert table.row_count == 3


def test_add_bindiff_signatures_partial():
    """Test adding partial signatures"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    signatures = {
        "imphash": "abc123",
        "richpe": ""
    }
    _add_bindiff_signatures(table, signatures)
    
    assert table.row_count == 1


def test_add_bindiff_signatures_empty_values():
    """Test adding signatures with empty values"""
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    signatures = {
        "imphash": "",
        "richpe": None
    }
    _add_bindiff_signatures(table, signatures)
    
    assert table.row_count == 0
