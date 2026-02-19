"""Comprehensive tests for display_sections_helpers.py functions."""

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


def test_add_simhash_feature_stats():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    feature_stats = {
        "total_features": 1000,
        "total_strings": 600,
        "total_opcodes": 400,
        "feature_diversity": 0.85,
    }
    
    _add_simhash_feature_stats(table, feature_stats)
    
    assert len(table.rows) == 4


def test_add_simhash_feature_stats_zero_values():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    feature_stats = {
        "total_features": 0,
        "total_strings": 0,
        "total_opcodes": 0,
        "feature_diversity": 0.0,
    }
    
    _add_simhash_feature_stats(table, feature_stats)
    
    assert len(table.rows) == 4


def test_format_simhash_hex_short():
    hash_hex = "abc123"
    result = _format_simhash_hex(hash_hex)
    assert result == "abc123"


def test_format_simhash_hex_long():
    hash_hex = "a" * 64
    result = _format_simhash_hex(hash_hex)
    assert "\n" in result
    assert result.startswith("a" * 32)


def test_format_simhash_hex_exact_32():
    hash_hex = "a" * 32
    result = _format_simhash_hex(hash_hex)
    assert result == "a" * 32
    assert "\n" not in result


def test_add_simhash_hashes_combined_only():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    simhash_info = {
        "combined_simhash": {
            "hex": "abc123",
            "feature_count": 500,
        }
    }
    
    _add_simhash_hashes(table, simhash_info)
    
    assert len(table.rows) == 2


def test_add_simhash_hashes_all_types():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    simhash_info = {
        "combined_simhash": {
            "hex": "abc123",
            "feature_count": 500,
        },
        "strings_simhash": {
            "hex": "def456",
        },
        "opcodes_simhash": {
            "hex": "ghi789",
        },
    }
    
    _add_simhash_hashes(table, simhash_info)
    
    assert len(table.rows) == 4


def test_add_simhash_hashes_long_hashes():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    simhash_info = {
        "combined_simhash": {
            "hex": "a" * 64,
            "feature_count": 500,
        },
        "strings_simhash": {
            "hex": "b" * 64,
        },
        "opcodes_simhash": {
            "hex": "c" * 64,
        },
    }
    
    _add_simhash_hashes(table, simhash_info)
    
    assert len(table.rows) == 4


def test_add_simhash_hashes_empty():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    simhash_info = {}
    
    _add_simhash_hashes(table, simhash_info)
    
    assert len(table.rows) == 0


def test_add_simhash_function_analysis_no_functions():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    simhash_info = {}
    
    _add_simhash_function_analysis(table, simhash_info)
    
    assert len(table.rows) == 0


def test_add_simhash_function_analysis_with_functions():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    simhash_info = {
        "function_simhashes": {"func1": "hash1"},
        "total_functions": 100,
        "analyzed_functions": 95,
        "similarity_groups": [],
    }
    
    _add_simhash_function_analysis(table, simhash_info)
    
    assert len(table.rows) >= 2


def test_add_simhash_function_analysis_with_groups():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    simhash_info = {
        "function_simhashes": {"func1": "hash1"},
        "total_functions": 100,
        "analyzed_functions": 95,
        "similarity_groups": [
            {
                "count": 5,
                "representative_hash": "hash123",
                "functions": ["func1", "func2"],
            }
        ],
    }
    
    _add_simhash_function_analysis(table, simhash_info)
    
    assert len(table.rows) >= 4


def test_add_simhash_similarity_groups_single():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    similarity_groups = [
        {
            "count": 5,
            "representative_hash": "hash1",
            "functions": ["func1"],
        }
    ]
    
    _add_simhash_similarity_groups(table, similarity_groups)
    
    assert len(table.rows) >= 1


def test_add_simhash_similarity_groups_multiple():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    similarity_groups = [
        {"count": 5, "representative_hash": "h1", "functions": ["f1"]},
        {"count": 3, "representative_hash": "h2", "functions": ["f2"]},
        {"count": 2, "representative_hash": "h3", "functions": ["f3"]},
        {"count": 1, "representative_hash": "h4", "functions": ["f4"]},
    ]
    
    _add_simhash_similarity_groups(table, similarity_groups)
    
    assert len(table.rows) >= 1


def test_add_simhash_similarity_group():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    group = {
        "count": 10,
        "representative_hash": "short_hash",
        "functions": ["func1", "func2"],
    }
    
    _add_simhash_similarity_group(table, 1, group)
    
    assert len(table.rows) >= 2


def test_add_simhash_similarity_group_long_hash():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    group = {
        "count": 10,
        "representative_hash": "a" * 100,
        "functions": [],
    }
    
    _add_simhash_similarity_group(table, 1, group)
    
    assert len(table.rows) == 2


def test_add_simhash_similarity_group_many_functions():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    group = {
        "count": 10,
        "representative_hash": "hash",
        "functions": [f"function_{i}" for i in range(10)],
    }
    
    _add_simhash_similarity_group(table, 1, group)
    
    assert len(table.rows) >= 2


def test_add_simhash_similarity_group_long_function_names():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    group = {
        "count": 2,
        "representative_hash": "hash",
        "functions": ["very_long_function_name_" * 5],
    }
    
    _add_simhash_similarity_group(table, 1, group)
    
    assert len(table.rows) >= 2


def test_add_simhash_top_features():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    feature_stats = {
        "most_common_features": [
            ("STR:hello", 50),
            ("OP:mov", 40),
            ("OPTYPE:call", 30),
        ]
    }
    
    _add_simhash_top_features(table, feature_stats)
    
    assert len(table.rows) == 1


def test_add_simhash_top_features_long_names():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    feature_stats = {
        "most_common_features": [
            ("STR:" + "a" * 100, 50),
        ]
    }
    
    _add_simhash_top_features(table, feature_stats)
    
    assert len(table.rows) == 1


def test_add_simhash_top_features_empty():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    feature_stats = {}
    
    _add_simhash_top_features(table, feature_stats)
    
    assert len(table.rows) == 0


def test_add_bindiff_entries_full():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    bindiff_info = {
        "filename": "test.exe",
        "structural_features": {"file_type": "PE"},
        "function_features": {"function_count": 100},
        "string_features": {"total_strings": 500},
        "signatures": {"md5": "abc123"},
    }
    
    _add_bindiff_entries(table, bindiff_info)
    
    assert len(table.rows) >= 1


def test_add_bindiff_entries_minimal():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    bindiff_info = {
        "filename": "test.exe",
    }
    
    _add_bindiff_entries(table, bindiff_info)
    
    assert len(table.rows) == 1


def test_add_bindiff_structural_full():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    structural = {
        "file_type": "PE32",
        "file_size": 102400,
        "section_count": 5,
        "section_names": [".text", ".data", ".rdata"],
        "import_count": 50,
        "export_count": 10,
    }
    
    _add_bindiff_structural(table, structural)
    
    assert len(table.rows) == 6


def test_add_bindiff_structural_many_sections():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    structural = {
        "file_type": "PE32",
        "file_size": 102400,
        "section_count": 10,
        "section_names": [f".section{i}" for i in range(10)],
        "import_count": 50,
        "export_count": 10,
    }
    
    _add_bindiff_structural(table, structural)
    
    assert len(table.rows) == 6


def test_add_bindiff_structural_no_sections():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    structural = {
        "file_type": "PE32",
        "file_size": 102400,
        "section_count": 0,
        "import_count": 50,
        "export_count": 10,
    }
    
    _add_bindiff_structural(table, structural)
    
    assert len(table.rows) == 5


def test_add_bindiff_structural_empty():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    structural = {}
    
    _add_bindiff_structural(table, structural)
    
    assert len(table.rows) == 0


def test_add_bindiff_functions():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    function_features = {
        "function_count": 100,
        "cfg_features": [{"func": "data"}] * 50,
    }
    
    _add_bindiff_functions(table, function_features)
    
    assert len(table.rows) == 2


def test_add_bindiff_functions_no_cfg():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    function_features = {
        "function_count": 100,
    }
    
    _add_bindiff_functions(table, function_features)
    
    assert len(table.rows) == 1


def test_add_bindiff_functions_empty():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    function_features = {}
    
    _add_bindiff_functions(table, function_features)
    
    assert len(table.rows) == 0


def test_add_bindiff_strings():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    string_features = {
        "total_strings": 500,
        "categorized_strings": {
            "ascii": 300,
            "unicode": 150,
            "urls": 50,
        },
    }
    
    _add_bindiff_strings(table, string_features)
    
    assert len(table.rows) == 2


def test_add_bindiff_strings_no_categories():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    string_features = {
        "total_strings": 500,
    }
    
    _add_bindiff_strings(table, string_features)
    
    assert len(table.rows) == 1


def test_add_bindiff_strings_empty():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    string_features = {}
    
    _add_bindiff_strings(table, string_features)
    
    assert len(table.rows) == 0


def test_add_bindiff_signatures():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    signatures = {
        "md5": "abc123",
        "sha256": "def456",
        "imphash": "ghi789",
    }
    
    _add_bindiff_signatures(table, signatures)
    
    assert len(table.rows) == 3


def test_add_bindiff_signatures_empty_values():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    signatures = {
        "md5": "abc123",
        "sha256": "",
        "imphash": None,
    }
    
    _add_bindiff_signatures(table, signatures)
    
    assert len(table.rows) == 1


def test_add_bindiff_signatures_empty():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    signatures = {}
    
    _add_bindiff_signatures(table, signatures)
    
    assert len(table.rows) == 0
