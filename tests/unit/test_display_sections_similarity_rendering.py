"""Comprehensive tests for display_sections_similarity.py rendering."""

import io

from rich.console import Console

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
    _display_binbloom,
    _display_binbloom_signature_details,
    _display_bindiff,
    _display_binlex,
    _display_machoc_functions,
    _display_simhash,
)
from rich.table import Table


def _make_console():
    return Console(file=io.StringIO(), record=True, width=120)


def _get_text(console: Console) -> str:
    return console.export_text()


def test_display_binlex_available(monkeypatch):
    from r2inspect.cli import display_sections_similarity
    
    console = _make_console()
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    
    results = {
        "binlex": {
            "available": True,
            "total_functions": 50,
            "analyzed_functions": 45,
            "ngram_sizes": [2, 3],
            "unique_signatures": {2: 30, 3: 35},
            "similar_functions": {2: [], 3: []},
            "binary_signature": {2: "abc123", 3: "def456"},
            "top_ngrams": {},
        }
    }
    
    _display_binlex(results)
    text = _get_text(console)
    
    assert "Binlex" in text
    assert "50" in text
    assert "45" in text
    assert "2, 3" in text


def test_display_binlex_not_available(monkeypatch):
    from r2inspect.cli import display_sections_similarity
    
    console = _make_console()
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    
    results = {
        "binlex": {
            "available": False,
            "error": "Binlex not installed",
        }
    }
    
    _display_binlex(results)
    text = _get_text(console)
    
    assert "Binlex" in text
    assert "Not Available" in text
    assert "Binlex not installed" in text


def test_display_binlex_not_present(monkeypatch):
    from r2inspect.cli import display_sections_similarity
    
    console = _make_console()
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    
    results = {}
    
    _display_binlex(results)
    text = _get_text(console)
    
    assert "Binlex" not in text


def test_add_binlex_basic_stats():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    binlex_info = {
        "total_functions": 100,
        "analyzed_functions": 90,
        "ngram_sizes": [2, 3, 4],
    }
    
    ngram_sizes = _add_binlex_basic_stats(table, binlex_info)
    
    assert ngram_sizes == [2, 3, 4]
    assert len(table.rows) == 3


def test_add_binlex_unique_signatures():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    ngram_sizes = [2, 3]
    unique_signatures = {2: 50, 3: 60}
    
    _add_binlex_unique_signatures(table, ngram_sizes, unique_signatures)
    
    assert len(table.rows) == 2


def test_add_binlex_unique_signatures_partial():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    ngram_sizes = [2, 3, 4]
    unique_signatures = {2: 50}
    
    _add_binlex_unique_signatures(table, ngram_sizes, unique_signatures)
    
    assert len(table.rows) == 1


def test_add_binlex_similarity_groups_with_groups():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    ngram_sizes = [2]
    similar_functions = {
        2: [
            {"count": 10, "signature": "abc"},
        ]
    }
    
    _add_binlex_similarity_groups(table, ngram_sizes, similar_functions)
    
    assert len(table.rows) == 2


def test_add_binlex_similarity_groups_empty():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    ngram_sizes = [2]
    similar_functions = {2: []}
    
    _add_binlex_similarity_groups(table, ngram_sizes, similar_functions)
    
    assert len(table.rows) == 0


def test_add_binlex_binary_signatures():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    ngram_sizes = [2, 3]
    binary_signature = {2: "abc123", 3: "def456" * 20}
    
    _add_binlex_binary_signatures(table, ngram_sizes, binary_signature)
    
    assert len(table.rows) == 2


def test_add_binlex_top_ngrams():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    ngram_sizes = [2]
    top_ngrams = {
        2: [
            ("ngram1&nbsp;test&amp;more", 10),
            ("ngram2", 5),
            ("very_long_ngram_" * 10, 3),
        ]
    }
    
    _add_binlex_top_ngrams(table, ngram_sizes, top_ngrams)
    
    assert len(table.rows) == 1


def test_add_binlex_entries():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    binlex_info = {
        "total_functions": 50,
        "analyzed_functions": 45,
        "ngram_sizes": [2],
        "unique_signatures": {2: 30},
        "similar_functions": {2: []},
        "binary_signature": {2: "abc"},
        "top_ngrams": {},
    }
    
    _add_binlex_entries(table, binlex_info)
    
    assert len(table.rows) > 0


def test_display_binbloom_available(monkeypatch):
    from r2inspect.cli import display_sections_similarity
    
    console = _make_console()
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    
    results = {
        "binbloom": {
            "available": True,
            "total_functions": 100,
            "analyzed_functions": 95,
            "capacity": 1000,
            "error_rate": 0.01,
            "unique_signatures": 80,
            "binary_signature": "bloom_sig",
            "bloom_stats": {
                "average_fill_rate": 0.5,
                "total_filters": 5,
            },
        }
    }
    
    _display_binbloom(results)
    text = _get_text(console)
    
    assert "Binbloom" in text
    assert "100" in text
    assert "95" in text


def test_display_binbloom_not_available_with_error(monkeypatch):
    from r2inspect.cli import display_sections_similarity
    
    console = _make_console()
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    
    results = {
        "binbloom": {
            "available": False,
            "error": "Test error",
        }
    }
    
    _display_binbloom(results)
    text = _get_text(console)
    
    assert "Not Available" in text
    assert "Test error" in text


def test_display_binbloom_library_not_available(monkeypatch):
    from r2inspect.cli import display_sections_similarity
    
    console = _make_console()
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    
    results = {
        "binbloom": {
            "available": False,
            "library_available": False,
        }
    }
    
    _display_binbloom(results)
    text = _get_text(console)
    
    assert "pybloom-live" in text


def test_add_binbloom_stats():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    binbloom_info = {
        "total_functions": 100,
        "analyzed_functions": 95,
        "capacity": 1000,
        "error_rate": 0.01,
        "unique_signatures": 80,
    }
    
    _add_binbloom_stats(table, binbloom_info)
    
    assert len(table.rows) >= 5


def test_add_binbloom_stats_with_function_signatures():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    binbloom_info = {
        "total_functions": 100,
        "analyzed_functions": 95,
        "capacity": 1000,
        "error_rate": 0.01,
        "unique_signatures": 80,
        "function_signatures": {
            "func1": {"instruction_count": 10, "unique_instructions": 8},
            "func2": {"instruction_count": 20, "unique_instructions": 15},
        },
    }
    
    _add_binbloom_stats(table, binbloom_info)
    
    assert len(table.rows) >= 7


def test_add_binbloom_similar_groups_empty():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    binbloom_info = {"similar_functions": []}
    
    _add_binbloom_similar_groups(table, binbloom_info)
    
    assert len(table.rows) == 1


def test_add_binbloom_similar_groups_with_data():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    binbloom_info = {
        "similar_functions": [
            {
                "count": 5,
                "signature": "sig1",
                "functions": ["func1", "func2"],
            }
        ]
    }
    
    _add_binbloom_similar_groups(table, binbloom_info)
    
    assert len(table.rows) >= 1


def test_add_binbloom_similar_groups_multiple():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    binbloom_info = {
        "similar_functions": [
            {"count": 5, "signature": "sig1", "functions": ["f1"]},
            {"count": 3, "signature": "sig2", "functions": ["f2"]},
            {"count": 2, "signature": "sig3", "functions": ["f3"]},
            {"count": 1, "signature": "sig4", "functions": ["f4"]},
        ]
    }
    
    _add_binbloom_similar_groups(table, binbloom_info)
    
    assert len(table.rows) >= 1


def test_add_binbloom_group():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    group = {
        "count": 10,
        "signature": "short_sig",
        "functions": ["func1", "func2", "func3"],
    }
    
    _add_binbloom_group(table, 1, group)
    
    assert len(table.rows) >= 3


def test_add_binbloom_group_long_signature():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    group = {
        "count": 10,
        "signature": "a" * 100,
        "functions": [],
    }
    
    _add_binbloom_group(table, 1, group)
    
    assert len(table.rows) == 2


def test_add_binbloom_group_many_functions():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    group = {
        "count": 10,
        "signature": "sig",
        "functions": [f"func{i}" for i in range(10)],
    }
    
    _add_binbloom_group(table, 1, group)
    
    assert len(table.rows) >= 3


def test_add_binbloom_group_long_function_names():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    group = {
        "count": 2,
        "signature": "sig",
        "functions": ["very_long_function_name_" * 5, "short"],
    }
    
    _add_binbloom_group(table, 1, group)
    
    assert len(table.rows) == 3


def test_add_binbloom_binary_signature():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    binbloom_info = {"binary_signature": "test_signature"}
    
    _add_binbloom_binary_signature(table, binbloom_info)
    
    assert len(table.rows) == 1


def test_add_binbloom_binary_signature_none():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    binbloom_info = {}
    
    _add_binbloom_binary_signature(table, binbloom_info)
    
    assert len(table.rows) == 0


def test_add_binbloom_bloom_stats():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    binbloom_info = {
        "bloom_stats": {
            "average_fill_rate": 0.75,
            "total_filters": 10,
        }
    }
    
    _add_binbloom_bloom_stats(table, binbloom_info)
    
    assert len(table.rows) == 2


def test_add_binbloom_bloom_stats_empty():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    binbloom_info = {}
    
    _add_binbloom_bloom_stats(table, binbloom_info)
    
    assert len(table.rows) == 0


def test_display_binbloom_signature_details_not_available(monkeypatch):
    from r2inspect.cli import display_sections_similarity
    
    console = _make_console()
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    
    binbloom_info = {"available": False}
    
    _display_binbloom_signature_details(binbloom_info)
    text = _get_text(console)
    
    assert "Signature Details" not in text


def test_display_binbloom_signature_details_single_signature(monkeypatch):
    from r2inspect.cli import display_sections_similarity
    
    console = _make_console()
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    
    binbloom_info = {"available": True, "unique_signatures": 1}
    
    _display_binbloom_signature_details(binbloom_info)
    text = _get_text(console)
    
    assert "Signature Details" not in text


def test_display_binbloom_signature_details_with_data(monkeypatch):
    from r2inspect.cli import display_sections_similarity
    
    console = _make_console()
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    
    binbloom_info = {
        "available": True,
        "unique_signatures": 3,
        "function_signatures": {
            "func1&nbsp;test&amp;x": {"signature": "sig1"},
            "func2": {"signature": "sig1"},
            "func3": {"signature": "sig2"},
            "func4": {"signature": "sig2" * 50},
        },
    }
    
    _display_binbloom_signature_details(binbloom_info)
    text = _get_text(console)
    
    assert "Signature Details" in text


def test_display_simhash_available(monkeypatch):
    from r2inspect.cli import display_sections_similarity
    
    console = _make_console()
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    
    results = {
        "simhash": {
            "available": True,
            "feature_stats": {
                "total_features": 100,
                "total_strings": 50,
                "total_opcodes": 50,
                "feature_diversity": 0.8,
            },
        }
    }
    
    _display_simhash(results)
    text = _get_text(console)
    
    assert "SimHash" in text
    assert "100" in text


def test_display_simhash_not_available_with_error(monkeypatch):
    from r2inspect.cli import display_sections_similarity
    
    console = _make_console()
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    
    results = {
        "simhash": {
            "available": False,
            "error": "SimHash failed",
        }
    }
    
    _display_simhash(results)
    text = _get_text(console)
    
    assert "Not Available" in text
    assert "SimHash failed" in text


def test_display_simhash_library_not_available(monkeypatch):
    from r2inspect.cli import display_sections_similarity
    
    console = _make_console()
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    
    results = {
        "simhash": {
            "available": False,
            "library_available": False,
        }
    }
    
    _display_simhash(results)
    text = _get_text(console)
    
    assert "simhash library" in text


def test_display_bindiff_comparison_ready(monkeypatch):
    from r2inspect.cli import display_sections_similarity
    
    console = _make_console()
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    
    results = {
        "bindiff": {
            "comparison_ready": True,
            "filename": "test.exe",
        }
    }
    
    _display_bindiff(results)
    text = _get_text(console)
    
    assert "BinDiff" in text
    assert "Comparison Ready" in text


def test_display_bindiff_not_ready_with_error(monkeypatch):
    from r2inspect.cli import display_sections_similarity
    
    console = _make_console()
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    
    results = {
        "bindiff": {
            "comparison_ready": False,
            "error": "BinDiff error",
        }
    }
    
    _display_bindiff(results)
    text = _get_text(console)
    
    assert "Not Available" in text
    assert "BinDiff error" in text


def test_display_bindiff_not_present(monkeypatch):
    from r2inspect.cli import display_sections_similarity
    
    console = _make_console()
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    
    results = {}
    
    _display_bindiff(results)
    text = _get_text(console)
    
    assert "BinDiff" not in text


def test_display_machoc_functions_basic(monkeypatch):
    from r2inspect.cli import display_sections_similarity
    
    console = _make_console()
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    
    results = {
        "functions": {
            "total_functions": 50,
            "machoc_hashes": {
                "func1": "hash1",
                "func2": "hash2",
                "func3": "hash1",
            },
        }
    }
    
    _display_machoc_functions(results)
    text = _get_text(console)
    
    assert "Function Analysis" in text
    assert "50" in text
    assert "2" in text
    assert "1" in text


def test_display_machoc_functions_no_hashes(monkeypatch):
    from r2inspect.cli import display_sections_similarity
    
    console = _make_console()
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    
    results = {
        "functions": {
            "total_functions": 50,
        }
    }
    
    _display_machoc_functions(results)
    text = _get_text(console)
    
    assert "Function Analysis" in text
    assert "0" in text


def test_display_machoc_functions_not_present(monkeypatch):
    from r2inspect.cli import display_sections_similarity
    
    console = _make_console()
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    
    results = {}
    
    _display_machoc_functions(results)
    text = _get_text(console)
    
    assert "Function Analysis" not in text
