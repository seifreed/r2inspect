from __future__ import annotations

import io

from rich.console import Console
from rich.table import Table

from r2inspect.cli.display_sections_similarity import (
    _display_binbloom,
    _display_simhash,
    _add_binlex_basic_stats,
    _add_binlex_unique_signatures,
    _add_binlex_similarity_groups,
    _add_binlex_binary_signatures,
    _add_binlex_top_ngrams,
    _add_binlex_entries,
    _add_binbloom_stats,
    _add_binbloom_similar_groups,
    _add_binbloom_group,
    _add_binbloom_binary_signature,
    _add_binbloom_bloom_stats,
    _display_binbloom_signature_details,
    _display_binlex,
    _display_bindiff,
    _display_machoc_functions,
)
from r2inspect.cli.display_sections_helpers import (
    _add_simhash_feature_stats,
    _format_simhash_hex,
    _add_simhash_hashes,
    _add_simhash_function_analysis,
    _add_simhash_similarity_groups,
    _add_simhash_similarity_group,
    _add_simhash_top_features,
    _add_bindiff_entries,
    _add_bindiff_structural,
    _add_bindiff_functions,
    _add_bindiff_strings,
    _add_bindiff_signatures,
)


def _make_console() -> Console:
    return Console(file=io.StringIO(), record=True, width=120)


def _get_text(console: Console) -> str:
    return console.export_text()


def _make_table() -> Table:
    t = Table()
    t.add_column("Property")
    t.add_column("Value")
    return t


# --- display_sections_similarity: _display_binbloom not present (line 125) ---

def test_display_binbloom_not_present_produces_no_output(monkeypatch):
    from r2inspect.cli import display_sections_similarity
    console = _make_console()
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    _display_binbloom({})
    assert "Binbloom" not in _get_text(console)


# --- display_sections_similarity: _display_simhash not present (line 287) ---

def test_display_simhash_not_present_produces_no_output(monkeypatch):
    from r2inspect.cli import display_sections_similarity
    console = _make_console()
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    _display_simhash({})
    assert "SimHash" not in _get_text(console)


# --- Additional coverage for display_sections_similarity helper paths ---

def test_display_binlex_not_available_no_error(monkeypatch):
    from r2inspect.cli import display_sections_similarity
    console = _make_console()
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    results = {"binlex": {"available": False}}
    _display_binlex(results)
    text = _get_text(console)
    assert "Not Available" in text


def test_display_binlex_available_with_similar_functions(monkeypatch):
    from r2inspect.cli import display_sections_similarity
    console = _make_console()
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    results = {
        "binlex": {
            "available": True,
            "total_functions": 20,
            "analyzed_functions": 18,
            "ngram_sizes": [3],
            "unique_signatures": {3: 10},
            "similar_functions": {
                3: [{"count": 5, "signature": "sig_abc"}]
            },
            "binary_signature": {},
            "top_ngrams": {
                3: [
                    ("word1", 5),
                    ("word2", 3),
                    ("word3", 2),
                    ("word4", 1),
                ]
            },
        }
    }
    _display_binlex(results)
    text = _get_text(console)
    assert "Binlex" in text
    assert "20" in text


def test_add_binlex_top_ngrams_long_ngram():
    table = _make_table()
    top_ngrams = {2: [("a" * 60, 10)]}
    _add_binlex_top_ngrams(table, [2], top_ngrams)
    assert len(table.rows) == 1


def test_add_binlex_top_ngrams_html_entities():
    table = _make_table()
    top_ngrams = {2: [("hello&nbsp;world&amp;test", 7)]}
    _add_binlex_top_ngrams(table, [2], top_ngrams)
    assert len(table.rows) == 1


def test_add_binlex_top_ngrams_no_matching_size():
    table = _make_table()
    _add_binlex_top_ngrams(table, [3], {2: [("x", 1)]})
    assert len(table.rows) == 0


def test_add_binlex_similarity_groups_one_group():
    table = _make_table()
    similar_functions = {2: [{"count": 3, "signature": "s"}]}
    _add_binlex_similarity_groups(table, [2], similar_functions)
    assert len(table.rows) == 2


def test_add_binlex_binary_signatures_no_match():
    table = _make_table()
    _add_binlex_binary_signatures(table, [4], {2: "abc"})
    assert len(table.rows) == 0


def test_add_binlex_entries_full_data():
    table = _make_table()
    binlex_info = {
        "total_functions": 100,
        "analyzed_functions": 90,
        "ngram_sizes": [2, 3],
        "unique_signatures": {2: 50, 3: 60},
        "similar_functions": {2: [{"count": 5, "signature": "s"}], 3: []},
        "binary_signature": {2: "sig2", 3: "x" * 70},
        "top_ngrams": {2: [("op1", 10), ("op2", 5)], 3: []},
    }
    _add_binlex_entries(table, binlex_info)
    assert len(table.rows) > 0


def test_add_binbloom_stats_zero_analyzed():
    table = _make_table()
    binbloom_info = {
        "total_functions": 0,
        "analyzed_functions": 0,
        "capacity": 500,
        "error_rate": 0.05,
        "unique_signatures": 0,
    }
    _add_binbloom_stats(table, binbloom_info)
    assert len(table.rows) >= 5


def test_add_binbloom_similar_groups_more_than_three(monkeypatch):
    from r2inspect.cli import display_sections_similarity
    console = _make_console()
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    table = _make_table()
    binbloom_info = {
        "similar_functions": [
            {"count": 5, "signature": "s1", "functions": ["f1"]},
            {"count": 4, "signature": "s2", "functions": ["f2"]},
            {"count": 3, "signature": "s3", "functions": ["f3"]},
            {"count": 2, "signature": "s4", "functions": ["f4"]},
            {"count": 1, "signature": "s5", "functions": ["f5"]},
        ]
    }
    _add_binbloom_similar_groups(table, binbloom_info)
    assert len(table.rows) > 1


def test_add_binbloom_group_long_signature_truncated():
    table = _make_table()
    group = {"count": 2, "signature": "z" * 40, "functions": []}
    _add_binbloom_group(table, 1, group)
    assert len(table.rows) == 2


def test_add_binbloom_group_functions_more_than_five():
    table = _make_table()
    group = {
        "count": 10,
        "signature": "sig",
        "functions": [f"func_{i}" for i in range(8)],
    }
    _add_binbloom_group(table, 1, group)
    assert len(table.rows) == 3


def test_add_binbloom_group_long_function_names_truncated():
    table = _make_table()
    group = {
        "count": 1,
        "signature": "sig",
        "functions": ["very_long_name_" * 10],
    }
    _add_binbloom_group(table, 1, group)
    assert len(table.rows) == 3


def test_display_binbloom_available_with_similar_groups(monkeypatch):
    from r2inspect.cli import display_sections_similarity
    console = _make_console()
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    results = {
        "binbloom": {
            "available": True,
            "total_functions": 50,
            "analyzed_functions": 48,
            "capacity": 500,
            "error_rate": 0.01,
            "unique_signatures": 5,
            "similar_functions": [
                {"count": 3, "signature": "sig1", "functions": ["a", "b", "c"]},
            ],
            "binary_signature": "bsig",
            "bloom_stats": {"average_fill_rate": 0.6, "total_filters": 3},
            "function_signatures": {
                "fa": {"instruction_count": 5, "unique_instructions": 4},
            },
        }
    }
    _display_binbloom(results)
    text = _get_text(console)
    assert "Binbloom" in text
    assert "50" in text


def test_display_binbloom_signature_details_many_funcs_per_sig(monkeypatch):
    from r2inspect.cli import display_sections_similarity
    console = _make_console()
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    func_sigs = {f"func{i}": {"signature": "shared_hash"} for i in range(6)}
    binbloom_info = {
        "available": True,
        "unique_signatures": 2,
        "function_signatures": func_sigs,
    }
    _display_binbloom_signature_details(binbloom_info)
    text = _get_text(console)
    assert "Signature Details" in text


def test_display_binbloom_signature_details_long_hash(monkeypatch):
    from r2inspect.cli import display_sections_similarity
    console = _make_console()
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    binbloom_info = {
        "available": True,
        "unique_signatures": 2,
        "function_signatures": {
            "fa": {"signature": "h" * 70},
            "fb": {"signature": "x" * 20},
        },
    }
    _display_binbloom_signature_details(binbloom_info)
    text = _get_text(console)
    assert "Signature Details" in text


def test_display_simhash_available_with_hashes(monkeypatch):
    from r2inspect.cli import display_sections_similarity
    console = _make_console()
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    results = {
        "simhash": {
            "available": True,
            "feature_stats": {
                "total_features": 200,
                "total_strings": 100,
                "total_opcodes": 100,
                "feature_diversity": 0.9,
                "most_common_features": [("STR:hello", 30), ("OP:mov", 20)],
            },
            "combined_simhash": {"hex": "ab" * 32, "feature_count": 200},
            "strings_simhash": {"hex": "cd" * 16},
            "opcodes_simhash": {"hex": "ef" * 16},
            "function_simhashes": {"func1": "h1"},
            "total_functions": 10,
            "analyzed_functions": 10,
            "similarity_groups": [
                {
                    "count": 3,
                    "representative_hash": "rh1",
                    "functions": ["f1", "f2", "f3"],
                }
            ],
        }
    }
    _display_simhash(results)
    text = _get_text(console)
    assert "SimHash" in text


def test_display_bindiff_not_ready_no_error(monkeypatch):
    from r2inspect.cli import display_sections_similarity
    console = _make_console()
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    results = {"bindiff": {"comparison_ready": False}}
    _display_bindiff(results)
    text = _get_text(console)
    assert "Not Available" in text


def test_display_machoc_functions_duplicate_hashes(monkeypatch):
    from r2inspect.cli import display_sections_similarity
    console = _make_console()
    monkeypatch.setattr(display_sections_similarity, "_get_console", lambda: console)
    results = {
        "functions": {
            "total_functions": 10,
            "machoc_hashes": {
                "f1": "h1",
                "f2": "h1",
                "f3": "h1",
                "f4": "h2",
            },
        }
    }
    _display_machoc_functions(results)
    text = _get_text(console)
    assert "Function Analysis" in text
    assert "2" in text


# --- display_sections_helpers: additional branch coverage ---

def test_add_simhash_feature_stats_missing_keys():
    table = _make_table()
    _add_simhash_feature_stats(table, {})
    assert len(table.rows) == 4


def test_format_simhash_hex_exactly_32_chars():
    result = _format_simhash_hex("a" * 32)
    assert "\n" not in result
    assert result == "a" * 32


def test_format_simhash_hex_33_chars():
    result = _format_simhash_hex("b" * 33)
    assert "\n" in result


def test_add_simhash_hashes_strings_only():
    table = _make_table()
    simhash_info = {"strings_simhash": {"hex": "aa" * 20}}
    _add_simhash_hashes(table, simhash_info)
    assert len(table.rows) == 1


def test_add_simhash_hashes_opcodes_only():
    table = _make_table()
    simhash_info = {"opcodes_simhash": {"hex": "bb" * 20}}
    _add_simhash_hashes(table, simhash_info)
    assert len(table.rows) == 1


def test_add_simhash_function_analysis_with_similarity_groups():
    table = _make_table()
    simhash_info = {
        "function_simhashes": {"f1": "h1"},
        "total_functions": 5,
        "analyzed_functions": 5,
        "similarity_groups": [
            {"count": 2, "representative_hash": "rh", "functions": ["f1", "f2"]},
        ],
    }
    _add_simhash_function_analysis(table, simhash_info)
    assert len(table.rows) >= 3


def test_add_simhash_function_analysis_no_groups():
    table = _make_table()
    simhash_info = {
        "function_simhashes": {"f1": "h1"},
        "total_functions": 5,
        "analyzed_functions": 5,
        "similarity_groups": [],
    }
    _add_simhash_function_analysis(table, simhash_info)
    assert len(table.rows) == 3


def test_add_simhash_similarity_groups_overflow():
    table = _make_table()
    groups = [
        {"count": i, "representative_hash": f"rh{i}", "functions": [f"f{i}"]}
        for i in range(5)
    ]
    _add_simhash_similarity_groups(table, groups)
    assert len(table.rows) >= 1


def test_add_simhash_similarity_group_no_functions():
    table = _make_table()
    group = {"count": 3, "representative_hash": "rh", "functions": []}
    _add_simhash_similarity_group(table, 1, group)
    assert len(table.rows) == 2


def test_add_simhash_similarity_group_exactly_five_functions():
    table = _make_table()
    group = {
        "count": 5,
        "representative_hash": "rh",
        "functions": [f"func{i}" for i in range(5)],
    }
    _add_simhash_similarity_group(table, 1, group)
    assert len(table.rows) == 3


def test_add_simhash_top_features_strips_prefixes():
    table = _make_table()
    feature_stats = {
        "most_common_features": [
            ("STR:hello_world", 10),
            ("OP:push", 8),
            ("OPTYPE:jump", 5),
        ]
    }
    _add_simhash_top_features(table, feature_stats)
    assert len(table.rows) == 1


def test_add_bindiff_structural_seven_sections_exactly():
    table = _make_table()
    structural = {
        "file_type": "ELF",
        "file_size": 50000,
        "section_count": 7,
        "section_names": [f".s{i}" for i in range(7)],
        "import_count": 5,
        "export_count": 2,
    }
    _add_bindiff_structural(table, structural)
    assert len(table.rows) == 6


def test_add_bindiff_functions_with_cfg():
    table = _make_table()
    function_features = {
        "function_count": 30,
        "cfg_features": {"f1": {}, "f2": {}},
    }
    _add_bindiff_functions(table, function_features)
    assert len(table.rows) == 2


def test_add_bindiff_strings_with_many_categories():
    table = _make_table()
    string_features = {
        "total_strings": 300,
        "categorized_strings": {
            "ascii": 200,
            "unicode": 80,
            "url": 15,
            "path": 5,
        },
    }
    _add_bindiff_strings(table, string_features)
    assert len(table.rows) == 2


def test_add_bindiff_signatures_mixed():
    table = _make_table()
    signatures = {"md5": "abc", "sha1": None, "imphash": ""}
    _add_bindiff_signatures(table, signatures)
    assert len(table.rows) == 1


def test_add_bindiff_entries_no_optional_sections():
    table = _make_table()
    _add_bindiff_entries(table, {"filename": "sample.exe"})
    assert len(table.rows) == 1
