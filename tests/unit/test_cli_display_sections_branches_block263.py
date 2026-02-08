from __future__ import annotations

from rich.table import Table

from r2inspect.cli import display_sections as ds


def test_display_sections_early_returns(capsys) -> None:
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
    ds._display_circuit_breaker_statistics({"opened": 0})
    ds._display_indicators({"indicators": []})

    out = capsys.readouterr().out
    assert out == ""


def test_display_sections_helpers_variants(capsys) -> None:
    ds._add_binlex_unique_signatures(Table(), [2, 3], {2: 1})
    ds._add_binlex_similarity_groups(Table(), [2, 3], {2: [{"count": 2}], 3: []})
    ds._add_binlex_binary_signatures(Table(), [2], {2: "hash"})
    ds._add_binlex_top_ngrams(Table(), [2], {2: [("aa", 1), ("bb", 2), ("cc", 3)]})

    ds._add_simhash_similarity_groups(
        Table(),
        [
            {"count": 2, "representative_hash": "h" * 32, "functions": ["a", "b"]},
            {"count": 1, "representative_hash": "h" * 8, "functions": []},
            {"count": 1, "representative_hash": "h" * 8, "functions": []},
            {"count": 1, "representative_hash": "h" * 8, "functions": []},
        ],
    )

    ds._add_binbloom_group(Table(), 1, {"count": 0, "signature": "sig", "functions": []})
    ds._add_binbloom_group(
        Table(), 2, {"count": 3, "signature": "sig2", "functions": ["a", "b", "c", "d", "e", "f"]}
    )

    ds._display_binbloom_signature_details(
        {"available": True, "unique_signatures": 2, "function_signatures": {}}
    )
    ds._display_binbloom_signature_details(
        {
            "available": True,
            "unique_signatures": 2,
            "function_signatures": {
                "f1": {"signature": "aa"},
                "f2": {"signature": "aa"},
                "f3": {"signature": "bb"},
            },
        }
    )

    ds._display_binbloom(
        {
            "binbloom": {
                "available": True,
                "total_functions": 0,
                "analyzed_functions": 0,
                "capacity": 0,
                "error_rate": 0.0,
                "unique_signatures": 0,
                "function_signatures": {},
                "similar_functions": [],
                "binary_signature": None,
                "bloom_stats": {},
            }
        }
    )

    ds._display_simhash(
        {
            "simhash": {
                "available": True,
                "feature_stats": {},
                "function_simhashes": {},
            }
        }
    )

    ds._display_bindiff({"bindiff": {"comparison_ready": False, "error": "nope"}})

    out = capsys.readouterr().out
    assert out
