"""Unit coverage for the extracted simhash_detailed helpers.

These exercise the pure helpers with a hand-rolled Simhash double so the
coverage does not depend on importing the numpy-backed ``simhash`` library.
"""

from __future__ import annotations

from typing import Any

from r2inspect.modules.simhash_detailed import _add_function_simhashes, _simhash_entry


class _FakeSimhash:
    def __init__(self, features: list[str]) -> None:
        self.value = len(features) * 7


def test_simhash_entry_builds_hash_descriptor() -> None:
    entry = _simhash_entry(["a", "b", "c"], _FakeSimhash)

    assert entry == {
        "hash": 21,
        "hex": hex(21),
        "binary": bin(21),
        "feature_count": 3,
    }


def test_add_function_simhashes_populates_results() -> None:
    results: dict[str, Any] = {}
    function_features = {"f1": {"simhash": 1}, "f2": {"simhash": 0}, "f3": {}}

    _add_function_simhashes(results, function_features, lambda feats: [{"group": list(feats)}])

    assert results["function_simhashes"] == function_features
    assert results["total_functions"] == 3
    assert results["analyzed_functions"] == 1
    assert results["similarity_groups"] == [{"group": ["f1", "f2", "f3"]}]


def test_add_function_simhashes_noop_without_features() -> None:
    results: dict[str, Any] = {}

    _add_function_simhashes(results, {}, lambda _feats: [{"unexpected": True}])

    assert results == {}
