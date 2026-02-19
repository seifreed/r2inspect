from __future__ import annotations

import pytest

from r2inspect.modules.simhash_detailed import run_detailed_simhash_analysis
from r2inspect.modules.similarity_scoring import (
    jaccard_similarity,
    normalized_difference_similarity,
)


# ----- similarity_scoring tests -----

def test_jaccard_similarity_both_empty_returns_one() -> None:
    assert jaccard_similarity(set(), set()) == 1.0


def test_jaccard_similarity_left_empty_returns_zero() -> None:
    assert jaccard_similarity(set(), {"a", "b"}) == 0.0


def test_jaccard_similarity_right_empty_returns_zero() -> None:
    assert jaccard_similarity({"a"}, set()) == 0.0


def test_jaccard_similarity_identical_sets() -> None:
    s = {"a", "b", "c"}
    assert jaccard_similarity(s, s) == 1.0


def test_jaccard_similarity_disjoint_sets() -> None:
    assert jaccard_similarity({"a", "b"}, {"c", "d"}) == 0.0


def test_jaccard_similarity_partial_overlap() -> None:
    left = {"a", "b", "c"}
    right = {"b", "c", "d"}
    result = jaccard_similarity(left, right)
    assert 0.0 < result < 1.0
    assert abs(result - 2 / 4) < 1e-9


def test_normalized_difference_similarity_both_zero_returns_zero() -> None:
    assert normalized_difference_similarity(0, 0) == 0.0


def test_normalized_difference_similarity_one_zero_returns_zero() -> None:
    assert normalized_difference_similarity(0, 10) == 0.0
    assert normalized_difference_similarity(10, 0) == 0.0


def test_normalized_difference_similarity_equal_values() -> None:
    assert normalized_difference_similarity(100, 100) == 1.0


def test_normalized_difference_similarity_different_values() -> None:
    result = normalized_difference_similarity(100, 50)
    assert 0.0 < result < 1.0
    assert abs(result - 0.5) < 1e-9


def test_normalized_difference_similarity_negative_values_return_zero() -> None:
    assert normalized_difference_similarity(-5, 10) == 0.0


# ----- simhash_detailed tests -----

def _make_simhash_params(**overrides):
    defaults = dict(
        filepath="test.bin",
        simhash_available=False,
        no_features_error="No features",
        extract_string_features=lambda: [],
        extract_opcodes_features=lambda: [],
        extract_function_features=lambda: {},
        find_similar_functions=lambda _: [],
        log_debug=lambda _: None,
        log_error=lambda _: None,
    )
    defaults.update(overrides)
    return defaults


def test_simhash_unavailable_returns_unavailable_result() -> None:
    params = _make_simhash_params(simhash_available=False)
    result = run_detailed_simhash_analysis(**params)
    assert result.get("available") is False or "error" in result or not result.get("library_available", True)


def test_simhash_no_features_returns_error() -> None:
    try:
        from simhash import Simhash  # noqa: F401
    except ImportError:
        pytest.skip("simhash not installed")

    params = _make_simhash_params(
        simhash_available=True,
        no_features_error="No features found",
        extract_string_features=lambda: [],
        extract_opcodes_features=lambda: [],
    )
    result = run_detailed_simhash_analysis(**params)
    assert result.get("error") == "No features found"


def test_simhash_with_string_features_only() -> None:
    try:
        from simhash import Simhash  # noqa: F401
    except ImportError:
        pytest.skip("simhash not installed")

    params = _make_simhash_params(
        simhash_available=True,
        extract_string_features=lambda: ["hello", "world", "test"],
        extract_opcodes_features=lambda: [],
    )
    result = run_detailed_simhash_analysis(**params)
    assert result.get("strings_simhash") is not None
    assert result.get("opcodes_simhash") is None


def test_simhash_with_opcodes_features_only() -> None:
    try:
        from simhash import Simhash  # noqa: F401
    except ImportError:
        pytest.skip("simhash not installed")

    params = _make_simhash_params(
        simhash_available=True,
        extract_string_features=lambda: [],
        extract_opcodes_features=lambda: ["mov", "push", "call", "ret"],
    )
    result = run_detailed_simhash_analysis(**params)
    assert result.get("opcodes_simhash") is not None
    assert result.get("strings_simhash") is None


def test_simhash_with_both_features() -> None:
    try:
        from simhash import Simhash  # noqa: F401
    except ImportError:
        pytest.skip("simhash not installed")

    params = _make_simhash_params(
        simhash_available=True,
        extract_string_features=lambda: ["hello", "world"],
        extract_opcodes_features=lambda: ["mov", "push"],
    )
    result = run_detailed_simhash_analysis(**params)
    assert result.get("combined_simhash") is not None
    assert result.get("strings_simhash") is not None
    assert result.get("opcodes_simhash") is not None
    assert result["feature_stats"]["total_strings"] == 2
    assert result["feature_stats"]["total_opcodes"] == 2


def test_simhash_with_function_features() -> None:
    try:
        from simhash import Simhash  # noqa: F401
    except ImportError:
        pytest.skip("simhash not installed")

    func_features = {
        "main": {"simhash": 0xABCD, "name": "main"},
        "sub_1000": {"simhash": 0x1234, "name": "sub_1000"},
    }

    params = _make_simhash_params(
        simhash_available=True,
        extract_string_features=lambda: ["hello"],
        extract_opcodes_features=lambda: ["mov"],
        extract_function_features=lambda: func_features,
        find_similar_functions=lambda _ffs: [{"group": ["main", "sub_1000"]}],
    )
    result = run_detailed_simhash_analysis(**params)
    assert result.get("function_simhashes") is not None
    assert len(result["similarity_groups"]) == 1


def test_simhash_feature_stats_includes_most_common() -> None:
    try:
        from simhash import Simhash  # noqa: F401
    except ImportError:
        pytest.skip("simhash not installed")

    params = _make_simhash_params(
        simhash_available=True,
        extract_string_features=lambda: ["a", "a", "b"],
        extract_opcodes_features=lambda: ["mov", "mov"],
    )
    result = run_detailed_simhash_analysis(**params)
    assert "most_common_features" in result["feature_stats"]
    assert "feature_diversity" in result["feature_stats"]
