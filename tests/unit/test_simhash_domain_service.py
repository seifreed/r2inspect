from __future__ import annotations

from r2inspect.domain.services.simhash import (
    build_feature_stats,
    build_similarity_groups,
    classify_opcode_type,
    get_length_category,
    interpret_similarity_distance,
)


def test_build_feature_stats() -> None:
    stats = build_feature_stats(["STR:a", "STR:b"], ["OP:mov", "OP:mov"])

    assert stats["total_strings"] == 2
    assert stats["total_opcodes"] == 2
    assert stats["total_features"] == 4
    assert "most_common_features" in stats


def test_build_feature_stats_skips_malformed_entries() -> None:
    stats = build_feature_stats(["STR:a", 1, None], ["OP:mov", object(), "OP:mov"])  # type: ignore[list-item]

    assert stats["total_strings"] == 1
    assert stats["total_opcodes"] == 2
    assert stats["total_features"] == 3
    assert stats["unique_strings"] == 1
    assert stats["unique_opcodes"] == 1


def test_build_similarity_groups() -> None:
    function_features = {
        "a": {"simhash": 10},
        "b": {"simhash": 12},
        "c": {"simhash": 100},
    }

    groups = build_similarity_groups(
        function_features,
        max_distance=5,
        distance_fn=lambda left, right: abs(left - right),
    )

    assert len(groups) == 1
    assert groups[0]["count"] == 2
    assert "a" in groups[0]["functions"]
    assert "b" in groups[0]["functions"]


def test_build_similarity_groups_skips_malformed_hashes() -> None:
    function_features = {
        "a": {"simhash": 10},
        "b": {"simhash": 12},
        "missing": {},
        "bad": {"simhash": "10"},
    }

    groups = build_similarity_groups(
        function_features,
        max_distance=5,
        distance_fn=lambda left, right: abs(left - right),
    )

    assert len(groups) == 1
    assert groups[0]["functions"] == ["a", "b"]


def test_build_similarity_groups_skips_non_dict_input() -> None:
    groups = build_similarity_groups(
        None,  # type: ignore[arg-type]
        max_distance=5,
        distance_fn=lambda left, right: abs(left - right),
    )

    assert groups == []


def test_interpret_similarity_distance() -> None:
    assert interpret_similarity_distance(0) == "identical"
    assert interpret_similarity_distance(3) == "very_similar"
    assert interpret_similarity_distance(10) == "similar"
    assert interpret_similarity_distance(20) == "somewhat_similar"
    assert interpret_similarity_distance(40) == "different"


def test_classify_opcode_type_and_length_category_skip_malformed_inputs() -> None:
    assert classify_opcode_type(None) == "other"
    assert classify_opcode_type(123) == "other"
    assert get_length_category("12") == "medium"
    assert get_length_category("bad") == "short"
