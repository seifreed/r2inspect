from __future__ import annotations

from r2inspect.domain.services.binbloom import (
    accumulate_bloom_bits,
    build_binbloom_result,
    build_signature_components,
    build_similar_function_groups,
    calculate_bloom_similarity,
    calculate_bloom_stats,
    count_unique_signatures,
    create_instruction_signature,
)


class _FakeBloom:
    def __init__(self, bits: list[int]) -> None:
        self.bit_array = bits


def test_build_binbloom_result_defaults() -> None:
    result = build_binbloom_result("binbloom", capacity=256, error_rate=0.001)

    assert result["analyzer"] == "binbloom"
    assert result["capacity"] == 256
    assert result["error_rate"] == 0.001
    assert result["available"] is False


def test_create_instruction_signature_is_deterministic() -> None:
    instructions = ["mov", "push", "call", "ret"]

    assert create_instruction_signature(instructions) == create_instruction_signature(instructions)


def test_build_signature_components_contains_expected_sections() -> None:
    components = build_signature_components(["mov", "push", "mov"])

    assert components[0].startswith("UNIQ:")
    assert components[1].startswith("FREQ:")
    assert components[2].startswith("BIGR:")


def test_count_unique_signatures() -> None:
    function_signatures = {
        "f1": {"signature": "a"},
        "f2": {"signature": "a"},
        "f3": {"signature": "b"},
    }

    assert count_unique_signatures(function_signatures) == 2


def test_build_similar_function_groups_only_returns_duplicates() -> None:
    function_signatures = {
        "func_a": {"signature": "same"},
        "func_b": {"signature": "same"},
        "func_c": {"signature": "other"},
    }

    groups = build_similar_function_groups(function_signatures)

    assert len(groups) == 1
    assert groups[0]["count"] == 2
    assert "func_a" in groups[0]["functions"]


def test_accumulate_bloom_bits_and_stats() -> None:
    blooms = {
        "f1": _FakeBloom([1, 0, 1]),
        "f2": _FakeBloom([1, 1, 0, 0]),
    }

    bits_set, total_capacity = accumulate_bloom_bits(blooms)
    stats = calculate_bloom_stats(blooms, capacity=256, error_rate=0.001)

    assert bits_set == 4
    assert total_capacity == 7
    assert stats["total_filters"] == 2
    assert stats["average_fill_rate"] == 4 / 7


def test_calculate_bloom_similarity() -> None:
    bloom1 = _FakeBloom([1, 0, 1, 0])
    bloom2 = _FakeBloom([1, 1, 1, 0])

    similarity = calculate_bloom_similarity(bloom1, bloom2)

    assert similarity == 2 / 3
