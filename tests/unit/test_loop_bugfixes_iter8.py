"""Regression test for loop iteration 8.

bindiff similarity functions incremented ``total_weight`` unconditionally for
their Jaccard feature categories while only adding to ``score`` when at least
one side had data. When a category was absent on BOTH binaries, its weight
stayed in the denominator, dragging the similarity below its true value (two
otherwise-identical inputs with no sections/imports scored 0.4 instead of 1.0).
The weight is now added only when the category contributes.
"""

from __future__ import annotations

from r2inspect.domain.formats.bindiff_compare import (
    compare_function_features,
    compare_string_features,
    compare_structural_features,
)


def test_structural_similarity_ignores_absent_categories() -> None:
    a = {"file_type": "PE", "architecture": "x86"}
    b = {"file_type": "PE", "architecture": "x86"}
    # file_type + architecture match; sections/imports absent on both sides.
    assert compare_structural_features(a, b) == 1.0


def test_structural_similarity_counts_present_category() -> None:
    a = {"file_type": "PE", "architecture": "x86", "section_names": [".text"]}
    b = {"file_type": "PE", "architecture": "x86", "section_names": [".data"]}
    # Disjoint sections (jaccard 0) must still pull the score down.
    assert compare_structural_features(a, b) < 1.0


def test_string_similarity_ignores_absent_categories() -> None:
    a = {"string_signature": "sigA", "api_strings": ["CreateFileA"]}
    b = {"string_signature": "sigB", "api_strings": ["CreateFileA"]}
    # Signatures differ; identical APIs; path/registry strings absent on both.
    assert compare_string_features(a, b) == 1.0


def test_function_similarity_ignores_absent_names() -> None:
    a = {"function_count": 10}
    b = {"function_count": 10}
    # Equal counts; function_names absent on both → not penalised.
    assert compare_function_features(a, b) == 1.0
