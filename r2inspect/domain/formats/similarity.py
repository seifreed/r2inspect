#!/usr/bin/env python3
"""Similarity scoring helpers."""

from __future__ import annotations


def jaccard_similarity(left: set, right: set) -> float:
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    union = left | right
    if not union:  # pragma: no cover
        return 0.0
    return len(left & right) / len(union)


def normalized_difference_similarity(a_val: int, b_val: int) -> float:
    if a_val <= 0 or b_val <= 0:
        return 0.0
    return 1.0 - abs(a_val - b_val) / max(a_val, b_val)
