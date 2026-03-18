#!/usr/bin/env python3
"""Facade for similarity display support helpers."""

from .display_sections_bindiff_support import (
    _add_bindiff_entries,
    _add_bindiff_functions,
    _add_bindiff_signatures,
    _add_bindiff_strings,
    _add_bindiff_structural,
)
from .display_sections_simhash_support import (
    _add_simhash_feature_stats,
    _add_simhash_function_analysis,
    _add_simhash_hashes,
    _add_simhash_similarity_group,
    _add_simhash_similarity_groups,
    _add_simhash_top_features,
    _format_simhash_hex,
)

__all__ = [
    "_add_simhash_feature_stats",
    "_format_simhash_hex",
    "_add_simhash_hashes",
    "_add_simhash_function_analysis",
    "_add_simhash_similarity_groups",
    "_add_simhash_similarity_group",
    "_add_simhash_top_features",
    "_add_bindiff_entries",
    "_add_bindiff_structural",
    "_add_bindiff_functions",
    "_add_bindiff_strings",
    "_add_bindiff_signatures",
]
