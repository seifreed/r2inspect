"""Similarity and analysis-related display sections."""

from __future__ import annotations

from .display_sections_similarity_binbloom import (
    _add_binbloom_binary_signature,
    _add_binbloom_bloom_stats,
    _add_binbloom_group,
    _add_binbloom_similar_groups,
    _add_binbloom_stats,
    _display_binbloom,
    _display_binbloom_signature_details,
)
from .display_sections_bindiff_support import _add_bindiff_entries
from .display_sections_simhash_support import (
    _add_simhash_feature_stats,
    _add_simhash_function_analysis,
    _add_simhash_hashes,
    _add_simhash_similarity_group,
    _add_simhash_similarity_groups,
    _add_simhash_top_features,
    _format_simhash_hex,
)
from .display_sections_similarity_misc import (
    _display_bindiff,
    _display_machoc_functions,
    _display_simhash,
)
from .display_sections_similarity_binlex import (
    _add_binlex_basic_stats,
    _add_binlex_binary_signatures,
    _add_binlex_entries,
    _add_binlex_similarity_groups,
    _add_binlex_top_ngrams,
    _add_binlex_unique_signatures,
    _display_binlex,
)
