"""Domain hashing utilities.

This module contains pure hashing/comparison logic with no infrastructure dependencies.
"""

from .simhash_compare import compare_hashes

__all__ = ["compare_hashes"]
