#!/usr/bin/env python3
"""Analyzer category definitions."""

from enum import Enum


class AnalyzerCategory(Enum):
    """
    Categorization of analyzer types.

    This enumeration provides semantic grouping of analyzers based on their
    primary function within the analysis pipeline. Categories enable filtered
    queries and selective execution of analyzer subsets.

    Categories:
        FORMAT: File format-specific analyzers (PE, ELF, Mach-O)
        HASHING: Hash computation and fuzzy matching (SSDeep, TLSH, Impfuzzy)
        DETECTION: Pattern matching and signature detection (Packer, Crypto, Anti-Analysis)
        METADATA: Structural metadata extraction (Sections, Imports, Exports, Compiler)
        SECURITY: Security feature analysis (Mitigations, Authenticode, Signatures)
        SIMILARITY: Code similarity and diffing (BinDiff, SimHash, Binbloom)
        BEHAVIORAL: Behavioral analysis (YARA, String analysis, Function analysis)
    """

    FORMAT = "format"
    HASHING = "hashing"
    DETECTION = "detection"
    METADATA = "metadata"
    SECURITY = "security"
    SIMILARITY = "similarity"
    BEHAVIORAL = "behavioral"
