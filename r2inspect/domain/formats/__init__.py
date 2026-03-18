"""Domain format-specific analysis logic.

This module contains pure domain logic for binary format analysis (PE, ELF, Mach-O).
All files here use only stdlib imports to maintain clean architecture isolation.

Modules:
    anti_analysis: Anti-analysis detection constants and patterns
    bindiff: Binary diffing calculations
    bindiff_compare: Comparison functions for binary diffing
    bindiff_indicator: Indicator detection for binary diffing
    compiler: Compiler detection patterns
    crypto: Cryptographic detection patterns
    elf: ELF format domain logic
    elf_security: ELF security feature detection
    import_analysis: Import analysis domain logic
    macho: Mach-O format domain logic
    macho_security: Mach-O security feature detection
    pe_info: PE format domain logic
    string: String analysis domain logic
    similarity: Similarity scoring functions
    telfhash: Telfhash symbol filtering (pure domain)
"""

from .anti_analysis import (
    ANTI_DEBUG_APIS,
    ENVIRONMENT_CHECK_COMMANDS,
    INJECTION_APIS,
    SANDBOX_INDICATORS,
    SUSPICIOUS_API_CATEGORIES,
    TIMING_APIS,
    VM_ARTIFACTS,
)
from .bindiff import (
    calculate_cyclomatic_complexity,
    calculate_rolling_hash,
    categorize_similarity,
    compare_behavioral_features,
    compare_byte_features,
    compare_function_features,
    compare_rolling_hashes,
    compare_string_features,
    compare_structural_features,
    has_crypto_indicators,
    has_network_indicators,
    has_persistence_indicators,
    is_crypto_api,
    is_network_api,
    is_suspicious_api,
)
from .crypto import (
    CRYPTO_PATTERNS,
    NOISE_PATTERNS,
    consolidate_detections,
    detect_algorithms_from_strings,
)
from .similarity import jaccard_similarity, normalized_difference_similarity
from .string import (
    SUSPICIOUS_PATTERNS,
    filter_strings,
    parse_search_results,
    xor_string,
    build_xor_matches,
)
from .telfhash import (
    normalize_telfhash_value,
    parse_telfhash_result,
    should_skip_symbol,
    filter_symbols_for_telfhash,
    extract_symbol_names,
)

__all__ = [
    "ANTI_DEBUG_APIS",
    "ENVIRONMENT_CHECK_COMMANDS",
    "INJECTION_APIS",
    "SANDBOX_INDICATORS",
    "SUSPICIOUS_API_CATEGORIES",
    "TIMING_APIS",
    "VM_ARTIFACTS",
    "calculate_cyclomatic_complexity",
    "calculate_rolling_hash",
    "categorize_similarity",
    "compare_behavioral_features",
    "compare_byte_features",
    "compare_function_features",
    "compare_rolling_hashes",
    "compare_string_features",
    "compare_structural_features",
    "has_crypto_indicators",
    "has_network_indicators",
    "has_persistence_indicators",
    "is_crypto_api",
    "is_network_api",
    "is_suspicious_api",
    "CRYPTO_PATTERNS",
    "NOISE_PATTERNS",
    "consolidate_detections",
    "detect_algorithms_from_strings",
    "jaccard_similarity",
    "normalized_difference_similarity",
    "SUSPICIOUS_PATTERNS",
    "filter_strings",
    "parse_search_results",
    "xor_string",
    "build_xor_matches",
    "normalize_telfhash_value",
    "parse_telfhash_result",
    "should_skip_symbol",
    "filter_symbols_for_telfhash",
    "extract_symbol_names",
]
