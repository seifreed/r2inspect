"""DEPRECATED: Import from r2inspect.domain.formats.string instead."""

from ..domain.formats.string import (
    SUSPICIOUS_PATTERNS,
    filter_strings,
    parse_search_results,
    xor_string,
    build_xor_matches,
    find_suspicious,
    decode_base64,
    decode_hex,
    is_base64,
    is_hex,
)

__all__ = [
    "SUSPICIOUS_PATTERNS",
    "filter_strings",
    "parse_search_results",
    "xor_string",
    "build_xor_matches",
    "find_suspicious",
    "decode_base64",
    "decode_hex",
    "is_base64",
    "is_hex",
]
