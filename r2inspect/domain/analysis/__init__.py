"""Domain analysis utilities.

This module contains pure domain analysis logic with no infrastructure dependencies.
"""

from .import_risk import (
    count_suspicious_indicators,
    get_function_description,
    get_risk_level,
    is_candidate_api_string,
    matches_known_api,
)
from .import_collection import (
    normalize_import_entries,
    safe_len,
)

__all__ = [
    "count_suspicious_indicators",
    "get_function_description",
    "get_risk_level",
    "is_candidate_api_string",
    "matches_known_api",
    "normalize_import_entries",
    "safe_len",
]
