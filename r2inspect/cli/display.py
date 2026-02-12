#!/usr/bin/env python3
"""
r2inspect CLI Display Module

Facade module for display helpers and section renderers.
"""

from .display_base import (
    ANALYZED_FUNCTIONS_LABEL,
    HTML_AMP,
    NOT_AVAILABLE,
    SIMILAR_GROUPS_LABEL,
    STATUS_AVAILABLE,
    STATUS_NOT_AVAILABLE,
    STATUS_NOT_AVAILABLE_SIMPLE,
    TOTAL_FUNCTIONS_LABEL,
    UNKNOWN_ERROR,
    console,
    create_info_table,
    display_error_statistics,
    display_performance_statistics,
    display_results,
    display_validation_errors,
    display_yara_rules_table,
    format_hash_display,
    handle_list_yara_option,
    print_banner,
)
from .display_sections import (
    _add_binbloom_group,
    _add_rich_header_entries,
    _display_binbloom,
    _display_binbloom_signature_details,
    _display_bindiff,
    _display_binlex,
    _display_ccbhash,
    _display_file_info,
    _display_impfuzzy,
    _display_indicators,
    _display_machoc_functions,
    _display_pe_info,
    _display_rich_header,
    _display_security,
    _display_simhash,
    _display_ssdeep,
    _display_telfhash,
    _display_tlsh,
    _format_simhash_hex,
)
from .display_statistics import (
    _display_circuit_breaker_statistics,
    _display_most_retried_commands,
    _display_retry_statistics,
)
