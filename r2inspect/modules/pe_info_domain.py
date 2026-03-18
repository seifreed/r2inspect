"""DEPRECATED: Import from r2inspect.domain.formats.pe_info instead."""

from ..domain.formats.pe_info import (
    PE32_PLUS,
    determine_pe_file_type,
    determine_pe_format,
    normalize_pe_format,
    compute_entry_point,
    apply_optional_header_info,
    characteristics_from_header,
    normalize_resource_entries,
    parse_version_info_text,
    characteristics_from_bin,
    build_subsystem_info,
)

__all__ = [
    "PE32_PLUS",
    "determine_pe_file_type",
    "determine_pe_format",
    "normalize_pe_format",
    "compute_entry_point",
    "apply_optional_header_info",
    "characteristics_from_header",
    "normalize_resource_entries",
    "parse_version_info_text",
    "characteristics_from_bin",
    "build_subsystem_info",
]
