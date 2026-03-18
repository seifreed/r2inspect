"""DEPRECATED: Import from r2inspect.domain.formats.elf instead."""

from ..domain.formats.elf import (
    parse_comment_compiler_info,
    parse_dwarf_info,
    parse_dwarf_producer,
    parse_dwarf_compile_time,
    parse_build_id_data,
    find_section_by_name,
    build_section_read_commands,
)

__all__ = [
    "parse_comment_compiler_info",
    "parse_dwarf_info",
    "parse_dwarf_producer",
    "parse_dwarf_compile_time",
    "parse_build_id_data",
    "find_section_by_name",
    "build_section_read_commands",
]
