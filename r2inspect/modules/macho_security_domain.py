"""DEPRECATED: Import from r2inspect.domain.formats.macho_security instead."""

from ..domain.formats.macho_security import (
    is_pie,
    has_stack_canary,
    has_arc,
    is_encrypted,
    is_signed,
)

__all__ = [
    "is_pie",
    "has_stack_canary",
    "has_arc",
    "is_encrypted",
    "is_signed",
]
