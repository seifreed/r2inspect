#!/usr/bin/env python3
"""Compiler signature facade."""

from .compiler_signature_constants import (
    DLL_ADVAPI32,
    DLL_SHELL32,
    SECTION_DATA,
    SECTION_EH_FRAME,
    SECTION_RDATA,
    SECTION_TEXT,
)
from .compiler_signatures_core import CORE_COMPILER_SIGNATURES
from .compiler_signatures_extended import EXTENDED_COMPILER_SIGNATURES


COMPILER_SIGNATURES = {
    **CORE_COMPILER_SIGNATURES,
    **EXTENDED_COMPILER_SIGNATURES,
}


__all__ = [
    "COMPILER_SIGNATURES",
    "DLL_ADVAPI32",
    "DLL_SHELL32",
    "SECTION_DATA",
    "SECTION_EH_FRAME",
    "SECTION_RDATA",
    "SECTION_TEXT",
]
