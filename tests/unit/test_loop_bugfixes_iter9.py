"""Regression tests for loop iteration 9.

Two Mach-O correctness bugs:

1. ``_analyze_macho_details`` had its little/big endianness maps swapped (and read
   cputype with the wrong byte order), so a little-endian x86-64 Mach-O — by far
   the common case — was reported as big-endian, and big-endian files as little.
2. The registry's ``MACHO_FORMATS`` set held ``"MACH0"`` (the digit zero) instead
   of ``"MACHO"``, so ``get_analyzers_for_format`` never matched the Mach-O
   analyzer for the runtime format strings ``"MACHO"`` / ``"Mach-O"``.
"""

from __future__ import annotations

import struct

from r2inspect.infrastructure.magic_detector import MagicByteDetector
from r2inspect.registry.default_registry import create_default_registry


def test_macho_little_endian_64bit_is_labelled_little():
    detector = MagicByteDetector()
    # On-disk bytes of a little-endian 64-bit Mach-O: CF FA ED FE, cputype x86_64.
    header = b"\xcf\xfa\xed\xfe" + struct.pack("<I", 0x01000007)
    details = detector._analyze_macho_details(header)
    assert details["bits"] == 64
    assert details["endianness"] == "Little"
    assert details["architecture"] == "x86-64"


def test_macho_big_endian_32bit_is_labelled_big():
    detector = MagicByteDetector()
    # On-disk bytes of a big-endian 32-bit Mach-O: FE ED FA CE, cputype PowerPC.
    header = b"\xfe\xed\xfa\xce" + struct.pack(">I", 18)
    details = detector._analyze_macho_details(header)
    assert details["bits"] == 32
    assert details["endianness"] == "Big"
    assert details["architecture"] == "PowerPC"


def test_macho_universal_binary_is_big_endian():
    detector = MagicByteDetector()
    # Standard fat/universal binary on disk: CA FE BA BE (fat header is big-endian).
    header = b"\xca\xfe\xba\xbe" + struct.pack(">I", 2)
    details = detector._analyze_macho_details(header)
    assert details["bits"] == "Universal"
    assert details["endianness"] == "Big"


def test_registry_resolves_macho_analyzer_for_runtime_formats():
    registry = create_default_registry()
    for fmt in ("MACHO", "Mach-O"):
        assert "macho_analyzer" in registry.get_analyzers_for_format(fmt)
