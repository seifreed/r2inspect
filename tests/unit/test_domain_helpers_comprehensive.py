#!/usr/bin/env python3
"""Comprehensive tests for domain_helpers.py module."""

import math
from r2inspect.modules.domain_helpers import (
    shannon_entropy,
    entropy_from_ints,
    clamp_score,
    count_suspicious_imports,
    normalize_section_name,
    suspicious_section_name_indicator,
    STANDARD_PE_SECTIONS,
)


def test_shannon_entropy_empty():
    """Test Shannon entropy with empty data."""
    result = shannon_entropy(b"")
    assert result == 0.0


def test_shannon_entropy_single_byte():
    """Test Shannon entropy with single byte."""
    result = shannon_entropy(b"\x00")
    assert result == 0.0


def test_shannon_entropy_uniform():
    """Test Shannon entropy with uniform distribution."""
    data = bytes(range(256))
    result = shannon_entropy(data)
    assert result == 8.0


def test_shannon_entropy_all_same():
    """Test Shannon entropy with all same bytes."""
    data = b"\x00" * 100
    result = shannon_entropy(data)
    assert result == 0.0


def test_shannon_entropy_two_values():
    """Test Shannon entropy with two different values."""
    data = b"\x00\xFF" * 50
    result = shannon_entropy(data)
    assert result == 1.0


def test_shannon_entropy_random_like():
    """Test Shannon entropy with pseudo-random data."""
    data = bytes([i % 256 for i in range(1000)])
    result = shannon_entropy(data)
    assert 0.0 < result <= 8.0


def test_shannon_entropy_text():
    """Test Shannon entropy with text data."""
    data = b"hello world"
    result = shannon_entropy(data)
    assert 0.0 < result <= 8.0


def test_shannon_entropy_large_data():
    """Test Shannon entropy with large data."""
    data = b"A" * 10000 + b"B" * 10000
    result = shannon_entropy(data)
    assert result == 1.0


def test_entropy_from_ints_empty():
    """Test entropy from ints with empty list."""
    result = entropy_from_ints([])
    assert result == 0.0


def test_entropy_from_ints_single():
    """Test entropy from ints with single value."""
    result = entropy_from_ints([0])
    assert result == 0.0


def test_entropy_from_ints_uniform():
    """Test entropy from ints with uniform distribution."""
    data = list(range(256))
    result = entropy_from_ints(data)
    assert result == 8.0


def test_entropy_from_ints_all_same():
    """Test entropy from ints with all same values."""
    result = entropy_from_ints([42] * 100)
    assert result == 0.0


def test_entropy_from_ints_two_values():
    """Test entropy from ints with two values."""
    data = [0, 255] * 50
    result = entropy_from_ints(data)
    assert result == 1.0


def test_entropy_from_ints_converts_to_bytes():
    """Test entropy from ints properly converts to bytes."""
    data = [65, 66, 67, 68]
    result = entropy_from_ints(data)
    expected = shannon_entropy(b"ABCD")
    assert result == expected


def test_clamp_score_within_range():
    """Test clamping score within range."""
    assert clamp_score(50) == 50
    assert clamp_score(0) == 0
    assert clamp_score(100) == 100


def test_clamp_score_below_minimum():
    """Test clamping score below minimum."""
    assert clamp_score(-10) == 0
    assert clamp_score(-100) == 0
    assert clamp_score(-1) == 0


def test_clamp_score_above_maximum():
    """Test clamping score above maximum."""
    assert clamp_score(110) == 100
    assert clamp_score(200) == 100
    assert clamp_score(101) == 100


def test_clamp_score_custom_range():
    """Test clamping score with custom range."""
    assert clamp_score(50, 10, 90) == 50
    assert clamp_score(5, 10, 90) == 10
    assert clamp_score(95, 10, 90) == 90


def test_clamp_score_zero_minimum():
    """Test clamping with zero minimum."""
    assert clamp_score(-5, 0, 100) == 0
    assert clamp_score(50, 0, 100) == 50


def test_clamp_score_negative_range():
    """Test clamping with negative range."""
    assert clamp_score(0, -50, 50) == 0
    assert clamp_score(-60, -50, 50) == -50
    assert clamp_score(60, -50, 50) == 50


def test_count_suspicious_imports_empty():
    """Test counting suspicious imports with empty list."""
    result = count_suspicious_imports([], set())
    assert result == 0


def test_count_suspicious_imports_no_suspicious():
    """Test counting with no suspicious imports."""
    imports = [
        {"name": "printf"},
        {"name": "malloc"},
    ]
    suspicious = {"CreateProcess", "VirtualAlloc"}
    result = count_suspicious_imports(imports, suspicious)
    assert result == 0


def test_count_suspicious_imports_all_suspicious():
    """Test counting with all imports suspicious."""
    imports = [
        {"name": "CreateProcess"},
        {"name": "VirtualAlloc"},
    ]
    suspicious = {"CreateProcess", "VirtualAlloc"}
    result = count_suspicious_imports(imports, suspicious)
    assert result == 2


def test_count_suspicious_imports_mixed():
    """Test counting with mixed imports."""
    imports = [
        {"name": "CreateProcess"},
        {"name": "printf"},
        {"name": "VirtualAlloc"},
        {"name": "malloc"},
    ]
    suspicious = {"CreateProcess", "VirtualAlloc"}
    result = count_suspicious_imports(imports, suspicious)
    assert result == 2


def test_count_suspicious_imports_missing_name():
    """Test counting with missing name field."""
    imports = [
        {"name": "CreateProcess"},
        {"other": "field"},
        {"name": "VirtualAlloc"},
    ]
    suspicious = {"CreateProcess", "VirtualAlloc"}
    result = count_suspicious_imports(imports, suspicious)
    assert result == 2


def test_normalize_section_name_valid():
    """Test normalizing valid section name."""
    assert normalize_section_name(".text") == ".text"
    assert normalize_section_name(".DATA") == ".data"
    assert normalize_section_name(".RsRc") == ".rsrc"


def test_normalize_section_name_none():
    """Test normalizing None section name."""
    assert normalize_section_name(None) == ""


def test_normalize_section_name_empty():
    """Test normalizing empty section name."""
    assert normalize_section_name("") == ""


def test_normalize_section_name_whitespace():
    """Test normalizing section name with whitespace."""
    assert normalize_section_name("  .text  ") == "  .text  "


def test_normalize_section_name_special_chars():
    """Test normalizing section name with special characters."""
    assert normalize_section_name(".text$mn") == ".text$mn"
    assert normalize_section_name("CODE_SEG") == "code_seg"


def test_normalize_section_name_non_string():
    """Test normalizing non-string section name."""
    assert normalize_section_name(123) == ""
    assert normalize_section_name([]) == ""


def test_suspicious_section_name_indicator_not_suspicious():
    """Test section name that is not suspicious."""
    result = suspicious_section_name_indicator(".text", ["upx", "packed"])
    assert result is None


def test_suspicious_section_name_indicator_suspicious():
    """Test section name that is suspicious."""
    result = suspicious_section_name_indicator("UPX0", ["upx"])
    assert result is not None
    assert "upx" in result.lower()


def test_suspicious_section_name_indicator_case_insensitive():
    """Test suspicious section name is case insensitive."""
    result = suspicious_section_name_indicator("PACKED", ["packed"])
    assert result is not None


def test_suspicious_section_name_indicator_partial_match():
    """Test suspicious section name with partial match."""
    result = suspicious_section_name_indicator(".textupx", ["upx"])
    assert result is not None


def test_suspicious_section_name_indicator_multiple_suspicious():
    """Test with multiple suspicious patterns."""
    suspicious = ["upx", "packed", "aspack"]
    result = suspicious_section_name_indicator("upx1", suspicious)
    assert result is not None
    assert "upx" in result.lower()


def test_suspicious_section_name_indicator_empty_list():
    """Test with empty suspicious list."""
    result = suspicious_section_name_indicator(".text", [])
    assert result is None


def test_standard_pe_sections_constant():
    """Test STANDARD_PE_SECTIONS constant."""
    assert isinstance(STANDARD_PE_SECTIONS, list)
    assert ".text" in STANDARD_PE_SECTIONS
    assert ".data" in STANDARD_PE_SECTIONS
    assert ".rsrc" in STANDARD_PE_SECTIONS
    assert ".reloc" in STANDARD_PE_SECTIONS


def test_standard_pe_sections_completeness():
    """Test STANDARD_PE_SECTIONS has common sections."""
    expected = [".text", ".data", ".rdata", ".bss", ".idata", 
                ".edata", ".rsrc", ".reloc", ".debug", ".pdata", ".xdata"]
    for section in expected:
        assert section in STANDARD_PE_SECTIONS


def test_shannon_entropy_calculation_correctness():
    """Test Shannon entropy calculation is mathematically correct."""
    data = b"\x00\xFF"
    result = shannon_entropy(data)
    expected = -((0.5 * math.log2(0.5)) + (0.5 * math.log2(0.5)))
    assert abs(result - expected) < 0.0001


def test_shannon_entropy_half_half():
    """Test Shannon entropy with half-half distribution."""
    data = b"\x00" * 128 + b"\xFF" * 128
    result = shannon_entropy(data)
    assert abs(result - 1.0) < 0.0001


def test_clamp_score_boundary_values():
    """Test clamping at exact boundary values."""
    assert clamp_score(0, 0, 100) == 0
    assert clamp_score(100, 0, 100) == 100
    assert clamp_score(0, -10, 10) == 0
    assert clamp_score(-10, -10, 10) == -10
    assert clamp_score(10, -10, 10) == 10


def test_count_suspicious_imports_case_sensitive():
    """Test counting suspicious imports is case sensitive."""
    imports = [
        {"name": "CreateProcess"},
        {"name": "createprocess"},
    ]
    suspicious = {"CreateProcess"}
    result = count_suspicious_imports(imports, suspicious)
    assert result == 1


def test_entropy_from_ints_large_values():
    """Test entropy from ints with values within byte range."""
    data = [255, 254, 253]
    result = entropy_from_ints(data)
    expected = shannon_entropy(bytes([255, 254, 253]))
    assert result == expected


def test_suspicious_section_name_indicator_returns_string():
    """Test suspicious section name indicator returns proper string format."""
    result = suspicious_section_name_indicator("UPX0", ["upx"])
    assert isinstance(result, str)
    assert "Suspicious section name" in result
    assert "upx" in result


def test_normalize_section_name_preserves_case_in_string():
    """Test that normalize actually lowercases."""
    result = normalize_section_name("TEXT")
    assert result == "text"
    assert result.islower()


def test_shannon_entropy_non_zero_small_data():
    """Test Shannon entropy with small non-uniform data."""
    data = b"AAB"
    result = shannon_entropy(data)
    assert result > 0.0
    assert result < 8.0


def test_clamp_score_inverted_range():
    """Test clamping when min > max (edge case)."""
    result = clamp_score(50, 100, 0)
    assert result == 100


def test_count_suspicious_imports_empty_names():
    """Test counting with imports that have empty names."""
    imports = [
        {"name": ""},
        {"name": "CreateProcess"},
    ]
    suspicious = {"CreateProcess", ""}
    result = count_suspicious_imports(imports, suspicious)
    assert result == 2


def test_entropy_calculations_match():
    """Test that entropy_from_ints matches shannon_entropy."""
    int_data = [72, 101, 108, 108, 111]
    byte_data = b"Hello"
    result1 = entropy_from_ints(int_data)
    result2 = shannon_entropy(byte_data)
    assert result1 == result2


def test_suspicious_section_name_with_common_section():
    """Test that common sections are not flagged."""
    suspicious = ["upx", "packed"]
    result = suspicious_section_name_indicator(".text", suspicious)
    assert result is None
    result = suspicious_section_name_indicator(".data", suspicious)
    assert result is None


def test_shannon_entropy_maximum_value():
    """Test Shannon entropy maximum is 8.0."""
    data = bytes(range(256))
    result = shannon_entropy(data)
    assert result <= 8.0
    assert abs(result - 8.0) < 0.0001
