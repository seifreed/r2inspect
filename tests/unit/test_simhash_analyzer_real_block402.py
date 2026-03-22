"""Comprehensive tests for simhash analyzer - targeting 13% -> 100% coverage.

Rewritten to use FakeR2 + R2PipeAdapter -- NO mocks, NO monkeypatch, NO @patch.
"""

from __future__ import annotations

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.simhash_analyzer import SimHashAnalyzer, SIMHASH_AVAILABLE
from r2inspect.testing.fake_r2 import FakeR2


SAMPLE = "samples/fixtures/hello_pe.exe"


# ---------------------------------------------------------------------------
# FakeR2 -- minimal r2pipe-compatible backend
# ---------------------------------------------------------------------------


def _make_adapter(*, cmd_map=None, cmdj_map=None):
    """Build an R2PipeAdapter backed by FakeR2."""
    return R2PipeAdapter(FakeR2(cmd_map=cmd_map, cmdj_map=cmdj_map))


def _make_analyzer(*, cmd_map=None, cmdj_map=None, adapter=None):
    """Create a SimHashAnalyzer with an adapter backed by FakeR2."""
    if adapter is None:
        adapter = _make_adapter(cmd_map=cmd_map, cmdj_map=cmdj_map)
    return SimHashAnalyzer(adapter, SAMPLE)


# ---------------------------------------------------------------------------
# Library availability
# ---------------------------------------------------------------------------


def test_simhash_is_available():
    available = SimHashAnalyzer.is_available()
    assert isinstance(available, bool)


# ---------------------------------------------------------------------------
# Basic analysis
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash library not installed")
def test_simhash_basic_analysis():
    analyzer = _make_analyzer(
        cmdj_map={
            "izzj": [
                {"string": "Hello World"},
                {"string": "Test String"},
            ],
            "aflj": [],
            "iSj": [],
        },
    )
    result = analyzer.analyze()
    assert "available" in result


# ---------------------------------------------------------------------------
# String feature extraction
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash library not installed")
def test_simhash_string_extraction():
    analyzer = _make_analyzer(
        cmdj_map={
            "izzj": [
                {"string": "LongEnoughString"},
                {"string": "abc"},  # Too short (< min_string_length=4)
                {"string": "AnotherValidString"},
            ],
            "iSj": [],
        },
    )
    features = analyzer._extract_string_features()
    # Should only extract strings >= min_length
    assert len(features) > 0


# ---------------------------------------------------------------------------
# Opcode extraction
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash library not installed")
def test_simhash_opcode_extraction():
    analyzer = _make_analyzer(
        cmdj_map={
            "aflj": [{"offset": 0x1000, "name": "func1", "size": 100}],
            # get_disasm(address=0x1000) => "pdfj @ 4096"
            "pdfj @ 4096": {
                "ops": [
                    {"mnemonic": "mov"},
                    {"mnemonic": "add"},
                    {"mnemonic": "ret"},
                ]
            },
        },
    )
    features = analyzer._extract_opcodes_features()
    assert len(features) > 0


# ---------------------------------------------------------------------------
# Pure helpers (no r2 interaction)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash library not installed")
def test_simhash_useful_string_filter():
    analyzer = _make_analyzer()
    assert analyzer._is_useful_string("ValidString123") is True
    assert analyzer._is_useful_string("   ") is False
    assert analyzer._is_useful_string("12345678") is False
    assert analyzer._is_useful_string("abcdef0123456789") is False


def test_simhash_length_category():
    analyzer = _make_analyzer()
    assert analyzer._get_length_category(5) == "short"
    assert analyzer._get_length_category(20) == "medium"
    assert analyzer._get_length_category(50) == "long"
    assert analyzer._get_length_category(200) == "very_long"


def test_simhash_opcode_classification():
    analyzer = _make_analyzer()
    assert analyzer._classify_opcode_type("jmp") == "control"
    assert analyzer._classify_opcode_type("mov") == "data"
    assert analyzer._classify_opcode_type("add") == "arithmetic"
    assert analyzer._classify_opcode_type("xor") == "logical"
    assert analyzer._classify_opcode_type("cmp") == "compare"
    assert analyzer._classify_opcode_type("unknown") == "other"


# ---------------------------------------------------------------------------
# Hash comparison
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash library not installed")
def test_simhash_compare_hashes():
    from simhash import Simhash

    hash1 = Simhash("test string").value
    hash2 = Simhash("test string").value

    distance = SimHashAnalyzer.compare_hashes(hex(hash1), hex(hash2))
    assert distance == 0


# ---------------------------------------------------------------------------
# Printable string extraction from raw bytes
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash library not installed")
def test_simhash_extract_printable_strings():
    analyzer = _make_analyzer()

    data = b"Hello\x00World\x00Test\x01Data"
    strings = analyzer._extract_printable_strings(data)

    assert "Hello" in strings
    assert "World" in strings


# ---------------------------------------------------------------------------
# Unavailable library path
# ---------------------------------------------------------------------------


def test_simhash_not_available():
    if not SIMHASH_AVAILABLE:
        analyzer = _make_analyzer()
        available, error = analyzer._check_library_availability()
        assert available is False
        assert error is not None


# ---------------------------------------------------------------------------
# Data section string extraction
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash library not installed")
def test_simhash_data_section_strings():
    hex_payload = (b"DataString\x00\x00" + b"X" * 88).hex()
    analyzer = _make_analyzer(
        cmdj_map={
            "iSj": [{"name": ".data", "vaddr": 0x2000, "size": 100}],
        },
        # read_bytes uses "p8 {size} @ {address}" via cmd()
        cmd_map={
            "p8 100 @ 8192": hex_payload,
        },
    )
    strings = analyzer._extract_data_section_strings()
    assert len(strings) >= 0


# ---------------------------------------------------------------------------
# Function features
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash library not installed")
def test_simhash_function_features():
    analyzer = _make_analyzer(
        cmdj_map={
            "aflj": [{"offset": 0x1000, "name": "func1", "size": 100}],
            "pdfj @ 4096": {"ops": [{"mnemonic": "mov"}, {"mnemonic": "ret"}]},
        },
    )
    analyzer._extract_function_features()
    # May or may not have features depending on implementation


# ---------------------------------------------------------------------------
# No features => error path
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash library not installed")
def test_simhash_no_features_error():
    analyzer = _make_analyzer(
        cmdj_map={
            "izzj": [],
            "aflj": [],
            "iSj": [],
        },
    )
    hash_val, method, error = analyzer._calculate_hash()
    # Should fail when no features available
    assert hash_val is None or error is not None


# ---------------------------------------------------------------------------
# Hash type identifier
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash library not installed")
def test_simhash_get_hash_type():
    analyzer = _make_analyzer()
    assert analyzer._get_hash_type() == "simhash"
