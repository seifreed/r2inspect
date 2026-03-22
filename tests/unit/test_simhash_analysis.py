"""Tests for SimHash analysis -- real code paths, no mocks."""

from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.simhash_analyzer import SIMHASH_AVAILABLE, SimHashAnalyzer
from r2inspect.testing.fake_r2 import FakeR2


SAMPLE = "samples/fixtures/hello_pe.exe"


# ---------------------------------------------------------------------------
# FakeR2 -- minimal r2pipe-compatible object
# ---------------------------------------------------------------------------


def _make_adapter(cmd_map=None, cmdj_map=None):
    """Build an R2PipeAdapter backed by FakeR2."""
    return R2PipeAdapter(FakeR2(cmd_map=cmd_map, cmdj_map=cmdj_map))


def _make_analyzer(adapter=None):
    """Create a SimHashAnalyzer with a default or given adapter."""
    if adapter is None:
        adapter = _make_adapter()
    return SimHashAnalyzer(adapter, SAMPLE)


# ---------------------------------------------------------------------------
# Library availability
# ---------------------------------------------------------------------------


def test_simhash_library_availability():
    result = SimHashAnalyzer.is_available()
    assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# Pure helper methods (no r2 interaction needed)
# ---------------------------------------------------------------------------


def test_simhash_is_useful_string():
    analyzer = _make_analyzer()
    assert analyzer._is_useful_string("Hello World") is True
    assert analyzer._is_useful_string("   ") is False
    assert analyzer._is_useful_string("12345") is False


def test_simhash_length_category():
    analyzer = _make_analyzer()
    assert analyzer._get_length_category(5) == "short"
    assert analyzer._get_length_category(15) == "medium"
    assert analyzer._get_length_category(50) == "long"
    assert analyzer._get_length_category(200) == "very_long"


def test_simhash_classify_opcode_control():
    analyzer = _make_analyzer()
    assert analyzer._classify_opcode_type("jmp") == "control"
    assert analyzer._classify_opcode_type("call") == "control"
    assert analyzer._classify_opcode_type("ret") == "control"


def test_simhash_classify_opcode_data():
    analyzer = _make_analyzer()
    assert analyzer._classify_opcode_type("mov") == "data"
    assert analyzer._classify_opcode_type("push") == "data"
    assert analyzer._classify_opcode_type("pop") == "data"


def test_simhash_classify_opcode_arithmetic():
    analyzer = _make_analyzer()
    assert analyzer._classify_opcode_type("add") == "arithmetic"
    assert analyzer._classify_opcode_type("sub") == "arithmetic"
    assert analyzer._classify_opcode_type("mul") == "arithmetic"


def test_simhash_classify_opcode_logical():
    analyzer = _make_analyzer()
    assert analyzer._classify_opcode_type("and") == "logical"
    assert analyzer._classify_opcode_type("or") == "logical"
    assert analyzer._classify_opcode_type("xor") == "logical"


def test_simhash_classify_opcode_compare():
    analyzer = _make_analyzer()
    assert analyzer._classify_opcode_type("cmp") == "compare"
    assert analyzer._classify_opcode_type("test") == "compare"


def test_simhash_extract_printable_strings():
    analyzer = _make_analyzer()
    data = b"Hello\x00World\x00Test\x00"
    strings = analyzer._extract_printable_strings(data)
    assert isinstance(strings, list)


def test_simhash_min_string_length():
    analyzer = _make_analyzer()
    assert analyzer.min_string_length == 4


def test_simhash_max_instructions():
    analyzer = _make_analyzer()
    assert analyzer.max_instructions_per_function == 500


def test_simhash_get_hash_type():
    analyzer = _make_analyzer()
    assert analyzer._get_hash_type() == "simhash"


# ---------------------------------------------------------------------------
# _extract_ops_from_disasm -- dict and list forms
# ---------------------------------------------------------------------------


def test_simhash_extract_ops_from_dict():
    analyzer = _make_analyzer()
    disasm = {"ops": [{"mnemonic": "mov"}, {"mnemonic": "add"}]}
    ops = analyzer._extract_ops_from_disasm(disasm)
    assert len(ops) == 2


def test_simhash_extract_ops_from_list():
    analyzer = _make_analyzer()
    disasm = [{"mnemonic": "mov"}, {"mnemonic": "add"}]
    ops = analyzer._extract_ops_from_disasm(disasm)
    assert len(ops) == 2


def test_simhash_extract_ops_from_none():
    analyzer = _make_analyzer()
    ops = analyzer._extract_ops_from_disasm(None)
    assert ops == []


def test_simhash_extract_ops_from_string():
    analyzer = _make_analyzer()
    ops = analyzer._extract_ops_from_disasm("unexpected")
    assert ops == []


# ---------------------------------------------------------------------------
# compare_hashes (static, no adapter needed)
# ---------------------------------------------------------------------------


def test_simhash_compare_empty_hashes():
    result = SimHashAnalyzer.compare_hashes("", "")
    assert result is None


def test_simhash_compare_none_hashes():
    result = SimHashAnalyzer.compare_hashes(None, None)
    assert result is None


def test_simhash_compare_identical():
    if not SIMHASH_AVAILABLE:
        pytest.skip("simhash library not available")

    hash1 = "0x123456789abcdef0"
    hash2 = "0x123456789abcdef0"
    distance = SimHashAnalyzer.compare_hashes(hash1, hash2)
    if distance is not None:
        assert distance == 0


# ---------------------------------------------------------------------------
# _extract_string_features via real adapter
# ---------------------------------------------------------------------------


def test_simhash_extract_string_features():
    if not SIMHASH_AVAILABLE:
        pytest.skip("simhash library not available")

    adapter = _make_adapter(
        cmdj_map={
            "izzj": [
                {"string": "Hello World", "vaddr": 0x1000},
                {"string": "Test String", "vaddr": 0x2000},
            ],
            "iSj": [],
        },
    )
    analyzer = SimHashAnalyzer(adapter, SAMPLE)
    features = analyzer._extract_string_features()
    assert isinstance(features, list)


def test_simhash_extract_string_features_empty():
    if not SIMHASH_AVAILABLE:
        pytest.skip("simhash library not available")

    adapter = _make_adapter(cmdj_map={"izzj": [], "iSj": []})
    analyzer = SimHashAnalyzer(adapter, SAMPLE)
    features = analyzer._extract_string_features()
    assert isinstance(features, list)


# ---------------------------------------------------------------------------
# _extract_opcodes_features via real adapter
# ---------------------------------------------------------------------------


def test_simhash_extract_opcodes():
    if not SIMHASH_AVAILABLE:
        pytest.skip("simhash library not available")

    adapter = _make_adapter(
        cmdj_map={
            "aflj": [
                {"offset": 0x1000, "name": "main", "size": 100},
            ],
            "pdfj @ 4096": {
                "ops": [
                    {"mnemonic": "mov"},
                    {"mnemonic": "add"},
                    {"mnemonic": "call"},
                ],
            },
        },
    )
    analyzer = SimHashAnalyzer(adapter, SAMPLE)
    features = analyzer._extract_opcodes_features()
    assert isinstance(features, list)


def test_simhash_extract_opcodes_no_functions():
    if not SIMHASH_AVAILABLE:
        pytest.skip("simhash library not available")

    adapter = _make_adapter(cmdj_map={"aflj": []})
    analyzer = SimHashAnalyzer(adapter, SAMPLE)
    features = analyzer._extract_opcodes_features()
    assert isinstance(features, list)
    assert features == []


# ---------------------------------------------------------------------------
# _get_prev_mnemonic helper
# ---------------------------------------------------------------------------


def test_get_prev_mnemonic_valid():
    analyzer = _make_analyzer()
    ops = [{"mnemonic": "mov"}, {"mnemonic": "add"}, {"mnemonic": "call"}]
    assert analyzer._get_prev_mnemonic(ops, 1) == "mov"
    assert analyzer._get_prev_mnemonic(ops, 2) == "add"


def test_get_prev_mnemonic_boundary():
    analyzer = _make_analyzer()
    ops = [{"mnemonic": "mov"}, {"mnemonic": "add"}]
    assert analyzer._get_prev_mnemonic(ops, 0) is None
    assert analyzer._get_prev_mnemonic(ops, -1) is None
    assert analyzer._get_prev_mnemonic(ops, 5) is None
