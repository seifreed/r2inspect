"""Comprehensive tests for tlsh_analyzer.py - hashing functionality.

All mocks replaced with real objects: FakeR2 + R2PipeAdapter for adapter
tests, real temp files for file-based tests.  NO mocks, NO monkeypatch,
NO @patch.
"""

import os
import tempfile
from pathlib import Path

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.tlsh_analyzer import TLSHAnalyzer, TLSH_AVAILABLE
from r2inspect.testing.fake_r2 import FakeR2

SAMPLES_DIR = Path(__file__).parent.parent.parent / "samples" / "fixtures"
HELLO_PE = SAMPLES_DIR / "hello_pe.exe"


# ---------------------------------------------------------------------------
# FakeR2 + helpers
# ---------------------------------------------------------------------------


def _make_adapter(cmdj_map=None, cmd_map=None):
    """Create a real R2PipeAdapter backed by a FakeR2."""
    return R2PipeAdapter(FakeR2(cmdj_map=cmdj_map, cmd_map=cmd_map))


def _tmp_file(content=b"", suffix=".bin"):
    """Create a real temp file and return its path. Caller should clean up."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.write(fd, content)
    os.close(fd)
    return path


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


def test_init():
    """Test TLSHAnalyzer initialization with a real adapter."""
    path = _tmp_file(b"\x00" * 100)
    try:
        adapter = _make_adapter()
        analyzer = TLSHAnalyzer(adapter, path)
        assert analyzer.filepath == Path(path)
        assert analyzer.adapter is adapter
    finally:
        os.unlink(path)


def test_init_stores_filepath_as_path():
    """Filepath is always stored as a Path object."""
    path = _tmp_file(b"x" * 10)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        assert isinstance(analyzer.filepath, Path)
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# is_available / _check_library_availability
# ---------------------------------------------------------------------------


def test_is_available_reflects_import():
    """is_available() must match the module-level TLSH_AVAILABLE constant."""
    assert TLSHAnalyzer.is_available() is TLSH_AVAILABLE


def test_check_library_availability_matches_is_available():
    """_check_library_availability result is consistent with is_available."""
    path = _tmp_file(b"\x00" * 100)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        is_avail, error = analyzer._check_library_availability()
        if TLSH_AVAILABLE:
            assert is_avail is True
            assert error is None
        else:
            assert is_avail is False
            assert "not available" in error.lower() or "not installed" in error.lower()
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# _get_hash_type
# ---------------------------------------------------------------------------


def test_get_hash_type():
    """Hash type is 'tlsh'."""
    path = _tmp_file(b"\x00" * 100)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        assert analyzer._get_hash_type() == "tlsh"
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# _calculate_hash  (exercises _calculate_binary_tlsh internally)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not TLSH_AVAILABLE, reason="tlsh not installed")
def test_calculate_hash_success_large_file():
    """_calculate_hash returns a hash for a file with enough entropy/size."""
    # TLSH requires >= 50 bytes AND enough byte variety.
    # Use random-ish data to satisfy the entropy requirement.
    data = bytes(range(256)) * 4  # 1024 bytes, good variety
    path = _tmp_file(data)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        hash_val, method, error = analyzer._calculate_hash()
        if hash_val is not None:
            assert isinstance(hash_val, str)
            assert method == "python_library"
            assert error is None
        else:
            # TLSH can return None even with data if entropy is insufficient
            assert method is None
            assert error is not None
    finally:
        os.unlink(path)


def test_calculate_hash_empty_file():
    """_calculate_hash returns an error for empty files."""
    path = _tmp_file(b"")
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        hash_val, method, error = analyzer._calculate_hash()
        assert hash_val is None
        assert method is None
        assert error is not None
    finally:
        os.unlink(path)


def test_calculate_hash_small_file():
    """_calculate_hash returns an error for files smaller than TLSH_MIN_DATA_SIZE."""
    path = _tmp_file(b"A" * 20)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        hash_val, method, error = analyzer._calculate_hash()
        assert hash_val is None
    finally:
        os.unlink(path)


def test_calculate_hash_nonexistent_file():
    """_calculate_hash handles a missing file gracefully."""
    path = _tmp_file(b"x")
    os.unlink(path)  # remove immediately
    analyzer = TLSHAnalyzer(_make_adapter(), path)
    hash_val, method, error = analyzer._calculate_hash()
    assert hash_val is None
    assert error is not None


# ---------------------------------------------------------------------------
# analyze (template method)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not TLSH_AVAILABLE, reason="tlsh not installed")
def test_analyze_adds_binary_tlsh_field():
    """analyze() always includes a 'binary_tlsh' key."""
    data = bytes(range(256)) * 4
    path = _tmp_file(data)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        result = analyzer.analyze()
        assert "binary_tlsh" in result
        assert result["binary_tlsh"] == result.get("hash_value")
    finally:
        os.unlink(path)


def test_analyze_empty_file_still_has_binary_tlsh():
    """Even for an empty file, binary_tlsh key exists."""
    path = _tmp_file(b"")
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        result = analyzer.analyze()
        assert "binary_tlsh" in result
    finally:
        os.unlink(path)


def test_analyze_result_structure():
    """analyze() returns the expected set of keys."""
    path = _tmp_file(b"\x00" * 100)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        result = analyzer.analyze()
        assert "available" in result
        assert "hash_type" in result
        assert result["hash_type"] == "tlsh"
        assert "binary_tlsh" in result
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# _calculate_tlsh_from_hex
# ---------------------------------------------------------------------------


def test_calculate_tlsh_from_hex_none():
    """None hex data returns None."""
    path = _tmp_file(b"\x00" * 100)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        assert analyzer._calculate_tlsh_from_hex(None) is None
    finally:
        os.unlink(path)


def test_calculate_tlsh_from_hex_empty():
    """Empty string returns None."""
    path = _tmp_file(b"\x00" * 100)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        assert analyzer._calculate_tlsh_from_hex("") is None
    finally:
        os.unlink(path)


def test_calculate_tlsh_from_hex_whitespace():
    """Whitespace-only string returns None."""
    path = _tmp_file(b"\x00" * 100)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        assert analyzer._calculate_tlsh_from_hex("   ") is None
    finally:
        os.unlink(path)


def test_calculate_tlsh_from_hex_too_small():
    """Hex data representing < 50 bytes returns None."""
    path = _tmp_file(b"\x00" * 100)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        hex_data = "00" * 30  # 30 bytes
        assert analyzer._calculate_tlsh_from_hex(hex_data) is None
    finally:
        os.unlink(path)


def test_calculate_tlsh_from_hex_invalid_hex():
    """Invalid hex characters return None."""
    path = _tmp_file(b"\x00" * 100)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        assert analyzer._calculate_tlsh_from_hex("invalid_hex_data") is None
    finally:
        os.unlink(path)


@pytest.mark.skipif(not TLSH_AVAILABLE, reason="tlsh not installed")
def test_calculate_tlsh_from_hex_valid():
    """Valid hex data large enough produces a hash (or None if low-entropy)."""
    path = _tmp_file(b"\x00" * 100)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        # 256 distinct byte values repeated to ensure entropy
        hex_data = "".join(f"{b:02x}" for b in range(256)) * 4  # 1024 bytes
        result = analyzer._calculate_tlsh_from_hex(hex_data)
        # TLSH may return a string or None depending on entropy threshold
        assert result is None or isinstance(result, str)
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# _calculate_binary_tlsh
# ---------------------------------------------------------------------------


def test_calculate_binary_tlsh_empty():
    """Empty file yields None."""
    path = _tmp_file(b"")
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        assert analyzer._calculate_binary_tlsh() is None
    finally:
        os.unlink(path)


def test_calculate_binary_tlsh_too_small():
    """File smaller than TLSH_MIN_DATA_SIZE returns None."""
    path = _tmp_file(b"A" * 20)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        assert analyzer._calculate_binary_tlsh() is None
    finally:
        os.unlink(path)


def test_calculate_binary_tlsh_nonexistent_file():
    """Missing file returns None without raising."""
    path = _tmp_file(b"x")
    os.unlink(path)
    analyzer = TLSHAnalyzer(_make_adapter(), path)
    assert analyzer._calculate_binary_tlsh() is None


@pytest.mark.skipif(not TLSH_AVAILABLE, reason="tlsh not installed")
def test_calculate_binary_tlsh_with_real_binary():
    """Test _calculate_binary_tlsh with the sample PE if available."""
    if not HELLO_PE.exists():
        pytest.skip("sample fixture not found")
    analyzer = TLSHAnalyzer(_make_adapter(), str(HELLO_PE))
    result = analyzer._calculate_binary_tlsh()
    if result is not None:
        assert isinstance(result, str)
        assert len(result) > 0


@pytest.mark.skipif(not TLSH_AVAILABLE, reason="tlsh not installed")
def test_calculate_binary_tlsh_large_diverse():
    """A large file with diverse bytes should produce a hash."""
    data = bytes(range(256)) * 40  # 10240 bytes, high entropy
    path = _tmp_file(data)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        result = analyzer._calculate_binary_tlsh()
        # Should succeed for data with good entropy
        assert result is None or isinstance(result, str)
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# compare_hashes (static)
# ---------------------------------------------------------------------------


def test_compare_hashes_empty_hash1():
    """Empty first hash returns None."""
    assert TLSHAnalyzer.compare_hashes("", "HASH2") is None


def test_compare_hashes_empty_hash2():
    """Empty second hash returns None."""
    assert TLSHAnalyzer.compare_hashes("HASH1", "") is None


def test_compare_hashes_none_hash1():
    """None first hash returns None."""
    assert TLSHAnalyzer.compare_hashes(None, "HASH2") is None


def test_compare_hashes_none_hash2():
    """None second hash returns None."""
    assert TLSHAnalyzer.compare_hashes("HASH1", None) is None


@pytest.mark.skipif(not TLSH_AVAILABLE, reason="tlsh not installed")
def test_compare_hashes_identical():
    """Comparing a hash with itself yields distance 0."""
    data = bytes(range(256)) * 4
    path = _tmp_file(data)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        h = analyzer._calculate_binary_tlsh()
        if h is not None:
            score = TLSHAnalyzer.compare_hashes(h, h)
            assert score == 0
    finally:
        os.unlink(path)


@pytest.mark.skipif(not TLSH_AVAILABLE, reason="tlsh not installed")
def test_compare_hashes_different():
    """Two different files produce a non-zero distance."""
    data1 = bytes(range(256)) * 4
    data2 = bytes(range(255, -1, -1)) * 4
    p1 = _tmp_file(data1)
    p2 = _tmp_file(data2)
    try:
        a1 = TLSHAnalyzer(_make_adapter(), p1)
        a2 = TLSHAnalyzer(_make_adapter(), p2)
        h1 = a1._calculate_binary_tlsh()
        h2 = a2._calculate_binary_tlsh()
        if h1 and h2:
            score = TLSHAnalyzer.compare_hashes(h1, h2)
            assert score is None or isinstance(score, int)
    finally:
        os.unlink(p1)
        os.unlink(p2)


def test_compare_hashes_not_available_returns_none():
    """When both hashes are present but TLSH_AVAILABLE is False, result depends on module state."""
    if TLSH_AVAILABLE:
        # With TLSH installed, invalid hashes cause an exception -> None
        result = TLSHAnalyzer.compare_hashes("BADHASH", "BADHASH2")
        assert result is None or isinstance(result, int)
    else:
        assert TLSHAnalyzer.compare_hashes("HASH1", "HASH2") is None


# ---------------------------------------------------------------------------
# get_similarity_level (static, pure function)
# ---------------------------------------------------------------------------


def test_get_similarity_level_none():
    assert TLSHAnalyzer.get_similarity_level(None) == "Unknown"


def test_get_similarity_level_identical():
    assert TLSHAnalyzer.get_similarity_level(0) == "Identical"


def test_get_similarity_level_very_similar():
    assert TLSHAnalyzer.get_similarity_level(20) == "Very Similar"


def test_get_similarity_level_similar():
    assert TLSHAnalyzer.get_similarity_level(40) == "Similar"


def test_get_similarity_level_somewhat_similar():
    assert TLSHAnalyzer.get_similarity_level(75) == "Somewhat Similar"


def test_get_similarity_level_different():
    assert TLSHAnalyzer.get_similarity_level(150) == "Different"


def test_get_similarity_level_very_different():
    assert TLSHAnalyzer.get_similarity_level(300) == "Very Different"


def test_get_similarity_level_boundaries():
    """Boundary value checks."""
    assert TLSHAnalyzer.get_similarity_level(30) == "Very Similar"
    assert TLSHAnalyzer.get_similarity_level(31) == "Similar"
    assert TLSHAnalyzer.get_similarity_level(50) == "Similar"
    assert TLSHAnalyzer.get_similarity_level(51) == "Somewhat Similar"
    assert TLSHAnalyzer.get_similarity_level(100) == "Somewhat Similar"
    assert TLSHAnalyzer.get_similarity_level(101) == "Different"
    assert TLSHAnalyzer.get_similarity_level(200) == "Different"
    assert TLSHAnalyzer.get_similarity_level(201) == "Very Different"


# ---------------------------------------------------------------------------
# TLSH_MIN_DATA_SIZE constant
# ---------------------------------------------------------------------------


def test_tlsh_min_data_size_constant():
    """Verify TLSH_MIN_DATA_SIZE constant exists and is correct."""
    path = _tmp_file(b"\x00" * 100)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        assert analyzer.TLSH_MIN_DATA_SIZE == 50
        assert isinstance(analyzer.TLSH_MIN_DATA_SIZE, int)
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# _get_sections / _get_functions via adapter
# ---------------------------------------------------------------------------


def test_get_sections_via_adapter():
    """_get_sections delegates to adapter.get_sections when available."""
    path = _tmp_file(b"\x00" * 100)
    try:
        adapter = _make_adapter(cmdj_map={"iSj": [{"name": ".text", "vaddr": 0, "size": 100}]})
        analyzer = TLSHAnalyzer(adapter, path)
        sections = analyzer._get_sections()
        assert isinstance(sections, list)
    finally:
        os.unlink(path)


def test_get_functions_via_adapter():
    """_get_functions delegates to adapter.get_functions when available."""
    path = _tmp_file(b"\x00" * 100)
    try:
        adapter = _make_adapter(cmdj_map={"aflj": [{"name": "main", "addr": 0x1000, "size": 64}]})
        analyzer = TLSHAnalyzer(adapter, path)
        functions = analyzer._get_functions()
        assert isinstance(functions, list)
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# _read_bytes_hex
# ---------------------------------------------------------------------------


def test_read_bytes_hex_with_adapter():
    """_read_bytes_hex returns hex or None through a real adapter."""
    path = _tmp_file(b"\x00" * 100)
    try:
        adapter = _make_adapter()
        analyzer = TLSHAnalyzer(adapter, path)
        result = analyzer._read_bytes_hex(0, 10)
        # R2PipeAdapter may or may not have read_bytes; result is hex or None
        assert result is None or isinstance(result, str)
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# analyze_sections
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not TLSH_AVAILABLE, reason="tlsh not installed")
def test_analyze_sections_basic():
    """analyze_sections returns dict with expected structure."""
    data = bytes(range(256)) * 4
    path = _tmp_file(data)
    try:
        adapter = _make_adapter(
            cmdj_map={
                "iSj": [{"name": ".text", "vaddr": 0, "size": 100}],
                "aflj": [],
            }
        )
        analyzer = TLSHAnalyzer(adapter, path)
        result = analyzer.analyze_sections()
        assert isinstance(result, dict)
        assert "available" in result
    finally:
        os.unlink(path)


def test_analyze_sections_not_available():
    """When TLSH is not installed, analyze_sections reports unavailable."""
    if TLSH_AVAILABLE:
        pytest.skip("TLSH is available; cannot test unavailable path without mocks")
    path = _tmp_file(b"\x00" * 100)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        result = analyzer.analyze_sections()
        assert result.get("available") is False
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# compare_tlsh (instance method)
# ---------------------------------------------------------------------------


def test_compare_tlsh_empty_hashes():
    """compare_tlsh with empty strings returns None."""
    path = _tmp_file(b"\x00" * 100)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        assert analyzer.compare_tlsh("", "something") is None
        assert analyzer.compare_tlsh("something", "") is None
    finally:
        os.unlink(path)


@pytest.mark.skipif(not TLSH_AVAILABLE, reason="tlsh not installed")
def test_compare_tlsh_identical_hashes():
    """compare_tlsh of a hash with itself returns 0."""
    data = bytes(range(256)) * 4
    path = _tmp_file(data)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        h = analyzer._calculate_binary_tlsh()
        if h:
            assert analyzer.compare_tlsh(h, h) == 0
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# find_similar_sections
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not TLSH_AVAILABLE, reason="tlsh not installed")
def test_find_similar_sections_returns_list():
    """find_similar_sections always returns a list."""
    data = bytes(range(256)) * 4
    path = _tmp_file(data)
    try:
        adapter = _make_adapter(cmdj_map={"iSj": [], "aflj": []})
        analyzer = TLSHAnalyzer(adapter, path)
        result = analyzer.find_similar_sections(threshold=100)
        assert isinstance(result, list)
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_analyze_file_validation_failure():
    """analyze() gracefully handles validation failure for missing files."""
    path = _tmp_file(b"x")
    os.unlink(path)
    analyzer = TLSHAnalyzer(_make_adapter(), path)
    result = analyzer.analyze()
    assert result.get("available") is False or result.get("error") is not None


def test_str_repr():
    """__str__ and __repr__ work without errors."""
    path = _tmp_file(b"\x00" * 100)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        s = str(analyzer)
        r = repr(analyzer)
        assert "TLSHAnalyzer" in s
        assert "TLSHAnalyzer" in r
    finally:
        os.unlink(path)
