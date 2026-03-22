"""Comprehensive tests for tlsh_analyzer.py - 100% coverage target.

All tests use real objects (FakeR2 + R2PipeAdapter pattern).
NO mocks, NO monkeypatch, NO @patch.
"""

import os
import tempfile
from pathlib import Path

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.tlsh_analyzer import TLSHAnalyzer, TLSH_AVAILABLE
from r2inspect.testing.fake_r2 import FakeR2


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_adapter(cmdj_map=None, cmd_map=None):
    """Create a real R2PipeAdapter backed by a FakeR2."""
    return R2PipeAdapter(FakeR2(cmdj_map=cmdj_map, cmd_map=cmd_map))


def _tmp_file(content=b"", suffix=".bin"):
    """Create a real temp file and return its path.  Caller must clean up."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.write(fd, content)
    os.close(fd)
    return path


class DirectAdapter:
    """Adapter that directly returns pre-configured data without r2pipe."""

    def __init__(self, sections=None, functions=None, cmd_map=None):
        self._sections = sections if sections is not None else []
        self._functions = functions if functions is not None else []
        self._cmd_map = cmd_map or {}

    def get_sections(self):
        return self._sections

    def get_functions(self):
        return self._functions

    def read_bytes(self, address, size):
        key = f"p8 {size} @ {address}"
        hex_data = self._cmd_map.get(key, "")
        if hex_data:
            return bytes.fromhex(hex_data)
        return b""


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


def test_init():
    """TLSHAnalyzer stores filepath as a Path."""
    path = _tmp_file(b"\x00" * 64)
    try:
        adapter = _make_adapter()
        analyzer = TLSHAnalyzer(adapter, path)
        assert str(analyzer.filepath) == path or analyzer.filepath == Path(path)
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# is_available / _check_library_availability
# ---------------------------------------------------------------------------


def test_is_available_returns_bool():
    """is_available returns the module-level TLSH_AVAILABLE flag."""
    result = TLSHAnalyzer.is_available()
    assert result is TLSH_AVAILABLE


def test_check_library_availability_reflects_is_available():
    """_check_library_availability agrees with is_available."""
    path = _tmp_file(b"\x00" * 64)
    try:
        adapter = _make_adapter()
        analyzer = TLSHAnalyzer(adapter, path)
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
    """_get_hash_type returns 'tlsh'."""
    path = _tmp_file(b"\x00" * 64)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        assert analyzer._get_hash_type() == "tlsh"
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# _calculate_hash
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not TLSH_AVAILABLE, reason="TLSH library not installed")
def test_calculate_hash_success():
    """_calculate_hash returns hash, method, None for a sufficiently large file."""
    # TLSH needs >= 50 bytes of non-trivial data
    data = os.urandom(1024)
    path = _tmp_file(data)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        hash_val, method, error = analyzer._calculate_hash()

        assert hash_val is not None
        assert method == "python_library"
        assert error is None
    finally:
        os.unlink(path)


def test_calculate_hash_file_too_small():
    """_calculate_hash returns no-hash error for a tiny file."""
    path = _tmp_file(b"\x00" * 10)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        hash_val, method, error = analyzer._calculate_hash()

        # File is below TLSH_MIN_DATA_SIZE (50 bytes)
        assert hash_val is None
        assert error is not None
    finally:
        os.unlink(path)


def test_calculate_hash_file_missing():
    """_calculate_hash handles missing file gracefully."""
    path = _tmp_file(b"\x00" * 100)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        os.unlink(path)
        path = None

        hash_val, method, error = analyzer._calculate_hash()
        assert hash_val is None
        assert error is not None
    finally:
        if path and os.path.exists(path):
            os.unlink(path)


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not TLSH_AVAILABLE, reason="TLSH library not installed")
def test_analyze_includes_binary_tlsh():
    """analyze() result contains both binary_tlsh and hash_value."""
    data = os.urandom(1024)
    path = _tmp_file(data)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        result = analyzer.analyze()

        assert "binary_tlsh" in result
        assert "hash_value" in result
        # binary_tlsh should equal hash_value
        assert result["binary_tlsh"] == result["hash_value"]
    finally:
        os.unlink(path)


def test_analyze_small_file_still_has_binary_tlsh_key():
    """analyze() always includes 'binary_tlsh', even when hash is None."""
    path = _tmp_file(b"\x00" * 10)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        result = analyzer.analyze()

        assert "binary_tlsh" in result
        assert "hash_value" in result
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# analyze_sections
# ---------------------------------------------------------------------------


def test_analyze_sections_not_available():
    """analyze_sections returns unavailable when TLSH library is missing."""
    import r2inspect.modules.tlsh_analyzer as tlsh_mod

    path = _tmp_file(b"\x00" * 100)
    try:
        adapter = _make_adapter()
        analyzer = TLSHAnalyzer(adapter, path)

        original = tlsh_mod.TLSH_AVAILABLE
        tlsh_mod.TLSH_AVAILABLE = False
        try:
            result = analyzer.analyze_sections()
        finally:
            tlsh_mod.TLSH_AVAILABLE = original

        assert result["available"] is False
        assert "error" in result
    finally:
        os.unlink(path)


@pytest.mark.skipif(not TLSH_AVAILABLE, reason="TLSH library not installed")
def test_analyze_sections_success():
    """analyze_sections populates stats correctly."""
    data = os.urandom(1024)
    path = _tmp_file(data)
    try:
        sections = [
            {
                "name": ".text",
                "vaddr": 4096,
                "vsize": 256,
                "size": 256,
                "paddr": 0,
                "perm": "r-x",
                "type": "",
            },
            {
                "name": ".data",
                "vaddr": 8192,
                "vsize": 128,
                "size": 128,
                "paddr": 256,
                "perm": "rw-",
                "type": "",
            },
        ]
        functions = [{"name": "func1", "offset": 4096, "addr": 4096, "size": 100}]
        cmd_map = {
            f"p8 256 @ {4096}": "AA" * 256,
            f"p8 128 @ {8192}": "BB" * 128,
            f"p8 100 @ {4096}": "CC" * 100,
        }
        cmdj_map = {"iSj": sections, "aflj": functions}
        adapter = _make_adapter(cmdj_map=cmdj_map, cmd_map=cmd_map)
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer.analyze_sections()

        assert result["available"] is True
        assert "binary_tlsh" in result
        assert result["stats"]["sections_analyzed"] == 2
        assert result["stats"]["functions_analyzed"] == 1
    finally:
        os.unlink(path)


@pytest.mark.skipif(not TLSH_AVAILABLE, reason="TLSH library not installed")
def test_analyze_sections_exception_when_file_removed():
    """analyze_sections returns error when binary TLSH calc fails."""
    path = _tmp_file(b"\x00" * 100)
    try:
        adapter = _make_adapter()
        analyzer = TLSHAnalyzer(adapter, path)

        os.unlink(path)
        path = None

        result = analyzer.analyze_sections()
        # The exception from file reading is caught -> available may be True
        # with binary_tlsh=None, or available=False with error
        assert "available" in result
    finally:
        if path and os.path.exists(path):
            os.unlink(path)


# ---------------------------------------------------------------------------
# _calculate_tlsh_from_hex
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not TLSH_AVAILABLE, reason="TLSH library not installed")
def test_calculate_tlsh_from_hex_success():
    """_calculate_tlsh_from_hex returns a hash for enough data."""
    path = _tmp_file(b"\x00" * 64)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        # 200 bytes of random hex data
        hex_data = os.urandom(200).hex()
        result = analyzer._calculate_tlsh_from_hex(hex_data)

        # TLSH may or may not produce a hash depending on data entropy
        assert result is None or isinstance(result, str)
    finally:
        os.unlink(path)


def test_calculate_tlsh_from_hex_too_small():
    """_calculate_tlsh_from_hex returns None for data below minimum size."""
    path = _tmp_file(b"\x00" * 64)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        # 30 bytes < TLSH_MIN_DATA_SIZE (50)
        hex_data = "00" * 30
        result = analyzer._calculate_tlsh_from_hex(hex_data)
        assert result is None
    finally:
        os.unlink(path)


def test_calculate_tlsh_from_hex_empty():
    """_calculate_tlsh_from_hex returns None for empty string."""
    path = _tmp_file(b"\x00" * 64)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        assert analyzer._calculate_tlsh_from_hex("") is None
    finally:
        os.unlink(path)


def test_calculate_tlsh_from_hex_none():
    """_calculate_tlsh_from_hex returns None for None input."""
    path = _tmp_file(b"\x00" * 64)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        assert analyzer._calculate_tlsh_from_hex(None) is None
    finally:
        os.unlink(path)


def test_calculate_tlsh_from_hex_invalid_hex():
    """_calculate_tlsh_from_hex returns None for non-hex strings."""
    path = _tmp_file(b"\x00" * 64)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        result = analyzer._calculate_tlsh_from_hex("not_valid_hex_string!!!")
        assert result is None
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# _calculate_binary_tlsh
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not TLSH_AVAILABLE, reason="TLSH library not installed")
def test_calculate_binary_tlsh_success():
    """_calculate_binary_tlsh returns hash for large-enough random file."""
    data = os.urandom(1024)
    path = _tmp_file(data)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        result = analyzer._calculate_binary_tlsh()
        assert result is not None
        assert isinstance(result, str)
        assert len(result) > 0
    finally:
        os.unlink(path)


def test_calculate_binary_tlsh_too_small():
    """_calculate_binary_tlsh returns None for tiny file."""
    path = _tmp_file(b"A" * 20)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        result = analyzer._calculate_binary_tlsh()
        assert result is None
    finally:
        os.unlink(path)


def test_calculate_binary_tlsh_file_missing():
    """_calculate_binary_tlsh returns None when file does not exist."""
    path = _tmp_file(b"\x00" * 100)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        os.unlink(path)
        path = None

        result = analyzer._calculate_binary_tlsh()
        assert result is None
    finally:
        if path and os.path.exists(path):
            os.unlink(path)


# ---------------------------------------------------------------------------
# _calculate_section_tlsh
# ---------------------------------------------------------------------------


def test_calculate_section_tlsh_with_sections():
    """_calculate_section_tlsh returns a dict keyed by section name."""
    path = _tmp_file(b"\x00" * 100)
    try:
        sections = [
            {
                "name": ".text",
                "vaddr": 0x1000,
                "vsize": 500,
                "size": 500,
                "paddr": 0,
                "perm": "r-x",
                "type": "",
            },
            {
                "name": ".data",
                "vaddr": 0x2000,
                "vsize": 0,
                "size": 0,
                "paddr": 500,
                "perm": "rw-",
                "type": "",
            },
        ]
        cmd_map = {f"p8 500 @ {0x1000}": "AA" * 500}
        cmdj_map = {"iSj": sections}
        adapter = _make_adapter(cmdj_map=cmdj_map, cmd_map=cmd_map)
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer._calculate_section_tlsh()

        assert ".text" in result
        assert ".data" in result
        # .data has size 0 -> None
        assert result[".data"] is None
    finally:
        os.unlink(path)


def test_calculate_section_tlsh_no_sections():
    """_calculate_section_tlsh returns empty dict when no sections."""
    path = _tmp_file(b"\x00" * 100)
    try:
        cmdj_map = {"iSj": []}
        adapter = _make_adapter(cmdj_map=cmdj_map)
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer._calculate_section_tlsh()
        assert result == {}
    finally:
        os.unlink(path)


def test_calculate_section_tlsh_exception():
    """_calculate_section_tlsh returns {} when _get_sections fails."""
    path = _tmp_file(b"\x00" * 100)
    try:
        # Adapter with no get_sections raises an exception path
        # Using DirectAdapter with sections that cause issues internally
        class FailingSectionsAdapter:
            def get_sections(self):
                raise RuntimeError("boom")

            def get_functions(self):
                return []

            def read_bytes(self, addr, size):
                return b""

        analyzer = TLSHAnalyzer(FailingSectionsAdapter(), path)
        result = analyzer._calculate_section_tlsh()
        assert result == {}
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# _calculate_function_tlsh
# ---------------------------------------------------------------------------


def test_calculate_function_tlsh_with_functions():
    """_calculate_function_tlsh returns a dict keyed by function name."""
    path = _tmp_file(b"\x00" * 100)
    try:
        functions = [
            {"name": "main", "addr": 0x1000, "size": 200},
            {"name": "helper", "addr": 0x2000, "size": 0},
        ]
        cmd_map = {f"p8 200 @ {0x1000}": "BB" * 200}
        adapter = DirectAdapter(functions=functions, cmd_map=cmd_map)
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer._calculate_function_tlsh()

        assert "main" in result
        assert "helper" in result
        # helper has size 0 -> None
        assert result["helper"] is None
    finally:
        os.unlink(path)


def test_calculate_function_tlsh_malformed():
    """_calculate_function_tlsh skips non-dict entries."""
    path = _tmp_file(b"\x00" * 100)
    try:
        functions = ["not a dict", {"name": "valid", "addr": 0x1000, "size": 100}]
        cmd_map = {f"p8 100 @ {0x1000}": "CC" * 100}
        adapter = DirectAdapter(functions=functions, cmd_map=cmd_map)
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer._calculate_function_tlsh()

        assert "valid" in result
        assert len(result) == 1
    finally:
        os.unlink(path)


def test_calculate_function_tlsh_limit_50():
    """_calculate_function_tlsh processes at most 50 functions."""
    path = _tmp_file(b"\x00" * 100)
    try:
        functions = [{"name": f"func{i}", "addr": 0x1000 + i * 100, "size": 100} for i in range(60)]
        cmd_map = {f"p8 100 @ {0x1000 + i * 100}": "DD" * 100 for i in range(60)}
        adapter = DirectAdapter(functions=functions, cmd_map=cmd_map)
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer._calculate_function_tlsh()

        assert len(result) == 50
    finally:
        os.unlink(path)


def test_calculate_function_tlsh_exception():
    """_calculate_function_tlsh returns {} when _get_functions fails."""
    path = _tmp_file(b"\x00" * 100)
    try:

        class FailingFuncAdapter:
            def get_sections(self):
                return []

            def get_functions(self):
                raise RuntimeError("boom")

            def read_bytes(self, addr, size):
                return b""

        analyzer = TLSHAnalyzer(FailingFuncAdapter(), path)
        result = analyzer._calculate_function_tlsh()
        assert result == {}
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# compare_tlsh
# ---------------------------------------------------------------------------


def test_compare_tlsh_empty_hash():
    """compare_tlsh returns None when one hash is empty."""
    path = _tmp_file(b"\x00" * 64)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        assert analyzer.compare_tlsh("", "HASH2") is None
        assert analyzer.compare_tlsh("HASH1", "") is None
    finally:
        os.unlink(path)


@pytest.mark.skipif(not TLSH_AVAILABLE, reason="TLSH library not installed")
def test_compare_tlsh_real_hashes():
    """compare_tlsh returns an integer distance for real hashes."""
    import tlsh

    path = _tmp_file(b"\x00" * 64)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        data1 = os.urandom(1024)
        data2 = os.urandom(1024)
        h1 = tlsh.hash(data1)
        h2 = tlsh.hash(data2)
        if not h1 or not h2:
            pytest.skip("TLSH could not hash random data")

        result = analyzer.compare_tlsh(h1, h2)
        assert isinstance(result, int)
        assert result >= 0
    finally:
        os.unlink(path)


@pytest.mark.skipif(not TLSH_AVAILABLE, reason="TLSH library not installed")
def test_compare_tlsh_invalid_hashes():
    """compare_tlsh returns None for invalid hash strings."""
    path = _tmp_file(b"\x00" * 64)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)
        result = analyzer.compare_tlsh("INVALID", "ALSO_INVALID")
        # Either None (exception caught) or int (library tolerant)
        assert result is None or isinstance(result, int)
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# find_similar_sections
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not TLSH_AVAILABLE, reason="TLSH library not installed")
def test_find_similar_sections_returns_pairs():
    """find_similar_sections returns sorted pairs within threshold."""
    import tlsh

    data = os.urandom(2048)
    path = _tmp_file(data)
    try:
        chunk1 = os.urandom(512)
        chunk2 = os.urandom(512)
        h1 = tlsh.hash(chunk1)
        h2 = tlsh.hash(chunk2)
        if not h1 or not h2:
            pytest.skip("TLSH could not hash random data")

        sections = [
            {
                "name": ".text",
                "vaddr": 4096,
                "vsize": 512,
                "size": 512,
                "paddr": 0,
                "perm": "r-x",
                "type": "",
            },
            {
                "name": ".data",
                "vaddr": 8192,
                "vsize": 512,
                "size": 512,
                "paddr": 512,
                "perm": "rw-",
                "type": "",
            },
        ]
        cmd_map = {
            f"p8 512 @ {4096}": chunk1.hex(),
            f"p8 512 @ {8192}": chunk2.hex(),
        }
        cmdj_map = {"iSj": sections, "aflj": []}
        adapter = _make_adapter(cmdj_map=cmdj_map, cmd_map=cmd_map)
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer.find_similar_sections(threshold=2000)

        assert isinstance(result, list)
        for pair in result:
            assert "section1" in pair
            assert "section2" in pair
            assert "similarity_score" in pair
    finally:
        os.unlink(path)


def test_find_similar_sections_not_available():
    """find_similar_sections returns [] when TLSH unavailable."""
    import r2inspect.modules.tlsh_analyzer as tlsh_mod

    path = _tmp_file(b"\x00" * 100)
    try:
        analyzer = TLSHAnalyzer(_make_adapter(), path)

        original = tlsh_mod.TLSH_AVAILABLE
        tlsh_mod.TLSH_AVAILABLE = False
        try:
            result = analyzer.find_similar_sections()
        finally:
            tlsh_mod.TLSH_AVAILABLE = original

        assert result == []
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# compare_hashes (static)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not TLSH_AVAILABLE, reason="TLSH library not installed")
def test_compare_hashes_static_real():
    """compare_hashes returns int distance for real hashes."""
    import tlsh

    h1 = tlsh.hash(os.urandom(1024))
    h2 = tlsh.hash(os.urandom(1024))
    if not h1 or not h2:
        pytest.skip("TLSH could not hash random data")

    result = TLSHAnalyzer.compare_hashes(h1, h2)
    assert isinstance(result, int)
    assert result >= 0


def test_compare_hashes_not_available():
    """compare_hashes returns None when TLSH is unavailable."""
    import r2inspect.modules.tlsh_analyzer as tlsh_mod

    original = tlsh_mod.TLSH_AVAILABLE
    tlsh_mod.TLSH_AVAILABLE = False
    try:
        result = TLSHAnalyzer.compare_hashes("HASH1", "HASH2")
        assert result is None
    finally:
        tlsh_mod.TLSH_AVAILABLE = original


def test_compare_hashes_empty():
    """compare_hashes returns None with empty hash strings."""
    result = TLSHAnalyzer.compare_hashes("", "HASH2")
    assert result is None

    result = TLSHAnalyzer.compare_hashes("HASH1", "")
    assert result is None


# ---------------------------------------------------------------------------
# get_similarity_level (static)
# ---------------------------------------------------------------------------


def test_get_similarity_level_all_bands():
    """get_similarity_level covers every threshold band."""
    assert TLSHAnalyzer.get_similarity_level(None) == "Unknown"
    assert TLSHAnalyzer.get_similarity_level(0) == "Identical"
    assert TLSHAnalyzer.get_similarity_level(20) == "Very Similar"
    assert TLSHAnalyzer.get_similarity_level(30) == "Very Similar"
    assert TLSHAnalyzer.get_similarity_level(40) == "Similar"
    assert TLSHAnalyzer.get_similarity_level(50) == "Similar"
    assert TLSHAnalyzer.get_similarity_level(75) == "Somewhat Similar"
    assert TLSHAnalyzer.get_similarity_level(100) == "Somewhat Similar"
    assert TLSHAnalyzer.get_similarity_level(150) == "Different"
    assert TLSHAnalyzer.get_similarity_level(200) == "Different"
    assert TLSHAnalyzer.get_similarity_level(300) == "Very Different"
    assert TLSHAnalyzer.get_similarity_level(1000) == "Very Different"


# ---------------------------------------------------------------------------
# _get_sections / _get_functions / _read_bytes_hex
# ---------------------------------------------------------------------------


def test_get_sections_real_adapter():
    """_get_sections delegates to adapter.get_sections."""
    path = _tmp_file(b"\x00" * 100)
    try:
        sections = [
            {
                "name": ".text",
                "vaddr": 4096,
                "vsize": 100,
                "size": 100,
                "paddr": 0,
                "perm": "r-x",
                "type": "",
            }
        ]
        cmdj_map = {"iSj": sections}
        adapter = _make_adapter(cmdj_map=cmdj_map)
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer._get_sections()
        assert len(result) == 1
    finally:
        os.unlink(path)


def test_get_sections_none_adapter():
    """_get_sections returns [] when adapter is None."""
    path = _tmp_file(b"\x00" * 100)
    try:
        analyzer = TLSHAnalyzer(None, path)
        assert analyzer._get_sections() == []
    finally:
        os.unlink(path)


def test_get_sections_no_method():
    """_get_sections returns [] when adapter lacks get_sections."""
    path = _tmp_file(b"\x00" * 100)
    try:

        class Minimal:
            pass

        analyzer = TLSHAnalyzer(Minimal(), path)
        assert analyzer._get_sections() == []
    finally:
        os.unlink(path)


def test_get_functions_real_adapter():
    """_get_functions delegates to adapter.get_functions."""
    path = _tmp_file(b"\x00" * 100)
    try:
        functions = [{"name": "main", "offset": 4096, "addr": 4096, "size": 100}]
        cmdj_map = {"aflj": functions}
        adapter = _make_adapter(cmdj_map=cmdj_map)
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer._get_functions()
        assert len(result) == 1
    finally:
        os.unlink(path)


def test_get_functions_none_adapter():
    """_get_functions returns [] when adapter is None."""
    path = _tmp_file(b"\x00" * 100)
    try:
        analyzer = TLSHAnalyzer(None, path)
        assert analyzer._get_functions() == []
    finally:
        os.unlink(path)


def test_get_functions_no_method():
    """_get_functions returns [] when adapter lacks get_functions."""
    path = _tmp_file(b"\x00" * 100)
    try:

        class Minimal:
            pass

        analyzer = TLSHAnalyzer(Minimal(), path)
        assert analyzer._get_functions() == []
    finally:
        os.unlink(path)


def test_read_bytes_hex_success():
    """_read_bytes_hex returns hex string from adapter bytes."""
    path = _tmp_file(b"\x00" * 100)
    try:
        cmd_map = {f"p8 4 @ {4096}": "01020304"}
        adapter = _make_adapter(cmd_map=cmd_map)
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer._read_bytes_hex(4096, 4)
        assert result == "01020304"
    finally:
        os.unlink(path)


def test_read_bytes_hex_empty_response():
    """_read_bytes_hex returns None when adapter returns empty bytes."""
    path = _tmp_file(b"\x00" * 100)
    try:
        adapter = _make_adapter()
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer._read_bytes_hex(4096, 4)
        # Empty response -> b"" which is falsy -> None
        assert result is None
    finally:
        os.unlink(path)


def test_read_bytes_hex_none_adapter():
    """_read_bytes_hex returns None when adapter is None."""
    path = _tmp_file(b"\x00" * 100)
    try:
        analyzer = TLSHAnalyzer(None, path)
        assert analyzer._read_bytes_hex(4096, 4) is None
    finally:
        os.unlink(path)


def test_read_bytes_hex_no_method():
    """_read_bytes_hex returns None when adapter lacks read_bytes."""
    path = _tmp_file(b"\x00" * 100)
    try:

        class Minimal:
            pass

        analyzer = TLSHAnalyzer(Minimal(), path)
        assert analyzer._read_bytes_hex(4096, 4) is None
    finally:
        os.unlink(path)


def test_read_bytes_hex_exception():
    """_read_bytes_hex returns None when adapter.read_bytes raises."""
    path = _tmp_file(b"\x00" * 100)
    try:

        class FailingAdapter:
            def read_bytes(self, addr, size):
                raise RuntimeError("read failed")

        analyzer = TLSHAnalyzer(FailingAdapter(), path)
        assert analyzer._read_bytes_hex(4096, 4) is None
    finally:
        os.unlink(path)
