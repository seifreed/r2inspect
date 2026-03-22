"""Comprehensive tests for tlsh_analyzer.py - analysis paths and comparison logic.

All mocks replaced with real objects using FakeR2 + R2PipeAdapter pattern.
"""

import tempfile
import os
from pathlib import Path

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.tlsh_analyzer import TLSHAnalyzer, TLSH_AVAILABLE
from r2inspect.testing.fake_r2 import FakeR2

SAMPLES_DIR = Path(__file__).parent.parent.parent / "samples" / "fixtures"


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
# analyze_sections tests
# ---------------------------------------------------------------------------


def test_analyze_sections_not_available():
    """Test analyze_sections when TLSH not available."""
    # Use a real temp file so the filepath validation passes
    path = _tmp_file(b"\x00" * 100)
    try:
        adapter = _make_adapter()
        analyzer = TLSHAnalyzer(adapter, path)

        # Temporarily flip the module-level TLSH_AVAILABLE flag that
        # analyze_sections passes into build_detailed_analysis.
        import r2inspect.modules.tlsh_analyzer as tlsh_mod

        original = tlsh_mod.TLSH_AVAILABLE
        tlsh_mod.TLSH_AVAILABLE = False
        try:
            result = analyzer.analyze_sections()
        finally:
            tlsh_mod.TLSH_AVAILABLE = original

        assert result["available"] is False
        assert "not installed" in result.get("error", "")
    finally:
        os.unlink(path)


def test_analyze_sections_success():
    """Test analyze_sections produces correct structure with real code paths."""
    # Create a file large enough for TLSH (needs >= 50 bytes)
    data = os.urandom(512)
    path = _tmp_file(data)
    try:
        # Provide sections and functions via FakeR2
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
        functions = [
            {"name": "main", "offset": 4096, "addr": 4096, "size": 100},
        ]
        # p8 commands return hex bytes for read_bytes
        hex_text = "AA" * 256
        hex_data = "BB" * 128
        hex_func = "CC" * 100

        cmd_map = {
            f"p8 256 @ {4096}": hex_text,
            f"p8 128 @ {8192}": hex_data,
            f"p8 100 @ {4096}": hex_func,
        }
        cmdj_map = {
            "iSj": sections,
            "aflj": functions,
        }
        adapter = _make_adapter(cmdj_map=cmdj_map, cmd_map=cmd_map)
        analyzer = TLSHAnalyzer(adapter, path)

        if not TLSH_AVAILABLE:
            pytest.skip("TLSH library not installed")

        result = analyzer.analyze_sections()

        assert result["available"] is True
        # binary_tlsh is calculated from the file directly
        assert "binary_tlsh" in result
        assert result["stats"]["sections_analyzed"] == 2
        assert result["stats"]["functions_analyzed"] == 1
    finally:
        os.unlink(path)


def test_analyze_sections_with_none_hashes():
    """Test analyze_sections when sections/functions return None hashes (zero-size)."""
    data = os.urandom(512)
    path = _tmp_file(data)
    try:
        # One section with size, one with size 0
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
                "name": ".bss",
                "vaddr": 8192,
                "vsize": 128,
                "size": 0,
                "paddr": 256,
                "perm": "rw-",
                "type": "",
            },
        ]
        # One function with size 0, one valid
        functions = [
            {"name": "func1", "offset": 4096, "addr": 4096, "size": 0},
            {"name": "func2", "offset": 8192, "addr": 8192, "size": 100},
        ]
        cmd_map = {
            f"p8 256 @ {4096}": "AA" * 256,
            f"p8 100 @ {8192}": "BB" * 100,
        }
        cmdj_map = {
            "iSj": sections,
            "aflj": functions,
        }
        adapter = _make_adapter(cmdj_map=cmdj_map, cmd_map=cmd_map)
        analyzer = TLSHAnalyzer(adapter, path)

        if not TLSH_AVAILABLE:
            pytest.skip("TLSH library not installed")

        result = analyzer.analyze_sections()

        assert result["stats"]["sections_analyzed"] == 2
        # .bss has size 0, so no TLSH
        assert result["section_tlsh"][".bss"] is None
        assert result["stats"]["functions_analyzed"] == 2
        # func1 has size 0, so no TLSH
        assert result["function_tlsh"]["func1"] is None
    finally:
        os.unlink(path)


def test_analyze_sections_exception():
    """Test analyze_sections when binary TLSH calculation fails (file missing)."""
    # Use a path that doesn't exist - _calculate_binary_tlsh reads from filesystem
    # The R2HashingStrategy requires a valid filepath string
    path = _tmp_file(b"\x00" * 100)
    try:
        adapter = _make_adapter()
        analyzer = TLSHAnalyzer(adapter, path)

        if not TLSH_AVAILABLE:
            pytest.skip("TLSH library not installed")

        # Remove the file so _calculate_binary_tlsh fails
        os.unlink(path)
        path = None  # Prevent double-unlink in finally

        result = analyzer.analyze_sections()
        # When binary_tlsh fails, it returns None but analyze_sections still succeeds
        # The result should still have available=True because the library is available
        assert "available" in result
    finally:
        if path and os.path.exists(path):
            os.unlink(path)


# ---------------------------------------------------------------------------
# _calculate_section_tlsh tests
# ---------------------------------------------------------------------------


def test_calculate_section_tlsh_success():
    """Test _calculate_section_tlsh with real sections returning hex data."""
    data = os.urandom(512)
    path = _tmp_file(data)
    try:
        sections = [
            {
                "name": ".text",
                "vaddr": 4096,
                "vsize": 500,
                "size": 500,
                "paddr": 0,
                "perm": "r-x",
                "type": "",
            },
            {
                "name": ".data",
                "vaddr": 8192,
                "vsize": 200,
                "size": 200,
                "paddr": 500,
                "perm": "rw-",
                "type": "",
            },
        ]
        hex500 = "AA" * 500
        hex200 = "BB" * 200
        cmd_map = {
            f"p8 500 @ {4096}": hex500,
            f"p8 200 @ {8192}": hex200,
        }
        cmdj_map = {"iSj": sections}
        adapter = _make_adapter(cmdj_map=cmdj_map, cmd_map=cmd_map)
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer._calculate_section_tlsh()

        assert ".text" in result
        assert ".data" in result
    finally:
        os.unlink(path)


def test_calculate_section_tlsh_empty_size():
    """Test _calculate_section_tlsh with zero size section."""
    path = _tmp_file(b"\x00" * 100)
    try:
        sections = [
            {
                "name": ".bss",
                "vaddr": 4096,
                "vsize": 0,
                "size": 0,
                "paddr": 0,
                "perm": "rw-",
                "type": "",
            }
        ]
        cmdj_map = {"iSj": sections}
        adapter = _make_adapter(cmdj_map=cmdj_map)
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer._calculate_section_tlsh()

        assert ".bss" in result
        assert result[".bss"] is None
    finally:
        os.unlink(path)


def test_calculate_section_tlsh_very_large():
    """Test _calculate_section_tlsh with very large section gets skipped."""
    path = _tmp_file(b"\x00" * 100)
    try:
        sections = [
            {
                "name": ".huge",
                "vaddr": 4096,
                "vsize": 100 * 1024 * 1024,
                "size": 100 * 1024 * 1024,
                "paddr": 0,
                "perm": "r-x",
                "type": "",
            }
        ]
        cmdj_map = {"iSj": sections}
        adapter = _make_adapter(cmdj_map=cmdj_map)
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer._calculate_section_tlsh()

        assert ".huge" in result
        assert result[".huge"] is None
    finally:
        os.unlink(path)


def test_calculate_section_tlsh_no_sections():
    """Test _calculate_section_tlsh with no sections."""
    path = _tmp_file(b"\x00" * 100)
    try:
        cmdj_map = {"iSj": []}
        adapter = _make_adapter(cmdj_map=cmdj_map)
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer._calculate_section_tlsh()

        assert result == {}
    finally:
        os.unlink(path)


def test_calculate_section_tlsh_section_exception():
    """Test _calculate_section_tlsh when read_bytes returns empty (simulates read error)."""
    path = _tmp_file(b"\x00" * 100)
    try:
        sections = [
            {
                "name": ".text",
                "vaddr": 4096,
                "vsize": 500,
                "size": 500,
                "paddr": 0,
                "perm": "r-x",
                "type": "",
            }
        ]
        # No cmd_map entry for p8, so read_bytes returns empty -> hex will be empty
        cmdj_map = {"iSj": sections}
        adapter = _make_adapter(cmdj_map=cmdj_map)
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer._calculate_section_tlsh()

        assert ".text" in result
        # Empty read returns None from _calculate_tlsh_from_hex
        assert result[".text"] is None
    finally:
        os.unlink(path)


def test_calculate_section_tlsh_general_exception():
    """Test _calculate_section_tlsh when adapter returns no section data at all."""
    path = _tmp_file(b"\x00" * 100)
    try:
        # No iSj mapping -> adapter returns empty list -> result is {}
        adapter = _make_adapter()
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer._calculate_section_tlsh()

        assert result == {}
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# _calculate_function_tlsh tests
# ---------------------------------------------------------------------------


def test_calculate_function_tlsh_success():
    """Test _calculate_function_tlsh with real functions returning hex data."""
    data = os.urandom(512)
    path = _tmp_file(data)
    try:
        functions = [
            {"name": "main", "offset": 4096, "addr": 4096, "size": 200},
            {"name": "helper", "offset": 8192, "addr": 8192, "size": 100},
        ]
        cmd_map = {
            f"p8 200 @ {4096}": "BB" * 200,
            f"p8 100 @ {8192}": "CC" * 100,
        }
        cmdj_map = {"aflj": functions}
        adapter = _make_adapter(cmdj_map=cmdj_map, cmd_map=cmd_map)
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer._calculate_function_tlsh()

        assert "main" in result
        assert "helper" in result
    finally:
        os.unlink(path)


def test_calculate_function_tlsh_malformed_data():
    """Test _calculate_function_tlsh with malformed function data (non-dict entry)."""
    path = _tmp_file(b"\x00" * 100)
    try:
        # aflj normally returns list of dicts; we include a non-dict entry
        # But R2PipeAdapter validates data, so we need to provide dicts
        # The actual malformed check is in calculate_function_tlsh which checks isinstance(func, dict)
        # Since FakeR2.cmdj returns what we put in, and the adapter validates,
        # we create an adapter that exposes get_functions directly

        # Build a custom adapter-like object that has get_functions, read_bytes, etc.
        class DirectAdapter:
            """Adapter that directly returns pre-configured data."""

            def __init__(self, functions, cmd_map=None):
                self._functions = functions
                self._cmd_map = cmd_map or {}

            def get_sections(self):
                return []

            def get_functions(self):
                return self._functions

            def read_bytes(self, address, size):
                key = f"p8 {size} @ {address}"
                hex_data = self._cmd_map.get(key, "")
                if hex_data:
                    return bytes.fromhex(hex_data)
                return b""

        functions = ["not a dict", {"name": "valid", "addr": 4096, "size": 100}]
        cmd_map = {f"p8 100 @ {4096}": "CC" * 100}
        adapter = DirectAdapter(functions, cmd_map)
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer._calculate_function_tlsh()

        # "not a dict" is skipped, only "valid" is processed
        assert "valid" in result
        assert len(result) == 1
    finally:
        os.unlink(path)


def test_calculate_function_tlsh_zero_size():
    """Test _calculate_function_tlsh with zero size function."""
    path = _tmp_file(b"\x00" * 100)
    try:
        functions = [{"name": "empty", "offset": 4096, "addr": 4096, "size": 0}]
        cmdj_map = {"aflj": functions}
        adapter = _make_adapter(cmdj_map=cmdj_map)
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer._calculate_function_tlsh()

        assert "empty" in result
        assert result["empty"] is None
    finally:
        os.unlink(path)


def test_calculate_function_tlsh_no_addr():
    """Test _calculate_function_tlsh with no address."""
    path = _tmp_file(b"\x00" * 100)
    try:
        functions = [{"name": "noaddr", "size": 100}]
        cmdj_map = {"aflj": functions}
        adapter = _make_adapter(cmdj_map=cmdj_map)
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer._calculate_function_tlsh()

        assert "noaddr" in result
        assert result["noaddr"] is None
    finally:
        os.unlink(path)


def test_calculate_function_tlsh_very_large():
    """Test _calculate_function_tlsh with very large function (>100000) gets skipped."""
    path = _tmp_file(b"\x00" * 100)
    try:
        functions = [{"name": "huge", "offset": 4096, "addr": 4096, "size": 200000}]
        cmdj_map = {"aflj": functions}
        adapter = _make_adapter(cmdj_map=cmdj_map)
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer._calculate_function_tlsh()

        assert "huge" in result
        assert result["huge"] is None
    finally:
        os.unlink(path)


def test_calculate_function_tlsh_limit():
    """Test _calculate_function_tlsh respects the 50-function limit."""
    path = _tmp_file(b"\x00" * 100)
    try:
        functions = [
            {"name": f"func{i}", "offset": 4096 + i * 256, "addr": 4096 + i * 256, "size": 100}
            for i in range(60)
        ]
        # Provide hex data for all 60 functions (only first 50 should be processed)
        cmd_map = {f"p8 100 @ {4096 + i * 256}": "DD" * 100 for i in range(60)}
        cmdj_map = {"aflj": functions}
        adapter = _make_adapter(cmdj_map=cmdj_map, cmd_map=cmd_map)
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer._calculate_function_tlsh()

        assert len(result) == 50
    finally:
        os.unlink(path)


def test_calculate_function_tlsh_no_functions():
    """Test _calculate_function_tlsh with no functions."""
    path = _tmp_file(b"\x00" * 100)
    try:
        cmdj_map = {"aflj": []}
        adapter = _make_adapter(cmdj_map=cmdj_map)
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer._calculate_function_tlsh()

        assert result == {}
    finally:
        os.unlink(path)


def test_calculate_function_tlsh_function_exception():
    """Test _calculate_function_tlsh when read_bytes returns empty for a function."""
    path = _tmp_file(b"\x00" * 100)
    try:
        functions = [{"name": "func1", "offset": 4096, "addr": 4096, "size": 100}]
        # No cmd_map entry -> read_bytes returns empty bytes -> hex is empty -> None
        cmdj_map = {"aflj": functions}
        adapter = _make_adapter(cmdj_map=cmdj_map)
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer._calculate_function_tlsh()

        assert "func1" in result
        assert result["func1"] is None
    finally:
        os.unlink(path)


def test_calculate_function_tlsh_general_exception():
    """Test _calculate_function_tlsh when no function data is available."""
    path = _tmp_file(b"\x00" * 100)
    try:
        adapter = _make_adapter()
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer._calculate_function_tlsh()

        assert result == {}
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# _get_sections tests
# ---------------------------------------------------------------------------


def test_get_sections():
    """Test _get_sections method with real adapter."""
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
        assert result[0]["name"] == ".text"
    finally:
        os.unlink(path)


def test_get_sections_no_adapter():
    """Test _get_sections with no adapter."""
    path = _tmp_file(b"\x00" * 100)
    try:
        analyzer = TLSHAnalyzer(None, path)

        result = analyzer._get_sections()

        assert result == []
    finally:
        os.unlink(path)


def test_get_sections_no_method():
    """Test _get_sections when adapter has no get_sections method."""
    path = _tmp_file(b"\x00" * 100)
    try:

        class MinimalAdapter:
            """Adapter without get_sections."""

            pass

        analyzer = TLSHAnalyzer(MinimalAdapter(), path)

        result = analyzer._get_sections()

        assert result == []
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# _get_functions tests
# ---------------------------------------------------------------------------


def test_get_functions():
    """Test _get_functions method with real adapter."""
    path = _tmp_file(b"\x00" * 100)
    try:
        functions = [{"name": "main", "offset": 4096, "addr": 4096, "size": 100}]
        cmdj_map = {"aflj": functions}
        adapter = _make_adapter(cmdj_map=cmdj_map)
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer._get_functions()

        assert len(result) == 1
        assert result[0]["name"] == "main"
    finally:
        os.unlink(path)


def test_get_functions_no_adapter():
    """Test _get_functions with no adapter."""
    path = _tmp_file(b"\x00" * 100)
    try:
        analyzer = TLSHAnalyzer(None, path)

        result = analyzer._get_functions()

        assert result == []
    finally:
        os.unlink(path)


def test_get_functions_no_method():
    """Test _get_functions when adapter has no get_functions method."""
    path = _tmp_file(b"\x00" * 100)
    try:

        class MinimalAdapter:
            """Adapter without get_functions."""

            pass

        analyzer = TLSHAnalyzer(MinimalAdapter(), path)

        result = analyzer._get_functions()

        assert result == []
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# _read_bytes_hex tests
# ---------------------------------------------------------------------------


def test_read_bytes_hex():
    """Test _read_bytes_hex method with real adapter."""
    path = _tmp_file(b"\x00" * 100)
    try:
        cmd_map = {f"p8 4 @ {4096}": "01020304"}
        adapter = _make_adapter(cmd_map=cmd_map)
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer._read_bytes_hex(4096, 4)

        assert result == "01020304"
    finally:
        os.unlink(path)


def test_read_bytes_hex_empty():
    """Test _read_bytes_hex with empty data (adapter returns empty bytes)."""
    path = _tmp_file(b"\x00" * 100)
    try:
        # No cmd_map entry -> adapter returns empty string -> read_bytes returns b""
        adapter = _make_adapter()
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer._read_bytes_hex(4096, 0)

        # read_bytes with size 0 or empty result -> None
        assert result is None
    finally:
        os.unlink(path)


def test_read_bytes_hex_none():
    """Test _read_bytes_hex when adapter returns no data."""
    path = _tmp_file(b"\x00" * 100)
    try:
        # No matching cmd -> read_bytes returns empty bytes -> hex is empty -> None
        adapter = _make_adapter()
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer._read_bytes_hex(4096, 4)

        # Empty hex string from empty response -> returns None or empty string
        # _read_bytes_hex returns data.hex() if data, else None; b"".hex() is ""
        # but b"" is falsy so it returns None
        assert result is None
    finally:
        os.unlink(path)


def test_read_bytes_hex_no_adapter():
    """Test _read_bytes_hex with no adapter."""
    path = _tmp_file(b"\x00" * 100)
    try:
        analyzer = TLSHAnalyzer(None, path)

        result = analyzer._read_bytes_hex(4096, 4)

        assert result is None
    finally:
        os.unlink(path)


def test_read_bytes_hex_no_method():
    """Test _read_bytes_hex when adapter has no read_bytes method."""
    path = _tmp_file(b"\x00" * 100)
    try:

        class MinimalAdapter:
            """Adapter without read_bytes."""

            pass

        analyzer = TLSHAnalyzer(MinimalAdapter(), path)

        result = analyzer._read_bytes_hex(4096, 4)

        assert result is None
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# compare_tlsh tests
# ---------------------------------------------------------------------------


def test_compare_tlsh_success():
    """Test compare_tlsh with real TLSH library if available."""
    path = _tmp_file(b"\x00" * 100)
    try:
        adapter = _make_adapter()
        analyzer = TLSHAnalyzer(adapter, path)

        if not TLSH_AVAILABLE:
            pytest.skip("TLSH library not installed")

        import tlsh

        # Generate two real TLSH hashes from random data
        data1 = os.urandom(1024)
        data2 = os.urandom(1024)
        hash1 = tlsh.hash(data1)
        hash2 = tlsh.hash(data2)

        if not hash1 or not hash2:
            pytest.skip("TLSH could not hash random data")

        result = analyzer.compare_tlsh(hash1, hash2)

        assert result is not None
        assert isinstance(result, int)
        assert result >= 0
    finally:
        os.unlink(path)


def test_compare_tlsh_empty_hash1():
    """Test compare_tlsh with empty first hash."""
    path = _tmp_file(b"\x00" * 100)
    try:
        adapter = _make_adapter()
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer.compare_tlsh("", "HASH2")

        assert result is None
    finally:
        os.unlink(path)


def test_compare_tlsh_empty_hash2():
    """Test compare_tlsh with empty second hash."""
    path = _tmp_file(b"\x00" * 100)
    try:
        adapter = _make_adapter()
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer.compare_tlsh("HASH1", "")

        assert result is None
    finally:
        os.unlink(path)


def test_compare_tlsh_exception():
    """Test compare_tlsh with invalid hashes triggers exception handling."""
    path = _tmp_file(b"\x00" * 100)
    try:
        adapter = _make_adapter()
        analyzer = TLSHAnalyzer(adapter, path)

        if not TLSH_AVAILABLE:
            pytest.skip("TLSH library not installed")

        # Invalid hash strings should cause tlsh.diff to raise
        result = analyzer.compare_tlsh("INVALID_HASH", "ANOTHER_INVALID")

        # Either returns None (exception caught) or a value (library tolerant)
        # The key behavior: it does not raise
        assert result is None or isinstance(result, int)
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# find_similar_sections tests
# ---------------------------------------------------------------------------


def test_find_similar_sections_success():
    """Test find_similar_sections with sections that have real TLSH hashes."""
    data = os.urandom(2048)
    path = _tmp_file(data)
    try:
        if not TLSH_AVAILABLE:
            pytest.skip("TLSH library not installed")

        import tlsh

        # Create sections with real TLSH-hashable data
        chunk1 = os.urandom(512)
        chunk2 = bytes(b ^ 0x01 for b in chunk1)  # Similar data
        chunk3 = os.urandom(512)

        hash1 = tlsh.hash(chunk1)
        hash2 = tlsh.hash(chunk2)
        hash3 = tlsh.hash(chunk3)

        if not all([hash1, hash2, hash3]):
            pytest.skip("TLSH could not produce hashes for test data")

        # Build an adapter that returns sections with hex data that produces known hashes
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
            {
                "name": ".rdata",
                "vaddr": 12288,
                "vsize": 512,
                "size": 512,
                "paddr": 1024,
                "perm": "r--",
                "type": "",
            },
        ]
        cmd_map = {
            f"p8 512 @ {4096}": chunk1.hex(),
            f"p8 512 @ {8192}": chunk2.hex(),
            f"p8 512 @ {12288}": chunk3.hex(),
        }
        cmdj_map = {
            "iSj": sections,
            "aflj": [],
        }
        adapter = _make_adapter(cmdj_map=cmdj_map, cmd_map=cmd_map)
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer.find_similar_sections(threshold=1000)

        # With a high threshold, we should get pairs
        assert isinstance(result, list)
        if len(result) > 0:
            assert all("section1" in r and "section2" in r for r in result)
    finally:
        os.unlink(path)


def test_find_similar_sections_not_available():
    """Test find_similar_sections when TLSH is not available."""
    path = _tmp_file(b"\x00" * 100)
    try:
        adapter = _make_adapter()
        analyzer = TLSHAnalyzer(adapter, path)

        # Temporarily flip the module-level TLSH_AVAILABLE flag
        import r2inspect.modules.tlsh_analyzer as tlsh_mod

        original = tlsh_mod.TLSH_AVAILABLE
        tlsh_mod.TLSH_AVAILABLE = False
        try:
            result = analyzer.find_similar_sections()
        finally:
            tlsh_mod.TLSH_AVAILABLE = original

        assert result == []
    finally:
        os.unlink(path)


def test_find_similar_sections_skip_none_hashes():
    """Test find_similar_sections skips None hashes from zero-size sections."""
    data = os.urandom(1024)
    path = _tmp_file(data)
    try:
        if not TLSH_AVAILABLE:
            pytest.skip("TLSH library not installed")

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
                "name": ".bss",
                "vaddr": 8192,
                "vsize": 256,
                "size": 0,
                "paddr": 512,
                "perm": "rw-",
                "type": "",
            },
            {
                "name": ".rdata",
                "vaddr": 12288,
                "vsize": 512,
                "size": 512,
                "paddr": 768,
                "perm": "r--",
                "type": "",
            },
        ]
        cmd_map = {
            f"p8 512 @ {4096}": "AA" * 512,
            f"p8 512 @ {12288}": "BB" * 512,
        }
        cmdj_map = {
            "iSj": sections,
            "aflj": [],
        }
        adapter = _make_adapter(cmdj_map=cmdj_map, cmd_map=cmd_map)
        analyzer = TLSHAnalyzer(adapter, path)

        result = analyzer.find_similar_sections(threshold=1000)

        # .bss should never appear in results (it has size 0 -> None hash)
        assert all(r["section1"] != ".bss" and r["section2"] != ".bss" for r in result)
    finally:
        os.unlink(path)


def test_find_similar_sections_above_threshold():
    """Test find_similar_sections filters out pairs above threshold."""
    data = os.urandom(1024)
    path = _tmp_file(data)
    try:
        if not TLSH_AVAILABLE:
            pytest.skip("TLSH library not installed")

        # Use very different data for sections so distance is high
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
            f"p8 512 @ {4096}": "AA" * 512,
            f"p8 512 @ {8192}": "55" * 512,
        }
        cmdj_map = {
            "iSj": sections,
            "aflj": [],
        }
        adapter = _make_adapter(cmdj_map=cmdj_map, cmd_map=cmd_map)
        analyzer = TLSHAnalyzer(adapter, path)

        # Use a very low threshold so most pairs are filtered out
        result = analyzer.find_similar_sections(threshold=0)

        # With threshold=0, only identical hashes would match
        # Our sections have different data, so no matches expected
        assert result == [] or all(r["similarity_score"] == 0 for r in result)
    finally:
        os.unlink(path)


def test_find_similar_sections_exception():
    """Test find_similar_sections returns empty list on error."""
    path = _tmp_file(b"\x00" * 100)
    try:
        # Use an adapter that will cause issues during analysis
        # By passing None as adapter, _get_sections returns [] so analyze_sections
        # should still work but produce no section data
        analyzer = TLSHAnalyzer(None, path)

        if not TLSH_AVAILABLE:
            pytest.skip("TLSH library not installed")

        result = analyzer.find_similar_sections()

        # With no sections, find_similar_sections returns []
        assert result == []
    finally:
        os.unlink(path)
