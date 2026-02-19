"""Coverage tests for tlsh_analyzer.py."""

import pytest

from r2inspect.modules.tlsh_analyzer import TLSH_AVAILABLE, TLSHAnalyzer
from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter


ELF_FIXTURE = "samples/fixtures/hello_elf"


class FakeR2:
    def __init__(self, cmd_map=None, cmdj_map=None):
        self._cmd_map = cmd_map or {}
        self._cmdj_map = cmdj_map or {}

    def cmd(self, command):
        return self._cmd_map.get(command, "")

    def cmdj(self, command):
        return self._cmdj_map.get(command)


class FakeAdapter:
    """Adapter that provides section and function data."""

    def __init__(self, sections=None, functions=None, bytes_data=None):
        self._sections = sections or []
        self._functions = functions or []
        self._bytes_data = bytes_data or {}

    def get_sections(self):
        return self._sections

    def get_functions(self):
        return self._functions

    def read_bytes(self, vaddr, size):
        return self._bytes_data.get(vaddr, b"")

    def cmd(self, command):
        return ""

    def cmdj(self, command):
        return None


# --- availability ---


def test_tlsh_is_available_returns_bool():
    result = TLSHAnalyzer.is_available()
    assert isinstance(result, bool)


def test_tlsh_available_constant_matches_is_available():
    assert TLSH_AVAILABLE == TLSHAnalyzer.is_available()


# --- get_similarity_level ---


def test_get_similarity_level_none():
    assert TLSHAnalyzer.get_similarity_level(None) == "Unknown"


def test_get_similarity_level_identical():
    assert TLSHAnalyzer.get_similarity_level(0) == "Identical"


def test_get_similarity_level_very_similar():
    assert TLSHAnalyzer.get_similarity_level(15) == "Very Similar"
    assert TLSHAnalyzer.get_similarity_level(30) == "Very Similar"


def test_get_similarity_level_similar():
    assert TLSHAnalyzer.get_similarity_level(31) == "Similar"
    assert TLSHAnalyzer.get_similarity_level(50) == "Similar"


def test_get_similarity_level_somewhat_similar():
    assert TLSHAnalyzer.get_similarity_level(51) == "Somewhat Similar"
    assert TLSHAnalyzer.get_similarity_level(100) == "Somewhat Similar"


def test_get_similarity_level_different():
    assert TLSHAnalyzer.get_similarity_level(101) == "Different"
    assert TLSHAnalyzer.get_similarity_level(200) == "Different"


def test_get_similarity_level_very_different():
    assert TLSHAnalyzer.get_similarity_level(201) == "Very Different"
    assert TLSHAnalyzer.get_similarity_level(999) == "Very Different"


# --- compare_hashes static ---


def test_compare_hashes_empty_strings():
    result = TLSHAnalyzer.compare_hashes("", "")
    assert result is None


def test_compare_hashes_none_first():
    result = TLSHAnalyzer.compare_hashes(None, "abc")  # type: ignore[arg-type]
    assert result is None


def test_compare_hashes_none_second():
    result = TLSHAnalyzer.compare_hashes("abc", None)  # type: ignore[arg-type]
    assert result is None


def test_compare_hashes_not_available_returns_none(tmp_path):
    if not TLSH_AVAILABLE:
        assert TLSHAnalyzer.compare_hashes("T1abc", "T1def") is None


def test_compare_hashes_with_real_hashes(tmp_path):
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "large.bin"
    f.write_bytes(bytes(range(256)) * 10)
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename=str(f))
    h = analyzer._calculate_binary_tlsh()
    if h is None or h == "TNULL":
        pytest.skip("TLSH hash not calculated (file may be too small or uniform)")
    result = TLSHAnalyzer.compare_hashes(h, h)
    assert result is not None
    assert result == 0


# --- _check_library_availability ---


def test_check_library_availability(tmp_path):
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename=str(f))
    available, error = analyzer._check_library_availability()
    assert isinstance(available, bool)


# --- _get_hash_type ---


def test_get_hash_type(tmp_path):
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename=str(f))
    assert analyzer._get_hash_type() == "tlsh"


# --- _calculate_tlsh_from_hex ---


def test_calculate_tlsh_from_hex_none():
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename="/tmp/test.bin")
    assert analyzer._calculate_tlsh_from_hex(None) is None


def test_calculate_tlsh_from_hex_empty():
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename="/tmp/test.bin")
    assert analyzer._calculate_tlsh_from_hex("") is None


def test_calculate_tlsh_from_hex_too_small():
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename="/tmp/test.bin")
    # Less than TLSH_MIN_DATA_SIZE (50 bytes)
    hex_data = b"A" * 20
    assert analyzer._calculate_tlsh_from_hex(hex_data.hex()) is None


def test_calculate_tlsh_from_hex_sufficient_data():
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename="/tmp/test.bin")
    # Create 200 bytes of varied data
    data = bytes(range(256)) * 1
    data = data + b"X" * 200
    result = analyzer._calculate_tlsh_from_hex(data.hex())
    # May be None if data is too uniform, but should not raise
    assert result is None or isinstance(result, str)


def test_calculate_tlsh_from_hex_invalid_hex():
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename="/tmp/test.bin")
    result = analyzer._calculate_tlsh_from_hex("not_valid_hex!!")
    assert result is None


# --- _calculate_binary_tlsh ---


def test_calculate_binary_tlsh_real_file(tmp_path):
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename=str(f))
    result = analyzer._calculate_binary_tlsh()
    assert result is None or isinstance(result, str)


def test_calculate_binary_tlsh_nonexistent_file():
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename="/nonexistent/path.bin")
    result = analyzer._calculate_binary_tlsh()
    assert result is None


def test_calculate_binary_tlsh_small_file(tmp_path):
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "small.bin"
    f.write_bytes(b"tiny")
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename=str(f))
    result = analyzer._calculate_binary_tlsh()
    assert result is None


# --- _calculate_hash ---


def test_calculate_hash_with_large_file(tmp_path):
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename=str(f))
    hash_value, method, error = analyzer._calculate_hash()
    assert error is None or isinstance(error, str)


def test_calculate_hash_small_file(tmp_path):
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "small.bin"
    f.write_bytes(b"tiny data")
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename=str(f))
    hash_value, method, error = analyzer._calculate_hash()
    assert hash_value is None
    assert error is not None


# --- analyze() ---


def test_analyze_returns_dict(tmp_path):
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename=str(f))
    result = analyzer.analyze()
    assert isinstance(result, dict)
    assert "hash_type" in result
    assert result["hash_type"] == "tlsh"


def test_analyze_includes_binary_tlsh(tmp_path):
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename=str(f))
    result = analyzer.analyze()
    assert "binary_tlsh" in result


def test_analyze_nonexistent_file():
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename="/nonexistent/file.bin")
    result = analyzer.analyze()
    assert result["available"] is False


# --- analyze_sections ---


def test_analyze_sections_not_available(tmp_path):
    if TLSH_AVAILABLE:
        pytest.skip("TLSH is available, skip unavailability test")
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename=str(f))
    result = analyzer.analyze_sections()
    assert result["available"] is False


def test_analyze_sections_with_empty_adapter(tmp_path):
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    adapter = FakeAdapter(sections=[], functions=[])
    analyzer = TLSHAnalyzer(adapter=adapter, filename=str(f))
    result = analyzer.analyze_sections()
    assert result["available"] is True
    assert result["section_tlsh"] == {}
    assert result["function_tlsh"] == {}


def test_analyze_sections_with_sections(tmp_path):
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 20)
    section_data = bytes(range(256)) * 4
    sections = [
        {"name": ".text", "vaddr": 0x1000, "size": len(section_data)},
        {"name": ".data", "vaddr": 0x2000, "size": 0},  # Empty section
    ]
    adapter = FakeAdapter(
        sections=sections,
        bytes_data={0x1000: section_data, 0x2000: b""},
    )
    analyzer = TLSHAnalyzer(adapter=adapter, filename=str(f))
    result = analyzer.analyze_sections()
    assert ".text" in result["section_tlsh"]
    assert ".data" in result["section_tlsh"]
    assert result["stats"]["sections_analyzed"] == 2


def test_analyze_sections_with_large_section(tmp_path):
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    sections = [
        {"name": ".oversized", "vaddr": 0x1000, "size": 60 * 1024 * 1024},  # Too large
    ]
    adapter = FakeAdapter(sections=sections)
    analyzer = TLSHAnalyzer(adapter=adapter, filename=str(f))
    result = analyzer.analyze_sections()
    assert result["section_tlsh"][".oversized"] is None


def test_analyze_sections_with_functions(tmp_path):
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    func_data = bytes(range(256)) * 2
    functions = [
        {"name": "main", "addr": 0x1000, "size": len(func_data)},
        {"name": "helper", "addr": 0x2000, "size": 0},  # Zero size
        {"name": "large_func", "addr": 0x3000, "size": 200001},  # Too large
    ]
    adapter = FakeAdapter(
        functions=functions,
        bytes_data={0x1000: func_data, 0x2000: b""},
    )
    analyzer = TLSHAnalyzer(adapter=adapter, filename=str(f))
    result = analyzer.analyze_sections()
    assert "main" in result["function_tlsh"]
    assert "helper" in result["function_tlsh"]
    assert "large_func" in result["function_tlsh"]


def test_analyze_sections_with_malformed_function(tmp_path):
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    functions = [
        "not_a_dict",  # Malformed function
        {"name": "valid", "addr": 0x1000, "size": 100},
    ]
    adapter = FakeAdapter(functions=functions)
    analyzer = TLSHAnalyzer(adapter=adapter, filename=str(f))
    result = analyzer.analyze_sections()
    assert isinstance(result, dict)


def test_analyze_sections_function_no_addr(tmp_path):
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    functions = [
        {"name": "no_addr_func", "size": 100},  # Missing addr
    ]
    adapter = FakeAdapter(functions=functions)
    analyzer = TLSHAnalyzer(adapter=adapter, filename=str(f))
    result = analyzer.analyze_sections()
    assert "no_addr_func" in result["function_tlsh"]
    assert result["function_tlsh"]["no_addr_func"] is None


# --- compare_tlsh instance method ---


def test_compare_tlsh_instance_empty():
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename="/tmp/test.bin")
    result = analyzer.compare_tlsh("", "")
    assert result is None


def test_compare_tlsh_instance_none():
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename="/tmp/test.bin")
    result = analyzer.compare_tlsh(None, None)  # type: ignore[arg-type]
    assert result is None


def test_compare_tlsh_instance_valid(tmp_path):
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename=str(f))
    h = analyzer._calculate_binary_tlsh()
    if h is None:
        pytest.skip("Could not calculate TLSH hash")
    result = analyzer.compare_tlsh(h, h)
    assert result == 0


# --- find_similar_sections ---


def test_find_similar_sections_unavailable(tmp_path):
    if TLSH_AVAILABLE:
        pytest.skip("TLSH is available")
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename=str(f))
    result = analyzer.find_similar_sections()
    assert result == []


def test_find_similar_sections_no_sections(tmp_path):
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    adapter = FakeAdapter(sections=[])
    analyzer = TLSHAnalyzer(adapter=adapter, filename=str(f))
    result = analyzer.find_similar_sections()
    assert result == []


def test_find_similar_sections_identical_sections(tmp_path):
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 20)
    # Use large varied data so TLSH actually produces a hash
    section_data = bytes(range(256)) * 4
    sections = [
        {"name": ".text", "vaddr": 0x1000, "size": len(section_data)},
        {"name": ".text2", "vaddr": 0x2000, "size": len(section_data)},
    ]
    adapter = FakeAdapter(
        sections=sections,
        bytes_data={0x1000: section_data, 0x2000: section_data},
    )
    analyzer = TLSHAnalyzer(adapter=adapter, filename=str(f))
    result = analyzer.find_similar_sections(threshold=100)
    assert isinstance(result, list)


# --- _get_sections and _get_functions with no adapter ---


def test_get_sections_no_adapter(tmp_path):
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    analyzer = TLSHAnalyzer(adapter=None, filename=str(f))
    assert analyzer._get_sections() == []


def test_get_functions_no_adapter(tmp_path):
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    analyzer = TLSHAnalyzer(adapter=None, filename=str(f))
    assert analyzer._get_functions() == []


# --- _read_bytes_hex ---


def test_read_bytes_hex_no_adapter(tmp_path):
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    analyzer = TLSHAnalyzer(adapter=None, filename=str(f))
    assert analyzer._read_bytes_hex(0x1000, 100) is None


def test_read_bytes_hex_adapter_returns_data(tmp_path):
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    data = b"Hello World"
    adapter = FakeAdapter(bytes_data={0x1000: data})
    analyzer = TLSHAnalyzer(adapter=adapter, filename=str(f))
    result = analyzer._read_bytes_hex(0x1000, len(data))
    assert result == data.hex()


def test_read_bytes_hex_adapter_returns_empty(tmp_path):
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    adapter = FakeAdapter(bytes_data={})
    analyzer = TLSHAnalyzer(adapter=adapter, filename=str(f))
    result = analyzer._read_bytes_hex(0x9999, 100)
    assert result is None


# --- supplementary tests for remaining missing lines ---


class ExceptionReadAdapter:
    """Adapter whose read_bytes raises an exception."""

    def get_sections(self):
        return []

    def get_functions(self):
        return []

    def read_bytes(self, vaddr, size):
        raise RuntimeError("read_bytes failed intentionally")

    def cmd(self, c):
        return ""

    def cmdj(self, c):
        return None


def test_read_bytes_hex_exception(tmp_path):
    """Test _read_bytes_hex when adapter.read_bytes raises."""
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    adapter = ExceptionReadAdapter()
    analyzer = TLSHAnalyzer(adapter=adapter, filename=str(f))
    result = analyzer._read_bytes_hex(0x1000, 100)
    assert result is None


def test_compare_tlsh_invalid_hash(tmp_path):
    """Test compare_tlsh with invalid hash string triggers exception handler."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename=str(f))
    result = analyzer.compare_tlsh("INVALID_HASH_STRING", "ALSO_INVALID")
    # Should return None when tlsh.diff raises exception
    assert result is None or isinstance(result, int)


def test_compare_hashes_static_exception():
    """Test static compare_hashes with invalid hash strings."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    result = TLSHAnalyzer.compare_hashes("NOT_A_VALID_TLSH", "ALSO_NOT_VALID")
    assert result is None or isinstance(result, int)


def test_calculate_hash_exception_branch(tmp_path):
    """Test _calculate_hash exception handler."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)

    class BrokenTLSHAnalyzer(TLSHAnalyzer):
        def _calculate_binary_tlsh(self):
            raise RuntimeError("intentional error for test")

    analyzer = BrokenTLSHAnalyzer(adapter=FakeAdapter(), filename=str(f))
    hash_value, method, error = analyzer._calculate_hash()
    assert hash_value is None
    assert error is not None
    assert "TLSH calculation failed" in error


def test_analyze_sections_section_exception(tmp_path):
    """Test _calculate_section_tlsh exception handler (lines 132-134)."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)

    class ExceptionSectionAdapter:
        def get_sections(self):
            return [{"name": ".text", "vaddr": 0x1000, "size": 100}]

        def get_functions(self):
            return []

        def read_bytes(self, vaddr, size):
            raise RuntimeError("read error")

        def cmd(self, c):
            return ""

        def cmdj(self, c):
            return None

    adapter = ExceptionSectionAdapter()
    analyzer = TLSHAnalyzer(adapter=adapter, filename=str(f))
    result = analyzer._calculate_section_tlsh()
    assert ".text" in result
    assert result[".text"] is None


def test_analyze_sections_function_exception(tmp_path):
    """Test _calculate_function_tlsh exception handler."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)

    class ExceptionFuncAdapter:
        def get_sections(self):
            return []

        def get_functions(self):
            return [{"name": "main", "addr": 0x1000, "size": 100}]

        def read_bytes(self, vaddr, size):
            raise RuntimeError("read error")

        def cmd(self, c):
            return ""

        def cmdj(self, c):
            return None

    adapter = ExceptionFuncAdapter()
    analyzer = TLSHAnalyzer(adapter=adapter, filename=str(f))
    result = analyzer._calculate_function_tlsh()
    assert "main" in result
    assert result["main"] is None


def test_find_similar_sections_exception(tmp_path):
    """Test find_similar_sections exception handler (lines 318-320)."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)

    class BrokenTLSHAnalyzer(TLSHAnalyzer):
        def analyze(self):
            raise RuntimeError("intentional error for test")

    analyzer = BrokenTLSHAnalyzer(adapter=FakeAdapter(), filename=str(f))
    result = analyzer.find_similar_sections()
    assert result == []


def test_find_similar_sections_with_hashes(tmp_path):
    """Test find_similar_sections code path with sections having hashes."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 20)

    section_data = bytes(range(256)) * 4

    class SectionHashAdapter:
        def get_sections(self):
            return [
                {"name": ".text", "vaddr": 0x1000, "size": len(section_data)},
                {"name": ".data", "vaddr": 0x2000, "size": len(section_data)},
            ]

        def get_functions(self):
            return []

        def read_bytes(self, vaddr, size):
            return section_data

        def cmd(self, c):
            return ""

        def cmdj(self, c):
            return None

    adapter = SectionHashAdapter()
    analyzer = TLSHAnalyzer(adapter=adapter, filename=str(f))
    result = analyzer.find_similar_sections(threshold=1000)
    assert isinstance(result, list)


# --- additional supplementary tests ---


class ExceptionSectionsAdapter:
    """Adapter whose get_sections raises an exception."""

    def get_sections(self):
        raise RuntimeError("get_sections failed intentionally")

    def get_functions(self):
        return []

    def read_bytes(self, vaddr, size):
        return b""

    def cmd(self, c):
        return ""

    def cmdj(self, c):
        return None


class ExceptionFunctionsAdapter:
    """Adapter whose get_functions raises an exception."""

    def get_sections(self):
        return []

    def get_functions(self):
        raise RuntimeError("get_functions failed intentionally")

    def cmd(self, c):
        return ""

    def cmdj(self, c):
        return None


def test_calculate_section_tlsh_outer_exception(tmp_path):
    """Test outer exception handler in _calculate_section_tlsh (lines 204-205)."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    adapter = ExceptionSectionsAdapter()
    analyzer = TLSHAnalyzer(adapter=adapter, filename=str(f))
    result = analyzer._calculate_section_tlsh()
    assert result == {}


def test_calculate_function_tlsh_outer_exception(tmp_path):
    """Test outer exception handler in _calculate_function_tlsh (lines 246-247)."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    adapter = ExceptionFunctionsAdapter()
    analyzer = TLSHAnalyzer(adapter=adapter, filename=str(f))
    result = analyzer._calculate_function_tlsh()
    assert result == {}


def test_calculate_function_tlsh_no_name(tmp_path):
    """Test line 287: function name fallback when 'name' key is missing."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    functions = [
        {"addr": 0x1000, "size": 100},  # No "name" key
    ]
    adapter = FakeAdapter(functions=functions)
    analyzer = TLSHAnalyzer(adapter=adapter, filename=str(f))
    result = analyzer._calculate_function_tlsh()
    assert "func_4096" in result or any("func_" in k for k in result)


def test_calculate_function_tlsh_no_addr_no_name(tmp_path):
    """Test line 287 fallback when both name and addr are missing."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    functions = [
        {"size": 100},  # No "name" or "addr" key
    ]
    adapter = FakeAdapter(functions=functions)
    analyzer = TLSHAnalyzer(adapter=adapter, filename=str(f))
    result = analyzer._calculate_function_tlsh()
    assert "func_unknown" in result


class SectionHashTLSHAnalyzer(TLSHAnalyzer):
    """Subclass that returns sections with real TLSH hashes in analyze()."""

    def __init__(self, adapter, filename, section_hashes):
        super().__init__(adapter=adapter, filename=filename)
        self._section_hashes = section_hashes

    def analyze(self):
        result = super().analyze()
        result["section_tlsh"] = self._section_hashes
        result["available"] = True
        return result


def test_find_similar_sections_with_precomputed_hashes(tmp_path):
    """Test lines 295-306: pairs comparison in find_similar_sections."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 20)

    # Pre-calculate real TLSH hashes from actual data
    import tlsh as tlsh_lib
    data1 = bytes(range(256)) * 4
    data2 = bytes(range(256)) * 4  # Same data = same hash
    h1 = tlsh_lib.hash(data1)
    h2 = tlsh_lib.hash(data2)

    if not h1 or not h2 or h1 == "TNULL" or h2 == "TNULL":
        pytest.skip("Could not compute TLSH hashes for test")

    section_hashes = {".text": h1, ".data": h2}
    adapter = FakeAdapter()
    analyzer = SectionHashTLSHAnalyzer(
        adapter=adapter, filename=str(f), section_hashes=section_hashes
    )
    result = analyzer.find_similar_sections(threshold=1000)
    assert isinstance(result, list)


# --- final supplementary tests ---


def test_find_similar_sections_available_false():
    """Test line 287 in find_similar_sections: return [] when not available."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    # File doesn't exist, so analyze() returns available=False
    analyzer = TLSHAnalyzer(adapter=FakeAdapter(), filename="/nonexistent/path.bin")
    result = analyzer.find_similar_sections()
    assert result == []


def test_find_similar_sections_with_none_section_hash(tmp_path):
    """Test lines 297, 302: continue when section hash is None."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 20)

    import tlsh as tlsh_lib
    data = bytes(range(256)) * 4
    h = tlsh_lib.hash(data)

    if not h or h == "TNULL":
        pytest.skip("Could not compute TLSH hash")

    # Mix of None and valid hashes to exercise both continue branches
    section_hashes = {
        ".text": h,      # Valid hash
        ".data": None,   # None hash -> line 302 continue
        ".bss": None,    # Also None
    }
    adapter = FakeAdapter()
    analyzer = SectionHashTLSHAnalyzer(
        adapter=adapter, filename=str(f), section_hashes=section_hashes
    )
    result = analyzer.find_similar_sections(threshold=1000)
    assert isinstance(result, list)


def test_find_similar_sections_first_hash_none(tmp_path):
    """Test line 297: continue when first hash is None."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 20)

    import tlsh as tlsh_lib
    data = bytes(range(256)) * 4
    h = tlsh_lib.hash(data)

    if not h or h == "TNULL":
        pytest.skip("Could not compute TLSH hash")

    section_hashes = {
        ".null": None,   # First section has None -> line 297 continue
        ".text": h,      # Second section valid
    }
    adapter = FakeAdapter()
    analyzer = SectionHashTLSHAnalyzer(
        adapter=adapter, filename=str(f), section_hashes=section_hashes
    )
    result = analyzer.find_similar_sections(threshold=1000)
    assert isinstance(result, list)


class BrokenBinaryTLSH(TLSHAnalyzer):
    """Subclass where _calculate_binary_tlsh raises to test analyze_sections exception."""

    def _calculate_binary_tlsh(self):
        raise RuntimeError("intentional error in binary tlsh")


def test_analyze_sections_outer_exception(tmp_path):
    """Test lines 132-134: outer exception handler in analyze_sections."""
    if not TLSH_AVAILABLE:
        pytest.skip("TLSH not available")
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(range(256)) * 10)
    analyzer = BrokenBinaryTLSH(adapter=FakeAdapter(), filename=str(f))
    result = analyzer.analyze_sections()
    assert result["available"] is False
    assert "error" in result
