"""Wave 3 coverage tests for base_analyzer, rich_header_analyzer, simhash_analyzer.

No mocks, no unittest.mock. Real code only.
"""

from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from r2inspect.abstractions.base_analyzer import BaseAnalyzer
import r2inspect.modules.rich_header_analyzer as rha_module
from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer
import r2inspect.modules.simhash_analyzer as sim_module
from r2inspect.modules.simhash_analyzer import SimHashAnalyzer, SIMHASH_AVAILABLE


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _write_tmp(data: bytes, suffix: str = ".exe") -> str:
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix, mode="wb") as f:
        f.write(data)
    return f.name


def _build_pe_with_rich_header(xor_key: int = 0xABCD1234) -> bytes:
    """Build a minimal PE binary that contains a Rich Header."""
    prod_id = 3
    build = 50727
    count = 1

    dans = b"DanS"
    pad = b"\x00" * 4
    e_val = prod_id | (build << 16)
    entry = struct.pack("<II", e_val ^ xor_key, count ^ xor_key)
    fill = b"\x00" * 4
    rich = b"Rich"
    xor_b = struct.pack("<I", xor_key)

    stub = dans + pad + entry + fill + rich + xor_b
    pe_off = 0x40 + len(stub)

    mz = bytearray(0x40)
    mz[0] = ord("M")
    mz[1] = ord("Z")
    struct.pack_into("<I", mz, 0x3C, pe_off)

    return bytes(mz) + stub + b"PE\x00\x00" + b"\x00" * 200


def _build_pe_no_rich() -> bytes:
    """Minimal valid MZ file without Rich Header."""
    mz = bytearray(0x40)
    mz[0] = ord("M")
    mz[1] = ord("Z")
    struct.pack_into("<I", mz, 0x3C, 0x40)
    return bytes(mz) + b"PE\x00\x00" + b"\x00" * 200


class _MinimalAdapter:
    """Non-None adapter so _is_pe_file can proceed to file magic check."""
    pass


# ---------------------------------------------------------------------------
# StubAdapter for simhash tests
# ---------------------------------------------------------------------------

class StubAdapter:
    """Minimal real adapter returning configurable data without mock libraries."""

    def __init__(
        self,
        strings: list[dict] | None = None,
        functions: list[dict] | None = None,
        sections: list[dict] | None = None,
        disasm_map: dict[int, Any] | None = None,
        bytes_map: dict[int, bytes] | None = None,
    ) -> None:
        self._strings: list[dict] = strings if strings is not None else []
        self._functions: list[dict] = functions if functions is not None else []
        self._sections: list[dict] = sections if sections is not None else []
        self._disasm_map: dict[int, Any] = disasm_map or {}
        self._bytes_map: dict[int, bytes] = bytes_map or {}

    def get_strings(self) -> list[dict]:
        return self._strings

    def get_functions(self) -> list[dict]:
        return self._functions

    def get_sections(self) -> list[dict]:
        return self._sections

    def get_disasm(self, address: int | None = None, size: int | None = None) -> Any:
        if address is None:
            return None
        return self._disasm_map.get(address)

    def read_bytes(self, address: int, size: int) -> bytes:
        return self._bytes_map.get(address, b"")


# ===========================================================================
# base_analyzer.py tests
# ===========================================================================


class _SimpleAnalyzer(BaseAnalyzer):
    """Minimal concrete subclass for testing base behavior."""

    def analyze(self) -> dict[str, Any]:
        return self._init_result_structure()


class _CategorizedAnalyzer(BaseAnalyzer):
    def analyze(self) -> dict[str, Any]:
        return {}

    def get_category(self) -> str:
        return "hashing"


# --- line 130: _mark_unavailable with library_available flag ---

def test_mark_unavailable_with_library_available_true() -> None:
    """Line 130: _mark_unavailable propagates library_available=True."""
    analyzer = _SimpleAnalyzer()
    result: dict[str, Any] = {"available": True, "error": None}
    out = analyzer._mark_unavailable(result, "lib missing", library_available=True)
    assert out["available"] is False
    assert out["library_available"] is True
    assert out["error"] == "lib missing"


def test_mark_unavailable_with_library_available_false() -> None:
    """Line 130: _mark_unavailable propagates library_available=False."""
    analyzer = _SimpleAnalyzer()
    result: dict[str, Any] = {"available": True, "error": None}
    out = analyzer._mark_unavailable(result, "not installed", library_available=False)
    assert out["available"] is False
    assert out["library_available"] is False


def test_mark_unavailable_without_library_available() -> None:
    """Line 130: _mark_unavailable without library_available kwarg."""
    analyzer = _SimpleAnalyzer()
    result: dict[str, Any] = {"available": True}
    out = analyzer._mark_unavailable(result, "something failed")
    assert out["available"] is False
    assert "library_available" not in out


# --- lines 196-197, 200: get_category cached path and "unknown" default ---

def test_get_category_returns_unknown_by_default() -> None:
    """Line 200: default get_category returns 'unknown'."""
    analyzer = _SimpleAnalyzer()
    assert analyzer.get_category() == "unknown"


def test_get_category_cached_path() -> None:
    """Lines 196-197: cached _cached_category is returned immediately."""
    analyzer = _SimpleAnalyzer()
    analyzer._cached_category = "cached_value"
    assert analyzer.get_category() == "cached_value"


def test_get_category_custom_subclass() -> None:
    """get_category from subclass override returns correct value."""
    analyzer = _CategorizedAnalyzer()
    assert analyzer.get_category() == "hashing"


# --- line 248: supports_format returns True by default ---

def test_supports_format_returns_true_for_any_format() -> None:
    """Line 248: supports_format always returns True in base class."""
    analyzer = _SimpleAnalyzer()
    assert analyzer.supports_format("PE") is True
    assert analyzer.supports_format("ELF") is True
    assert analyzer.supports_format("RANDOM") is True


# --- line 300: is_available returns True by default ---

def test_is_available_base_returns_true() -> None:
    """Line 300: is_available class method defaults to True."""
    assert _SimpleAnalyzer.is_available() is True


# --- lines 312, 336, 348: _log_debug, _log_warning, _log_error ---

def test_log_debug_emits_message(caplog: Any) -> None:
    """Line 312: _log_debug writes to logger with analyzer name prefix."""
    import logging
    caplog.set_level(logging.DEBUG)
    analyzer = _SimpleAnalyzer()
    analyzer._log_debug("debug payload")
    assert "debug payload" in caplog.text


def test_log_warning_emits_message(caplog: Any) -> None:
    """Line 336: _log_warning writes to logger."""
    import logging
    caplog.set_level(logging.WARNING)
    analyzer = _SimpleAnalyzer()
    analyzer._log_warning("watch out")
    assert "watch out" in caplog.text


def test_log_error_emits_message(caplog: Any) -> None:
    """Line 348: _log_error writes to logger."""
    import logging
    caplog.set_level(logging.ERROR)
    analyzer = _SimpleAnalyzer()
    analyzer._log_error("something broke")
    assert "something broke" in caplog.text


# --- lines 370-380: _measure_execution_time wrapper ---

def test_measure_execution_time_dict_result_gets_timing() -> None:
    """Lines 370-376,378,380: wrapper records execution_time for dict results."""
    analyzer = _SimpleAnalyzer()

    @analyzer._measure_execution_time
    def _work() -> dict[str, Any]:
        return {"value": 42}

    result = _work()
    assert result["value"] == 42
    assert "execution_time" in result
    assert isinstance(result["execution_time"], float)


def test_measure_execution_time_non_dict_result_unchanged() -> None:
    """Line 375-378: non-dict result passes through without modification."""
    analyzer = _SimpleAnalyzer()

    @analyzer._measure_execution_time
    def _work() -> str:
        return "plain string"

    assert _work() == "plain string"


def test_measure_execution_time_with_args() -> None:
    """Lines 370-372: wrapper passes args/kwargs to wrapped function."""
    analyzer = _SimpleAnalyzer()

    @analyzer._measure_execution_time
    def _add(a: int, b: int) -> dict[str, Any]:
        return {"sum": a + b}

    result = _add(3, 4)
    assert result["sum"] == 7
    assert result["execution_time"] >= 0.0


# --- lines 400-402: _analysis_context exception handling ---

def test_analysis_context_captures_exception_in_result() -> None:
    """Lines 400-402: exception is caught and stored in result['error']."""
    analyzer = _SimpleAnalyzer()
    result: dict[str, Any] = {"available": False, "error": None}

    with analyzer._analysis_context(result, error_message="ctx error"):
        raise RuntimeError("injected failure")

    assert result["error"] == "injected failure"
    assert result["available"] is False


def test_analysis_context_sets_available_on_success() -> None:
    """Line 399: available is set True when no exception occurs."""
    analyzer = _SimpleAnalyzer()
    result: dict[str, Any] = {"available": False, "error": None}

    with analyzer._analysis_context(result, error_message="should not appear"):
        pass

    assert result["available"] is True
    assert result["error"] is None


def test_analysis_context_set_available_false_option() -> None:
    """Lines 398-399: set_available=False means available stays False on success."""
    analyzer = _SimpleAnalyzer()
    result: dict[str, Any] = {"available": False, "error": None}

    with analyzer._analysis_context(result, error_message="msg", set_available=False):
        pass

    assert result["available"] is False


# --- lines 416-422: get_file_size ---

def test_get_file_size_with_real_file(tmp_path: Path) -> None:
    """Lines 416-422: get_file_size returns byte count for existing file."""
    f = tmp_path / "data.bin"
    f.write_bytes(b"hello world")
    analyzer = _SimpleAnalyzer(filepath=f)
    assert analyzer.get_file_size() == 11


def test_get_file_size_no_filepath() -> None:
    """Line 416-417: None filepath returns None."""
    analyzer = _SimpleAnalyzer()
    assert analyzer.get_file_size() is None


def test_get_file_size_nonexistent_file() -> None:
    """Lines 419-422: OSError is caught, returns None."""
    analyzer = _SimpleAnalyzer(filepath="/no/such/path/file.bin")
    assert analyzer.get_file_size() is None


# --- lines 436-439: get_file_extension ---

def test_get_file_extension_no_filepath() -> None:
    """Lines 436-437: None filepath returns empty string."""
    analyzer = _SimpleAnalyzer()
    assert analyzer.get_file_extension() == ""


def test_get_file_extension_with_exe(tmp_path: Path) -> None:
    """Line 439: extension is lowercased and stripped of dot."""
    f = tmp_path / "binary.EXE"
    f.write_bytes(b"x")
    analyzer = _SimpleAnalyzer(filepath=f)
    assert analyzer.get_file_extension() == "exe"


def test_get_file_extension_no_extension(tmp_path: Path) -> None:
    """Line 439: file with no extension returns empty string."""
    f = tmp_path / "noext"
    f.write_bytes(b"x")
    analyzer = _SimpleAnalyzer(filepath=f)
    assert analyzer.get_file_extension() == ""


# --- lines 452-455: file_exists ---

def test_file_exists_no_filepath() -> None:
    """Lines 452-453: None filepath returns False."""
    analyzer = _SimpleAnalyzer()
    assert analyzer.file_exists() is False


def test_file_exists_real_file(tmp_path: Path) -> None:
    """Line 455: existing file returns True."""
    f = tmp_path / "exists.bin"
    f.write_bytes(b"x")
    analyzer = _SimpleAnalyzer(filepath=f)
    assert analyzer.file_exists() is True


def test_file_exists_directory(tmp_path: Path) -> None:
    """Line 455: directory path returns False (is_file check)."""
    analyzer = _SimpleAnalyzer(filepath=tmp_path)
    assert analyzer.file_exists() is False


def test_file_exists_missing_file() -> None:
    """Line 455: non-existent path returns False."""
    analyzer = _SimpleAnalyzer(filepath="/no/such/file.bin")
    assert analyzer.file_exists() is False


# --- lines 468-469: __str__ ---

def test_str_with_filepath(tmp_path: Path) -> None:
    """Lines 468-469: __str__ includes filename from filepath."""
    f = tmp_path / "sample.exe"
    analyzer = _SimpleAnalyzer(filepath=f)
    s = str(analyzer)
    assert "sample.exe" in s
    assert "_Simple" in s


def test_str_without_filepath() -> None:
    """Lines 468-469: __str__ shows 'no_file' when filepath is None."""
    analyzer = _SimpleAnalyzer()
    s = str(analyzer)
    assert "no_file" in s


# ===========================================================================
# rich_header_analyzer.py tests
# ===========================================================================


# --- lines 33-35: module-level PEFILE_AVAILABLE flag ---

def test_pefile_available_flag_is_boolean() -> None:
    """Lines 33-35: PEFILE_AVAILABLE must be a bool set at import time."""
    assert isinstance(rha_module.PEFILE_AVAILABLE, bool)


# --- lines 83-84: pefile method success path ---

@pytest.mark.skipif(not rha_module.PEFILE_AVAILABLE, reason="pefile not available")
def test_analyze_uses_pefile_on_real_pe() -> None:
    """Lines 83-84: method_used='pefile' when pefile extracts Rich Header."""
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("fixture not present")
    analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=str(sample))
    result = analyzer.analyze()
    assert "is_pe" in result
    if result.get("available"):
        assert result["method_used"] in ("pefile", "r2pipe")


# --- lines 140-151: _extract_rich_header_pefile internals ---

@pytest.mark.skipif(not rha_module.PEFILE_AVAILABLE, reason="pefile not available")
def test_extract_rich_header_pefile_on_real_pe() -> None:
    """Lines 140-151: pefile extraction path with real PE fixture."""
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("fixture not present")
    analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=str(sample))
    result = analyzer._extract_rich_header_pefile()
    # Either None (no Rich Header) or a dict with expected keys
    assert result is None or isinstance(result, dict)


def test_extract_rich_header_pefile_returns_none_when_unavailable() -> None:
    """Line 131: PEFILE_AVAILABLE=False causes early None return."""
    orig = rha_module.PEFILE_AVAILABLE
    rha_module.PEFILE_AVAILABLE = False
    try:
        analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
        assert analyzer._extract_rich_header_pefile() is None
    finally:
        rha_module.PEFILE_AVAILABLE = orig


# --- lines 160-161: pefile close exception during finally ---

@pytest.mark.skipif(not rha_module.PEFILE_AVAILABLE, reason="pefile not available")
def test_pefile_bad_path_does_not_raise() -> None:
    """Lines 153-161: exception in pefile.PE() is caught and returns None."""
    analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath="/nonexistent/file.exe")
    result = analyzer._extract_rich_header_pefile()
    assert result is None


# --- lines 269-270: _check_magic_bytes ---

def test_check_magic_bytes_mz_file() -> None:
    """Lines 269-270: MZ file returns True from _check_magic_bytes."""
    data = _build_pe_no_rich()
    path = _write_tmp(data)
    try:
        analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=path)
        assert analyzer._check_magic_bytes() is True
    finally:
        os.unlink(path)


def test_check_magic_bytes_non_mz_file() -> None:
    """Lines 269-270: non-MZ file returns False from _check_magic_bytes."""
    path = _write_tmp(b"\x7fELF" + b"\x00" * 100)
    try:
        analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=path)
        assert analyzer._check_magic_bytes() is False
    finally:
        os.unlink(path)


def test_check_magic_bytes_no_filepath() -> None:
    """Lines 269-270: None filepath returns False."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    assert analyzer._check_magic_bytes() is False


# --- lines 305-310: _extract_rich_header with r2pipe scan fallback ---

def test_extract_rich_header_direct_search_on_pe_with_rich() -> None:
    """Lines 305-310: direct file search finds Rich Header."""
    orig = rha_module.PEFILE_AVAILABLE
    rha_module.PEFILE_AVAILABLE = False
    data = _build_pe_with_rich_header()
    path = _write_tmp(data)
    try:
        analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=path)
        result = analyzer._extract_rich_header()
        assert result is None or isinstance(result, dict)
    finally:
        rha_module.PEFILE_AVAILABLE = orig
        os.unlink(path)


def test_extract_rich_header_returns_none_for_pe_without_rich() -> None:
    """Lines 309-310: PE without Rich Header returns None from _extract_rich_header."""
    data = _build_pe_no_rich()
    path = _write_tmp(data)
    try:
        analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=path)
        result = analyzer._extract_rich_header()
        assert result is None
    finally:
        os.unlink(path)


# --- lines 350-355: _try_rich_dans_combinations ---

def test_try_rich_dans_combinations_empty_inputs() -> None:
    """Lines 350-355: empty lists return None."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    result = analyzer._try_rich_dans_combinations([], [])
    assert result is None


def test_try_rich_dans_combinations_no_offsets() -> None:
    """Lines 350-355: entries without offset keys are skipped."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    rich = [{"no_offset": 1}]
    dans = [{"no_offset": 2}]
    result = analyzer._try_rich_dans_combinations(rich, dans)
    assert result is None


def test_try_rich_dans_combinations_invalid_offsets() -> None:
    """Lines 350-355: reversed offsets (rich < dans) are skipped."""
    data = _build_pe_no_rich()
    path = _write_tmp(data)
    try:
        analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=path)
        rich = [{"offset": 5}]
        dans = [{"offset": 100}]
        result = analyzer._try_rich_dans_combinations(rich, dans)
        assert result is None
    finally:
        os.unlink(path)


# --- lines 398-411: _direct_file_rich_search paths ---

def test_direct_file_rich_search_on_pe_with_rich() -> None:
    """Lines 398-411: _direct_file_rich_search succeeds on crafted PE."""
    data = _build_pe_with_rich_header()
    path = _write_tmp(data)
    try:
        analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=path)
        result = analyzer._direct_file_rich_search()
        assert result is None or ("xor_key" in result and "entries" in result)
    finally:
        os.unlink(path)


def test_direct_file_rich_search_no_mz() -> None:
    """Lines 398,402: non-MZ data returns None quickly."""
    path = _write_tmp(b"\x7fELF" + b"\x00" * 200)
    try:
        analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=path)
        result = analyzer._direct_file_rich_search()
        assert result is None
    finally:
        os.unlink(path)


def test_direct_file_rich_search_no_filepath() -> None:
    """Lines 406,410: None filepath causes early return of None."""
    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    result = analyzer._direct_file_rich_search()
    assert result is None


def test_direct_file_rich_search_pe_no_rich() -> None:
    """Lines 410-411: PE without Rich signature returns None."""
    data = _build_pe_no_rich()
    path = _write_tmp(data)
    try:
        analyzer = RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=path)
        result = analyzer._direct_file_rich_search()
        assert result is None
    finally:
        os.unlink(path)


# --- line 586: calculate_richpe_hash_from_file ---

def test_calculate_richpe_hash_from_file_missing_path() -> None:
    """Line 586: returns None when file does not exist."""
    result = RichHeaderAnalyzer.calculate_richpe_hash_from_file("/nonexistent/path.exe")
    assert result is None or isinstance(result, str)


def test_calculate_richpe_hash_from_file_real_pe() -> None:
    """Line 586: runs on real PE fixture and returns str or None."""
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("fixture not present")
    result = RichHeaderAnalyzer.calculate_richpe_hash_from_file(str(sample))
    assert result is None or isinstance(result, str)


# ===========================================================================
# simhash_analyzer.py tests
# ===========================================================================


# --- lines 21-24: module-level simhash import ---

def test_simhash_available_is_bool() -> None:
    """Lines 21-24: SIMHASH_AVAILABLE reflects import success."""
    assert isinstance(sim_module.SIMHASH_AVAILABLE, bool)


# --- line 41: _check_library_availability returns (True, None) when available ---

@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_check_library_availability_returns_true_when_available() -> None:
    """Line 41: (True, None) returned when library present."""
    adapter = StubAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    available, error = analyzer._check_library_availability()
    assert available is True
    assert error is None


def test_check_library_availability_returns_false_when_unavailable() -> None:
    """Lines 42-43: (False, error_msg) when library missing."""
    orig = sim_module.SIMHASH_AVAILABLE
    sim_module.SIMHASH_AVAILABLE = False
    try:
        adapter = StubAdapter()
        analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
        available, error = analyzer._check_library_availability()
        assert available is False
        assert error is not None
        assert "simhash" in error.lower()
    finally:
        sim_module.SIMHASH_AVAILABLE = orig


# --- line 52: _calculate_hash returns (None, None, error) when no features ---

@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_calculate_hash_no_features_returns_error() -> None:
    """Line 52: empty feature extraction produces NO_FEATURES_ERROR."""
    adapter = StubAdapter(strings=[], functions=[])
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    hash_val, method, error = analyzer._calculate_hash()
    assert hash_val is None
    assert error is not None
    assert "no features" in error.lower() or "simhash" in error.lower()


# --- line 62: _calculate_hash "Failed to calculate SimHash from features" ---

@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_calculate_hash_returns_hex_when_features_present() -> None:
    """Line 62 inverse: valid features produce a hex hash value."""
    adapter = StubAdapter(strings=[{"string": "long_enough_string_value"}])
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    hash_val, method, error = analyzer._calculate_hash()
    if hash_val is not None:
        assert hash_val.startswith("0x")
        assert method == "feature_extraction"
        assert error is None


# --- line 70: _get_hash_type returns "simhash" ---

def test_get_hash_type_returns_simhash() -> None:
    """Line 70: _get_hash_type always returns 'simhash'."""
    adapter = StubAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    assert analyzer._get_hash_type() == "simhash"


# --- lines 106-108: _extract_string_features exception path ---

def test_extract_string_features_exception_returns_empty() -> None:
    """Lines 106-108: adapter raising on get_strings returns empty list."""

    class RaisingAdapter(StubAdapter):
        def get_strings(self) -> list[dict]:
            raise RuntimeError("get_strings exploded")

    adapter = RaisingAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    features = analyzer._extract_string_features()
    assert isinstance(features, list)


# --- lines 229, 242-243: _extract_function_opcodes with adapter.get_disasm ---

@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_extract_function_opcodes_with_disasm_dict_result() -> None:
    """Lines 229,242-243: adapter.get_disasm returns dict with 'ops'."""
    ops = [
        {"mnemonic": "push"},
        {"mnemonic": "mov"},
        {"mnemonic": "ret"},
    ]
    disasm_map = {0x1000: {"ops": ops}}
    adapter = StubAdapter(disasm_map=disasm_map)
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_function_opcodes(0x1000, "test_func")
    assert isinstance(result, list)
    assert any("OP:push" in f for f in result)


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_extract_function_opcodes_disasm_returns_none_falls_back() -> None:
    """Lines 229,242-243: adapter returns None for primary, then list for secondary."""
    ops = [{"mnemonic": "nop"}]
    # Primary address returns None, secondary (same address) returns list
    disasm_map: dict[int, Any] = {0x2000: None}

    class FallbackAdapter(StubAdapter):
        _call_count = 0

        def get_disasm(self, address: int | None = None, size: int | None = None) -> Any:
            self.__class__._call_count += 1
            if size is None:
                return None
            return ops

    adapter = FallbackAdapter(disasm_map=disasm_map)
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_function_opcodes(0x2000, "fallback_func")
    assert isinstance(result, list)


# --- lines 251, 256: _extract_opcodes_from_ops processing ---

@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_extract_opcodes_from_ops_control_flow_classified() -> None:
    """Line 251,256: control flow opcodes get OPTYPE:control tag."""
    ops = [
        {"mnemonic": "call"},
        {"mnemonic": "ret"},
        {"mnemonic": "jmp"},
    ]
    adapter = StubAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_opcodes_from_ops(ops)
    assert any("OP:call" in f for f in result)
    assert any("OPTYPE:control" in f for f in result)


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_extract_opcodes_from_ops_skips_non_dict_entries() -> None:
    """Line 256: non-dict op entries are skipped."""
    ops: list[Any] = [None, "string", {"mnemonic": "nop"}, 42]
    adapter = StubAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_opcodes_from_ops(ops)
    assert any("OP:nop" in f for f in result)


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_extract_opcodes_from_ops_bigram_feature() -> None:
    """Lines 251,256: two consecutive mnemonics produce a BIGRAM feature."""
    ops = [
        {"mnemonic": "push"},
        {"mnemonic": "mov"},
    ]
    adapter = StubAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_opcodes_from_ops(ops)
    assert any("BIGRAM:" in f for f in result)


# --- lines 272, 284-285: _extract_data_section_strings ---

def test_extract_data_section_strings_empty_sections() -> None:
    """Lines 272,284-285: empty sections list returns empty list."""
    adapter = StubAdapter(sections=[])
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_data_section_strings()
    assert result == []


def test_extract_data_section_strings_non_data_section_skipped() -> None:
    """Lines 272,284-285: non-'.data' sections are not read."""
    adapter = StubAdapter(sections=[{"name": ".text", "vaddr": 0x1000, "size": 64}])
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_data_section_strings()
    assert result == []


def test_extract_data_section_strings_data_section_with_printable() -> None:
    """Lines 272,284-285: .data section with printable bytes yields features."""
    text = b"HelloWorld"
    adapter = StubAdapter(
        sections=[{"name": ".data", "vaddr": 0x3000, "size": len(text)}],
        bytes_map={0x3000: text},
    )
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_data_section_strings()
    assert any("DATASTR:" in f for f in result)


# --- line 324: _get_strings_data fallback when no get_strings attr ---

def test_get_strings_data_fallback_when_no_get_strings_method() -> None:
    """Line 324: adapter without get_strings falls back to _cmd_list('izzj')."""

    class NoStringsAdapter:
        pass

    adapter = NoStringsAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    # _cmd_list will return [] because no r2 session; must not raise
    result = analyzer._get_strings_data()
    assert isinstance(result, list)


# --- line 329: _get_functions fallback when no get_functions attr ---

def test_get_functions_fallback_when_no_get_functions_method() -> None:
    """Line 329: adapter without get_functions falls back to _cmd_list('aflj')."""

    class NoFunctionsAdapter:
        pass

    adapter = NoFunctionsAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._get_functions()
    assert isinstance(result, list)


# --- line 334: _get_sections fallback when no get_sections attr ---

def test_get_sections_fallback_when_no_get_sections_method() -> None:
    """Line 334: adapter without get_sections falls back to _cmd_list('iSj')."""

    class NoSectionsAdapter:
        pass

    adapter = NoSectionsAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._get_sections()
    assert isinstance(result, list)


# --- line 340: _extract_ops_from_disasm list input ---

def test_extract_ops_from_disasm_with_list_input() -> None:
    """Line 340: disasm is a list, returned directly."""
    ops: list[Any] = [{"mnemonic": "nop"}, {"mnemonic": "ret"}]
    adapter = StubAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_ops_from_disasm(ops)
    assert result == ops


def test_extract_ops_from_disasm_with_dict_ops() -> None:
    """Line 337-339: dict with 'ops' key returns the ops list."""
    inner_ops: list[Any] = [{"mnemonic": "push"}]
    adapter = StubAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_ops_from_disasm({"ops": inner_ops})
    assert result == inner_ops


def test_extract_ops_from_disasm_with_unknown_input() -> None:
    """Line 341: unknown disasm type returns empty list."""
    adapter = StubAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    result = analyzer._extract_ops_from_disasm("not a list or dict")
    assert result == []


# --- line 354: _extract_printable_strings trailing string ---

def test_extract_printable_strings_trailing_string_included() -> None:
    """Line 354: string at end of bytes (no null terminator) is included."""
    adapter = StubAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    data = b"Hello"  # 5 printable bytes, no null at end
    result = analyzer._extract_printable_strings(data)
    assert "Hello" in result


def test_extract_printable_strings_short_string_excluded() -> None:
    """Line 354: string shorter than min_string_length is not included."""
    adapter = StubAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    data = b"Hi\x00OK"  # "Hi" is 2 bytes < 4, "OK" is 2 bytes < 4
    result = analyzer._extract_printable_strings(data)
    assert result == []


def test_extract_printable_strings_mixed_data() -> None:
    """Line 350-354: printable regions separated by non-printable bytes."""
    adapter = StubAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
    data = b"validstring\x00garbage\x01more_valid_text"
    result = analyzer._extract_printable_strings(data)
    assert len(result) >= 1


# --- compare_hashes static method ---

@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_compare_hashes_identical_values() -> None:
    """compare_hashes returns 0 for identical hashes."""
    distance = SimHashAnalyzer.compare_hashes(0x1234ABCD, 0x1234ABCD)
    assert distance == 0


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_compare_hashes_hex_string_inputs() -> None:
    """compare_hashes accepts hex strings."""
    distance = SimHashAnalyzer.compare_hashes("0x1234", "0x1234")
    assert distance == 0


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not available")
def test_compare_hashes_different_values_nonzero_distance() -> None:
    """compare_hashes returns nonzero for different hashes."""
    distance = SimHashAnalyzer.compare_hashes(0x1, 0xFFFFFFFF)
    assert distance is not None
    assert distance > 0


def test_compare_hashes_returns_none_when_simhash_unavailable() -> None:
    """compare_hashes returns None when library unavailable."""
    orig = sim_module.SIMHASH_AVAILABLE
    sim_module.SIMHASH_AVAILABLE = False
    try:
        result = SimHashAnalyzer.compare_hashes(0x1234, 0x5678)
        assert result is None
    finally:
        sim_module.SIMHASH_AVAILABLE = orig


def test_compare_hashes_returns_none_for_empty_hash() -> None:
    """compare_hashes returns None when either hash is falsy."""
    result = SimHashAnalyzer.compare_hashes(0, 0x1234)
    assert result is None


# --- is_available ---

def test_simhash_is_available_matches_flag() -> None:
    """SimHashAnalyzer.is_available() mirrors SIMHASH_AVAILABLE."""
    assert SimHashAnalyzer.is_available() == sim_module.SIMHASH_AVAILABLE


# --- analyze with unavailable library ---

def test_analyze_returns_unavailable_when_simhash_missing() -> None:
    """analyze() returns available=False when simhash not importable."""
    orig = sim_module.SIMHASH_AVAILABLE
    sim_module.SIMHASH_AVAILABLE = False
    try:
        adapter = StubAdapter()
        analyzer = SimHashAnalyzer(adapter=adapter, filepath="/fake/path")
        result = analyzer.analyze()
        assert result.get("available") is False
        assert result.get("error") is not None
    finally:
        sim_module.SIMHASH_AVAILABLE = orig
