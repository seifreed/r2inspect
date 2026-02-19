"""
Unit tests for missing coverage in wave 3 modules.

Covers:
  r2inspect/modules/function_analyzer.py      lines 108,109,458,459,471,472
  r2inspect/modules/macho_security.py         lines 30,31,38,42,45,50
  r2inspect/modules/pe_imports.py             lines 88,89,95,96,97
  r2inspect/registry/entry_points.py          lines 23,24,25,30,31,32
  r2inspect/schemas/converters.py             lines 283,284,285,312,313,314
  r2inspect/utils/rate_limiter.py             lines 162,164,166,167,346,347
  r2inspect/abstractions/hashing_strategy.py  lines 106,107,150,151,155
  r2inspect/cli/interactive.py                lines 135,142,143,144,145
  r2inspect/modules/binlex_analyzer.py        lines 180,269,272,395,400
  r2inspect/modules/packer_helpers.py         lines 18,122,131,149,153
"""

from __future__ import annotations

import io
import logging
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

import psutil
import pytest

# ---------------------------------------------------------------------------
# Helpers shared across multiple test groups
# ---------------------------------------------------------------------------

_logger = logging.getLogger("test_wave3")


# ---------------------------------------------------------------------------
# function_analyzer.py  -- lines 108,109,458,459,471,472
# ---------------------------------------------------------------------------

from r2inspect.modules.function_analyzer import FunctionAnalyzer


def test_function_analyzer_file_size_nonexistent_path():
    """Lines 108-109: OSError branch in _get_file_size_mb for missing file."""
    analyzer = FunctionAnalyzer(
        adapter=object(),
        config=None,
        filename="/nonexistent/path/does_not_exist_xyz.bin",
    )
    assert analyzer._file_size_mb is None


def test_function_analyzer_classify_none_name_exception():
    """Lines 458-459: except-Exception branch in _classify_function_type."""
    analyzer = FunctionAnalyzer(adapter=object(), config=None)
    # Passing None as func_name triggers AttributeError inside the try block.
    result = analyzer._classify_function_type(None, {})  # type: ignore[arg-type]
    assert result == "unknown"


def test_function_analyzer_std_dev_type_error_exception():
    """Lines 471-472: except-Exception branch in _calculate_std_dev."""
    analyzer = FunctionAnalyzer(adapter=object(), config=None)
    # Non-numeric values cause TypeError in sum(), hitting the except block.
    result = analyzer._calculate_std_dev(["not", "numbers"])  # type: ignore[arg-type]
    assert result == 0.0


# ---------------------------------------------------------------------------
# macho_security.py  -- lines 30,31,38,42,45,50
# ---------------------------------------------------------------------------

from r2inspect.modules.macho_security import _get_headers, _get_info, get_security_features


class _BadSymbolsAdapter:
    """Adapter whose get_symbols() raises so the except branch fires."""

    def get_file_info(self) -> dict:
        return {"bin": {"class": "MACH064"}}

    def get_symbols(self):
        raise RuntimeError("symbols unavailable")

    def get_headers_json(self) -> dict:
        return {"flag": 0}


def test_macho_get_security_features_exception_path():
    """Lines 30-31: except branch in get_security_features when adapter explodes."""
    result = get_security_features(_BadSymbolsAdapter(), _logger)
    # The function returns the default-False dict after the exception.
    assert isinstance(result, dict)
    assert "pie" in result


def test_macho_get_headers_none_adapter():
    """Line 38: _get_headers returns [] when adapter is None."""
    assert _get_headers(None) == []


def test_macho_get_headers_dict_response():
    """Line 42: _get_headers wraps a dict response in a list."""

    class DictHeaderAdapter:
        def get_headers_json(self) -> dict:
            return {"bits": 64}

    result = _get_headers(DictHeaderAdapter())
    assert result == [{"bits": 64}]


def test_macho_get_headers_no_method():
    """Line 45: _get_headers returns [] for adapter with no get_headers_json."""
    assert _get_headers(object()) == []


def test_macho_get_info_none_adapter():
    """Line 50: _get_info returns None when adapter is None."""
    assert _get_info(None) is None


# ---------------------------------------------------------------------------
# pe_imports.py  -- lines 88,89,95,96,97
# ---------------------------------------------------------------------------

from r2inspect.modules.pe_imports import calculate_imphash


class _EmptyImportsAdapter:
    def get_imports(self) -> list:
        return []


class _BrokenImportsAdapter:
    def get_imports(self):
        raise RuntimeError("imports unavailable")


def test_pe_imports_no_imports_returns_empty_string():
    """Lines 88-89: if not impstrs branch in calculate_imphash."""
    result = calculate_imphash(_EmptyImportsAdapter(), _logger)
    assert result == ""


def test_pe_imports_exception_returns_empty_string():
    """Lines 95-97: except branch in calculate_imphash."""
    result = calculate_imphash(_BrokenImportsAdapter(), _logger)
    assert result == ""


# ---------------------------------------------------------------------------
# entry_points.py  -- lines 23,24,25,30,31,32
# ---------------------------------------------------------------------------

import r2inspect.registry.entry_points as _ep_module
from r2inspect.registry.entry_points import EntryPointLoader


class _FakeRegistry:
    def register(self, **kwargs: Any) -> None:
        pass

    def is_base_analyzer(self, cls: Any) -> bool:
        return False

    def extract_metadata_from_class(self, cls: Any) -> dict:
        return {"name": "test"}

    def _parse_category(self, cat: str) -> str:
        return cat


class _FakeEP:
    """Minimal entry-point stub that loads a harmless callable."""

    name = "test_ep_wave3"

    def load(self) -> Any:
        return lambda registry: None


class _ControlledLoader(EntryPointLoader):
    """Subclass that injects a known entry-point list into load()."""

    def _get_entry_points_group(self, group: str) -> list:  # type: ignore[override]
        return [_FakeEP()]


def test_entry_point_loader_loop_executes():
    """Lines 23-25: for-loop and final return in load() with non-empty group."""
    loader = _ControlledLoader(_FakeRegistry())
    count = loader.load("test_group")
    assert isinstance(count, int)


def test_entry_point_get_group_exception_path():
    """Lines 30-32: except branch in _get_entry_points_group when entry_points() fails."""
    original = _ep_module.entry_points

    def _bad_entry_points(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("simulated entry_points failure")

    _ep_module.entry_points = _bad_entry_points  # type: ignore[assignment]
    try:
        loader = EntryPointLoader(object())
        result = loader._get_entry_points_group("any_group")
        assert result == []
    finally:
        _ep_module.entry_points = original  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# schemas/converters.py  -- lines 283,284,285,312,313,314
# ---------------------------------------------------------------------------

from r2inspect.schemas.converters import safe_convert, validate_result
from r2inspect.schemas.hashing import HashAnalysisResult


class _ExplodingModel:
    """A non-Pydantic class that always raises TypeError on construction."""

    def __init__(self, **kwargs: Any) -> None:
        raise TypeError("deliberate construction error")


def test_safe_convert_exception_branch():
    """Lines 283-285: except-Exception in safe_convert when dict_to_model raises."""
    result = safe_convert({"key": "value"}, _ExplodingModel, default=None)  # type: ignore[arg-type]
    assert result is None


def test_validate_result_validation_error_branch():
    """Lines 312-314: except-ValidationError in validate_result."""
    # model_construct bypasses validation, so hash_type is absent.
    incomplete = HashAnalysisResult.model_construct(available=True)
    result = validate_result(incomplete)
    assert result is False


# ---------------------------------------------------------------------------
# utils/rate_limiter.py  -- lines 162,164,166,167,346,347
# ---------------------------------------------------------------------------

from r2inspect.utils.rate_limiter import AdaptiveRateLimiter, cleanup_memory


def test_rate_limiter_increase_rate_low_system_load():
    """Line 162: elif branch (increase rate) in _check_system_load."""
    original_vmem = psutil.virtual_memory
    original_cpu = psutil.cpu_percent

    class _LowMemInfo:
        percent = 20.0  # well below the 60 % threshold

    psutil.virtual_memory = lambda: _LowMemInfo()  # type: ignore[assignment]
    psutil.cpu_percent = lambda **kwargs: 20.0  # type: ignore[assignment]
    try:
        limiter = AdaptiveRateLimiter(base_rate=5.0, max_rate=20.0)
        limiter.last_system_check = 0.0  # force immediate check
        old_rate = limiter.current_rate
        limiter._check_system_load()
        assert limiter.current_rate >= old_rate
    finally:
        psutil.virtual_memory = original_vmem  # type: ignore[assignment]
        psutil.cpu_percent = original_cpu  # type: ignore[assignment]


def test_rate_limiter_check_system_load_exception():
    """Lines 164-167: except branch in _check_system_load when psutil fails."""
    original_vmem = psutil.virtual_memory

    def _bad_vmem() -> None:
        raise RuntimeError("vmem unavailable")

    psutil.virtual_memory = _bad_vmem  # type: ignore[assignment]
    try:
        limiter = AdaptiveRateLimiter(base_rate=5.0, max_rate=20.0)
        limiter.last_system_check = 0.0
        old_rate = limiter.current_rate
        limiter._check_system_load()
        # After exception, rate is reduced conservatively.
        assert limiter.current_rate <= old_rate
    finally:
        psutil.virtual_memory = original_vmem  # type: ignore[assignment]


def test_cleanup_memory_exception_returns_none():
    """Lines 346-347: except branch in cleanup_memory when psutil.Process fails."""
    original_process = psutil.Process

    def _bad_process(pid: Any = None) -> None:
        raise RuntimeError("process info unavailable")

    psutil.Process = _bad_process  # type: ignore[assignment]
    try:
        result = cleanup_memory()
        assert result is None
    finally:
        psutil.Process = original_process  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# abstractions/hashing_strategy.py  -- lines 106,107,150,151,155
# ---------------------------------------------------------------------------

from r2inspect.abstractions.hashing_strategy import HashingStrategy


class _RaisingHashing(HashingStrategy):
    """Concrete strategy whose _check_library_availability raises unexpectedly."""

    def _check_library_availability(self) -> tuple[bool, str | None]:
        raise RuntimeError("unexpected internal error")

    def _calculate_hash(self) -> tuple[str | None, str | None, str | None]:
        return "abc", "demo", None

    def _get_hash_type(self) -> str:
        return "demo"

    @staticmethod
    def compare_hashes(hash1: str, hash2: str) -> Any | None:
        return None

    @staticmethod
    def is_available() -> bool:
        return True


class _DemoHashing(HashingStrategy):
    """Normal working strategy for validation tests."""

    def _check_library_availability(self) -> tuple[bool, str | None]:
        return True, None

    def _calculate_hash(self) -> tuple[str | None, str | None, str | None]:
        return "abc123", "demo", None

    def _get_hash_type(self) -> str:
        return "demo"

    @staticmethod
    def compare_hashes(hash1: str, hash2: str) -> Any | None:
        return None

    @staticmethod
    def is_available() -> bool:
        return True


def test_hashing_strategy_analyze_unexpected_exception():
    """Lines 106-107: except-Exception branch in analyze()."""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"A" * 100)
        fname = f.name
    try:
        strategy = _RaisingHashing(fname)
        result = strategy.analyze()
        assert result["error"] is not None
        assert "demo" in result["error"]
    finally:
        os.unlink(fname)


def test_hashing_strategy_validate_file_oserror():
    """Lines 150-151: OSError branch in _validate_file via a too-long filename."""
    # A filename component longer than NAME_MAX (255 on macOS/Linux) raises OSError.
    long_name = "a" * 300 + ".bin"
    strategy = _DemoHashing("/tmp/" + long_name)
    result = strategy._validate_file()
    assert result is not None
    assert "Cannot access file statistics" in result


def test_hashing_strategy_validate_file_not_readable():
    """Line 155: unreadable-file branch in _validate_file."""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"B" * 200)
        fname = f.name
    os.chmod(fname, 0o000)
    try:
        strategy = _DemoHashing(fname)
        result = strategy._validate_file()
        assert result is not None
        assert "not readable" in result
    finally:
        os.chmod(fname, 0o644)
        os.unlink(fname)


# ---------------------------------------------------------------------------
# cli/interactive.py  -- lines 135,142,143,144,145
# ---------------------------------------------------------------------------

from r2inspect.cli.interactive import run_interactive_mode


class _SimpleInspector:
    def get_strings(self) -> list:
        return []

    def get_file_info(self) -> dict:
        return {}

    def get_pe_info(self) -> dict:
        return {}

    def get_imports(self) -> list:
        return []

    def get_exports(self) -> list:
        return []

    def get_sections(self) -> list:
        return []


class _KBInterruptStdin:
    """Stdin replacement that raises KeyboardInterrupt on first read."""

    def readline(self) -> str:
        raise KeyboardInterrupt

    def isatty(self) -> bool:
        return False

    def read(self, n: int = -1) -> str:
        raise KeyboardInterrupt


def test_interactive_empty_command_continues():
    """Line 135: continue branch for empty command input."""
    old_stdin = sys.stdin
    sys.stdin = io.StringIO("\nquit\n")
    try:
        run_interactive_mode(_SimpleInspector(), {})
    finally:
        sys.stdin = old_stdin


def test_interactive_keyboard_interrupt_exits():
    """Lines 142-143: KeyboardInterrupt except branch breaks the loop."""
    old_stdin = sys.stdin
    sys.stdin = _KBInterruptStdin()
    try:
        run_interactive_mode(_SimpleInspector(), {})
    finally:
        sys.stdin = old_stdin


def test_interactive_eof_error_exits():
    """Lines 144-145: EOFError except branch breaks the loop."""
    old_stdin = sys.stdin
    sys.stdin = io.StringIO("")  # empty → input() raises EOFError
    try:
        run_interactive_mode(_SimpleInspector(), {})
    finally:
        sys.stdin = old_stdin


# ---------------------------------------------------------------------------
# modules/binlex_analyzer.py  -- lines 180,269,272,395,400
# ---------------------------------------------------------------------------

from r2inspect.modules.binlex_analyzer import BinlexAnalyzer


class _ShortTokenAdapter:
    """Returns two-token disassembly for any address."""

    def get_disasm(self, address: int = 0, size: int | None = None) -> dict:
        return {"ops": [{"mnemonic": "mov"}, {"mnemonic": "push"}]}


def test_binlex_collect_signatures_missing_n_key():
    """Line 180: continue when n is not in func_sigs."""
    analyzer = BinlexAnalyzer(adapter=object(), filepath="/tmp/test.bin")
    # n=3 is not present in func_sigs for func_a (only n=2 is present).
    fs: dict = {"func_a": {2: {"signature": "abc123"}}}
    sigs, groups = analyzer._collect_signatures_for_size(fs, 3)
    assert sigs == set()
    assert len(groups) == 0


def test_binlex_analyze_function_tokens_shorter_than_n():
    """Lines 269,272: debug-log + continue when len(tokens) < n."""
    analyzer = BinlexAnalyzer(adapter=_ShortTokenAdapter(), filepath="/tmp/test.bin")
    # Two tokens extracted; n=5 exceeds token count → continue branch fires.
    result = analyzer._analyze_function(0, "short_func", [5])
    assert result is None


def test_binlex_normalize_mnemonic_none_input():
    """Line 395: return None for None mnemonic."""
    analyzer = BinlexAnalyzer(adapter=object(), filepath="/tmp/test.bin")
    assert analyzer._normalize_mnemonic(None) is None


def test_binlex_normalize_mnemonic_ampersand_entity():
    """Line 400: return None for mnemonic that becomes an '&'-prefixed string."""
    analyzer = BinlexAnalyzer(adapter=object(), filepath="/tmp/test.bin")
    # "&amp;test" → after replace → "&test" which starts with "&" → None
    assert analyzer._normalize_mnemonic("&amp;test") is None


# ---------------------------------------------------------------------------
# modules/packer_helpers.py  -- lines 18,122,131,149,153
# ---------------------------------------------------------------------------

from r2inspect.modules.packer_helpers import (
    find_packer_signature,
    is_suspicious_section_name,
    overlay_info,
    update_section_info,
)


def _always_found(hex_sig: str) -> str:
    """search_hex_fn that always reports a hit."""
    return "found"


def test_find_packer_signature_match_returns_dict():
    """Line 18: return branch inside find_packer_signature when signature is found."""
    sigs: dict[str, list[bytes]] = {"UPX": [b"UPX!"]}
    result = find_packer_signature(_always_found, sigs)
    assert result is not None
    assert result["type"] == "UPX"


def test_update_section_info_suspicious_name():
    """Line 122: suspicious_section append for known bad section name."""
    section_info: dict = {
        "suspicious_sections": [],
        "executable_sections": 0,
        "writable_executable": 0,
    }
    update_section_info(section_info, {"name": ".upx", "flags": "", "size": 500})
    names = [s["name"] for s in section_info["suspicious_sections"]]
    assert ".upx" in names


def test_update_section_info_very_large_section():
    """Line 131: suspicious_section append for a very large section."""
    section_info: dict = {
        "suspicious_sections": [],
        "executable_sections": 0,
        "writable_executable": 0,
    }
    update_section_info(section_info, {"name": ".data", "flags": "", "size": 20_000_001})
    reasons = [s.get("reason", "") for s in section_info["suspicious_sections"]]
    assert "Very large section" in reasons


def test_overlay_info_no_bin_key_returns_empty():
    """Line 149: early return {} when file_info has no 'bin' key."""
    result = overlay_info({"other": 1}, [{"vaddr": 0, "size": 100}])
    assert result == {}


def test_overlay_info_no_sections_returns_empty():
    """Line 153: early return {} when sections is None."""
    result = overlay_info({"bin": {"size": 1000}}, None)
    assert result == {}
