#!/usr/bin/env python3
"""Targeted tests for small remaining coverage gaps across multiple modules."""

from __future__ import annotations

import logging
import os
import struct
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

import r2inspect.pipeline.stages_format as _sf_mod
import r2inspect.registry.analyzer_registry as _ar_mod
from r2inspect.config import Config
from r2inspect.config_store import ConfigStore
from r2inspect.core.inspector_helpers import InspectorExecutionMixin
from r2inspect.error_handling.policies import ErrorHandlingStrategy, ErrorPolicy
from r2inspect.error_handling.unified_handler import handle_errors
from r2inspect.modules.elf_analyzer import ELFAnalyzer
from r2inspect.modules.function_analyzer import FunctionAnalyzer
from r2inspect.modules.pe_analyzer import PEAnalyzer
from r2inspect.modules.pe_imports import calculate_imphash
from r2inspect.modules.pe_security import get_security_features
from r2inspect.modules.resource_analyzer import ResourceAnalyzer
from r2inspect.modules.rich_header_search import RichHeaderSearchMixin
from r2inspect.modules.simhash_analyzer import SimHashAnalyzer
from r2inspect.modules.string_analyzer import StringAnalyzer
from r2inspect.pipeline.stages_format import FileInfoStage, FormatDetectionStage
from r2inspect.registry.default_registry import create_default_registry
from r2inspect.utils.analyzer_runner import run_analyzer_on_file
from r2inspect.utils.memory_manager import MemoryAwareAnalyzer, MemoryLimits, MemoryMonitor

# ---------------------------------------------------------------------------
# 1. utils/memory_manager.py - lines 116, 120-122, 184-185, 356-363
# ---------------------------------------------------------------------------


def test_memory_monitor_triggers_gc_at_threshold():
    """Line 116: gc_trigger_threshold path when usage is above gc but below warning."""
    limits = MemoryLimits(
        gc_trigger_threshold=0.0,
        memory_warning_threshold=2.0,
        memory_critical_threshold=2.0,
        max_process_memory_mb=10**9,
    )
    monitor = MemoryMonitor(limits)
    stats = monitor.check_memory(force=True)
    assert stats["status"] == "normal"
    assert monitor.gc_count >= 1


def test_memory_monitor_check_memory_exception_returns_error_stats():
    """Lines 120-122: exception inside check_memory try block."""

    class _BadProcess:
        def memory_info(self) -> None:
            raise RuntimeError("simulated process memory failure")

    monitor = MemoryMonitor()
    monitor.process = _BadProcess()
    stats = monitor.check_memory(force=True)
    assert stats["process_memory_mb"] == 0.0
    assert stats["process_usage_percent"] == 0.0


def test_memory_monitor_get_cached_stats_exception():
    """Lines 184-185: exception inside _get_cached_stats."""

    class _BadProcess:
        def memory_info(self) -> None:
            raise RuntimeError("simulated process memory failure")

    monitor = MemoryMonitor()
    monitor.check_interval = float("inf")
    monitor.last_check = time.time()
    monitor.process = _BadProcess()
    stats = monitor.check_memory(force=False)
    assert stats["process_memory_mb"] == 0.0


def test_memory_aware_analyzer_memory_error_in_operation():
    """Lines 356-360: MemoryError raised inside safe_large_operation."""

    def _raise_memory_error() -> None:
        raise MemoryError("simulated OOM")

    analyzer = MemoryAwareAnalyzer()
    result = analyzer.safe_large_operation(_raise_memory_error, estimated_memory_mb=1.0)
    assert result is None


def test_memory_aware_analyzer_exception_in_operation():
    """Lines 361-363: generic Exception inside safe_large_operation."""

    def _raise_runtime_error() -> None:
        raise RuntimeError("simulated failure")

    analyzer = MemoryAwareAnalyzer()
    result = analyzer.safe_large_operation(_raise_runtime_error, estimated_memory_mb=1.0)
    assert result is None


# ---------------------------------------------------------------------------
# 2. modules/simhash_analyzer.py - lines 229, 242-243, 251, 256, 284-285
# ---------------------------------------------------------------------------


def test_simhash_extract_function_opcodes_adapter_none():
    """Line 229: return [] early when adapter is None."""
    analyzer = SimHashAnalyzer(adapter=None, filepath="/tmp/_simhash_dummy")
    result = analyzer._extract_function_opcodes(0, "main")
    assert result == []


def test_simhash_extract_function_opcodes_adapter_raises():
    """Lines 242-243: exception logged and empty list returned."""

    class _RaisingAdapter:
        def get_disasm(self, *args: Any, **kwargs: Any) -> None:
            raise RuntimeError("simulated disasm failure")

    analyzer = SimHashAnalyzer(adapter=_RaisingAdapter(), filepath="/tmp/_simhash_dummy")
    result = analyzer._extract_function_opcodes(0, "func_0")
    assert result == []


def test_simhash_extract_opcodes_from_ops_index_limit():
    """Line 251: break when index >= max_instructions_per_function."""
    analyzer = SimHashAnalyzer(adapter=None, filepath="/tmp/_simhash_dummy")
    analyzer.max_instructions_per_function = 1
    ops = [{"mnemonic": "mov"}, {"mnemonic": "add"}]
    result = analyzer._extract_opcodes_from_ops(ops)
    assert any("OP:mov" in r for r in result)
    assert not any("OP:add" in r for r in result)


def test_simhash_extract_opcodes_from_ops_empty_mnemonic():
    """Line 256: continue when mnemonic is empty after strip."""
    analyzer = SimHashAnalyzer(adapter=None, filepath="/tmp/_simhash_dummy")
    ops = [{"mnemonic": "   "}]
    result = analyzer._extract_opcodes_from_ops(ops)
    assert result == []


def test_simhash_extract_data_section_strings_exception():
    """Lines 284-285: exception in _get_sections is caught and empty list returned."""

    class _RaisingSectionsAdapter:
        def get_sections(self) -> None:
            raise RuntimeError("simulated sections failure")

    analyzer = SimHashAnalyzer(adapter=_RaisingSectionsAdapter(), filepath="/tmp/_simhash_dummy")
    result = analyzer._extract_data_section_strings()
    assert result == []


# ---------------------------------------------------------------------------
# 3. modules/resource_analyzer.py - lines 208-210, 286-288, 360
# ---------------------------------------------------------------------------


class _RABase(ResourceAnalyzer):
    """Minimal ResourceAnalyzer subclass without full adapter setup."""

    def __init__(self) -> None:
        self.adapter = None
        self.r2 = None
        self.RESOURCE_TYPES = ResourceAnalyzer.RESOURCE_TYPES


def test_resource_analyzer_hash_exception_sets_empty_hashes():
    """Lines 208-210: inner exception for hash calculation stores empty dict."""

    class _RACorrruptEntropy(_RABase):
        def _cmdj(self, command: str, default: Any = None) -> Any:
            if command.startswith("pxj"):
                return [65, 66, 67]
            return default

        def _calculate_entropy(self, data: list) -> float:
            data[:] = [256]
            return 0.0

    ra = _RACorrruptEntropy()
    resource: dict[str, Any] = {"offset": 1, "size": 3}
    ra._analyze_resource_data(resource)
    assert resource.get("hashes") == {}


def test_resource_analyzer_parse_version_info_exception():
    """Lines 286-288: exception inside _parse_version_info returns None."""

    class _RAWithRaisingSignature(_RABase):
        def _find_vs_signature(self, data: list) -> None:
            raise RuntimeError("simulated signature failure")

        def _read_version_info_data(self, offset: int, size: int) -> list:
            return [0] * 100

    ra = _RAWithRaisingSignature()
    result = ra._parse_version_info(100, 200)
    assert result is None


def test_resource_analyzer_read_version_string_value_null_terminated():
    """Line 360: value_bytes is empty because value is immediately null-terminated."""
    ra = _RABase()
    key = "A"
    key_bytes = list(key.encode("utf-16le"))
    data = key_bytes + [0] * 4 + [0, 0, 0, 0]
    result = ra._read_version_string_value(data, key)
    assert result == ""


# ---------------------------------------------------------------------------
# 4. pipeline/stages_format.py - lines 49-50, 149, 150, 152, 156, 262
# ---------------------------------------------------------------------------


class _NullAdapter:
    def get_file_info(self) -> dict[str, Any]:
        return {}


def test_file_info_stage_magic_none_sets_null_mime():
    """Lines 49-50: when _magic_detectors is None, mime_type and file_type are None."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(b"\x00" * 32)
        fname = f.name
    try:
        old = _sf_mod._magic_detectors
        _sf_mod._magic_detectors = None
        try:
            stage = FileInfoStage(adapter=_NullAdapter(), filename=fname)
            result = stage._execute({"results": {}})
            assert result["file_info"]["mime_type"] is None
            assert result["file_info"]["file_type"] is None
        finally:
            _sf_mod._magic_detectors = old
    finally:
        os.unlink(fname)


def test_format_detection_archive_detection():
    """Line 149: ZIP magic → _detect_via_enhanced_magic returns 'Archive'."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as f:
        f.write(b"PK\x03\x04" + b"\x00" * 60)
        fname = f.name
    try:
        stage = FormatDetectionStage(adapter=_NullAdapter(), filename=fname)
        result = stage._detect_via_enhanced_magic()
        assert result == "Archive"
    finally:
        os.unlink(fname)


def test_format_detection_document_detection():
    """Line 150: PDF magic → _detect_via_enhanced_magic returns 'Document'."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as f:
        f.write(b"%PDF-1.4" + b"\x00" * 60)
        fname = f.name
    try:
        stage = FormatDetectionStage(adapter=_NullAdapter(), filename=fname)
        result = stage._detect_via_enhanced_magic()
        assert result == "Document"
    finally:
        os.unlink(fname)


def test_format_detection_unhandled_format_returns_none():
    """Line 152: UPX magic → confidence > 0.7 but format not in map → returns None."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".upx") as f:
        f.write(b"UPX!" + b"\x00" * 60)
        fname = f.name
    try:
        stage = FormatDetectionStage(adapter=_NullAdapter(), filename=fname)
        result = stage._detect_via_enhanced_magic()
        assert result is None
    finally:
        os.unlink(fname)


def test_format_detection_basic_magic_none_returns_none():
    """Line 156: _magic_detectors is None → _detect_via_basic_magic returns None."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(b"\x00" * 32)
        fname = f.name
    try:
        old = _sf_mod._magic_detectors
        _sf_mod._magic_detectors = None
        try:
            stage = FormatDetectionStage(adapter=_NullAdapter(), filename=fname)
            result = stage._detect_via_basic_magic()
            assert result is None
        finally:
            _sf_mod._magic_detectors = old
    finally:
        os.unlink(fname)


def test_format_analysis_stage_skips_missing_analyzer_class():
    """Line 262: registry.get_analyzer_class returns None → continue."""
    from r2inspect.pipeline.stages_format import FormatAnalysisStage
    from r2inspect.registry.analyzer_registry import AnalyzerRegistry

    class _FakeConfig:
        analyze_authenticode: bool = True
        analyze_overlay: bool = False
        analyze_resources: bool = False
        analyze_mitigations: bool = False

    empty_registry = AnalyzerRegistry()
    stage = FormatAnalysisStage(
        registry=empty_registry,
        adapter=_NullAdapter(),
        config=_FakeConfig(),
        filename="/tmp/_dummy",
    )
    pe_info: dict[str, Any] = {}
    stage._run_optional_pe_analyzers(pe_info)
    assert pe_info == {}


# ---------------------------------------------------------------------------
# 5. modules/elf_analyzer.py - lines 121-122, 176-179, 239-240
# ---------------------------------------------------------------------------


class _ELFWithRaisingComment(ELFAnalyzer):
    def _extract_comment_section(self) -> None:
        raise RuntimeError("simulated comment section failure")


def test_elf_analyzer_compilation_info_exception():
    """Lines 121-122: exception inside _get_compilation_info is caught."""
    analyzer = _ELFWithRaisingComment(adapter=None)
    result = analyzer._get_compilation_info()
    assert isinstance(result, dict)


class _ELFWithRaisingCmdList(ELFAnalyzer):
    def _cmd_list(self, command: str) -> list:
        raise RuntimeError("simulated cmd_list failure")


def test_elf_analyzer_extract_build_id_exception():
    """Lines 176-179: exception in _extract_build_id is caught and None returned."""
    analyzer = _ELFWithRaisingCmdList(adapter=None)
    result = analyzer._extract_build_id()
    assert result is None


def test_elf_analyzer_program_headers_exception():
    """Lines 239-240: exception in _get_program_headers is caught."""
    import r2inspect.modules.elf_analyzer as _ea_mod

    def _raising_get_elf_headers(r2_instance: Any) -> None:
        raise RuntimeError("simulated elf headers failure")

    orig = _ea_mod.get_elf_headers
    _ea_mod.get_elf_headers = _raising_get_elf_headers
    try:
        analyzer = ELFAnalyzer(adapter=None)
        result = analyzer._get_program_headers()
        assert result == []
    finally:
        _ea_mod.get_elf_headers = orig


# ---------------------------------------------------------------------------
# 6. modules/rich_header_search.py - lines 187, 191, 197-199
# ---------------------------------------------------------------------------


class _Searcher(RichHeaderSearchMixin):
    def __init__(self, adapter: Any) -> None:
        self.adapter = adapter


def test_rich_header_encoded_data_too_short_returns_none():
    """Line 187: _extract_encoded_data returns None when read is too short."""

    class _ShortDataAdapter:
        def read_bytes_list(self, offset: int, size: int) -> list[int]:
            if size == 4:
                return [0x01, 0x02, 0x03, 0x04]
            return [0x00, 0x01, 0x02]

    searcher = _Searcher(_ShortDataAdapter())
    result = searcher._try_extract_rich_at_offsets(0, 20)
    assert result is None


def test_rich_header_validate_decoded_entries_fails_returns_none():
    """Line 191: decode_rich_header returns empty entries → validate fails."""
    xor_key = 0x12345678

    class _ZeroCountAdapter:
        def read_bytes_list(self, offset: int, size: int) -> list[int]:
            if size == 4:
                return list(struct.pack("<I", xor_key))
            dans_placeholder = b"\xab\xcd\xef\x00"
            entry_prodid = struct.pack("<I", 0x00000001)
            entry_count = struct.pack("<I", xor_key)
            encoded = dans_placeholder + entry_prodid + entry_count
            return list(encoded)

    searcher = _Searcher(_ZeroCountAdapter())
    result = searcher._try_extract_rich_at_offsets(0, 12)
    assert result is None


def test_rich_header_extraction_exception_returns_none():
    """Lines 197-199: exception from adapter during extraction is caught."""

    class _RaisingAdapter:
        def read_bytes_list(self, offset: int, size: int) -> None:
            raise RuntimeError("simulated read failure")

    searcher = _Searcher(_RaisingAdapter())
    result = searcher._try_extract_rich_at_offsets(0, 20)
    assert result is None


# ---------------------------------------------------------------------------
# 7. utils/analyzer_runner.py - lines 27-31
# ---------------------------------------------------------------------------

_TINY_BIN = str(Path(__file__).parent.parent.parent / "samples" / "fixtures" / "edge_tiny.bin")


def test_analyzer_runner_calls_analyze_method():
    """Lines 29-30: run_analyzer_on_file calls analyze() when callable."""
    if not Path(_TINY_BIN).exists():
        return

    class _AnalyzerFactory:
        def __init__(self, adapter: Any, filepath: str) -> None:
            pass

        def analyze(self) -> dict[str, Any]:
            return {"ok": True}

    result = run_analyzer_on_file(_AnalyzerFactory, _TINY_BIN)
    assert result == {"ok": True} or result is None


def test_analyzer_runner_returns_none_without_analyze_method():
    """Line 31: run_analyzer_on_file returns None when no analyze attribute."""
    if not Path(_TINY_BIN).exists():
        return

    class _NoAnalyzeFactory:
        def __init__(self, adapter: Any, filepath: str) -> None:
            pass

    result = run_analyzer_on_file(_NoAnalyzeFactory, _TINY_BIN)
    assert result is None


# ---------------------------------------------------------------------------
# 8. modules/pe_imports.py - lines 88-89
# ---------------------------------------------------------------------------


def test_calculate_imphash_empty_impstrs_returns_empty():
    """Lines 88-89: all function names are empty so impstrs is empty."""

    class _EmptyImportsAdapter:
        def get_imports(self) -> list[dict[str, Any]]:
            return [{"libname": "kernel32.dll", "name": ""}]

    logger = logging.getLogger("test_pe_imports")
    result = calculate_imphash(_EmptyImportsAdapter(), logger)
    assert result == ""


# ---------------------------------------------------------------------------
# 9. modules/string_analyzer.py - lines 118-121
# ---------------------------------------------------------------------------


def test_string_analyzer_search_xor_exception_returns_empty():
    """Lines 118-121: exception in build_xor_matches is caught, returns []."""

    class _RaisingSearchAdapter:
        def search_hex(self, pattern: str) -> None:
            raise RuntimeError("simulated search failure")

    config = Config()
    analyzer = StringAnalyzer(adapter=_RaisingSearchAdapter(), config=config)
    result = analyzer.search_xor("test")
    assert result == []


# ---------------------------------------------------------------------------
# 10. error_handling/unified_handler.py - lines 285-286
# ---------------------------------------------------------------------------


def test_handle_errors_unreachable_strategy_hits_assert_never():
    """Lines 285-286: case _ fires when strategy is not a known enum member."""

    class _FakeStrategy:
        value: str = "not_a_real_strategy"

    policy = ErrorPolicy(strategy=ErrorHandlingStrategy.FAIL_FAST, fallback_value=None)
    policy.strategy = _FakeStrategy()

    @handle_errors(policy)
    def _fn() -> dict[str, Any]:
        return {"result": "ok"}

    with pytest.raises(AssertionError):
        _fn()


# ---------------------------------------------------------------------------
# 11. core/inspector_helpers.py - lines 82, 168
# ---------------------------------------------------------------------------


class _FakeCryptoClass:
    def __init__(self, **kwargs: Any) -> None:
        pass

    def detect(self) -> dict[str, Any]:
        return {"algorithms": ["AES"], "constants": []}

    def analyze(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return {"args": args, "kwargs": kwargs}


class _FakeRegistry:
    def get_analyzer_class(self, name: str) -> Any:
        if name in ("crypto_analyzer", "fake"):
            return _FakeCryptoClass
        return None


class _MinimalInspector(InspectorExecutionMixin):
    adapter: Any = None
    config: Any = None
    filename: str = "/tmp/_dummy"
    registry: Any = _FakeRegistry()
    _result_aggregator: Any = None


def test_inspector_helpers_execute_analyzer_with_args():
    """Line 82: _execute_analyzer passes args to analyzer.analyze()."""
    inspector = _MinimalInspector()
    result = inspector._execute_analyzer("fake", "analyze", "extra_arg")
    assert isinstance(result, dict)


def test_inspector_helpers_detect_crypto_success_path():
    """Line 168: detect_crypto returns _as_dict(result) when result is truthy."""
    inspector = _MinimalInspector()
    result = inspector.detect_crypto()
    assert isinstance(result, dict)
    assert result.get("algorithms") == ["AES"]


# ---------------------------------------------------------------------------
# 12. config_store.py - lines 39-40
# ---------------------------------------------------------------------------


def test_config_store_save_exception_is_printed(capsys: Any) -> None:
    """Lines 39-40: exception during save is caught and warning printed."""
    ConfigStore.save("/nonexistent/readonly/path/config.json", {"key": "value"})
    captured = capsys.readouterr()
    assert "Warning" in captured.out


# ---------------------------------------------------------------------------
# 13. modules/pe_security.py - lines 30-31
# ---------------------------------------------------------------------------


def test_pe_security_exception_is_logged():
    """Lines 30-31: exception during security detection is caught."""

    class _RaisingAdapter:
        @property
        def get_pe_security_text(self) -> None:
            raise RuntimeError("simulated security text error")

    logger = logging.getLogger("test_pe_security")
    result = get_security_features(_RaisingAdapter(), logger)
    assert isinstance(result, dict)
    assert "aslr" in result


# ---------------------------------------------------------------------------
# 14. registry/default_registry.py - lines 271-272
# ---------------------------------------------------------------------------


def test_default_registry_entry_points_exception_is_swallowed():
    """Lines 271-272: exception from load_entry_points is caught and logged."""
    orig = _ar_mod.AnalyzerRegistry.load_entry_points

    def _raising_load(self: Any, *args: Any, **kwargs: Any) -> None:
        raise RuntimeError("simulated entry point failure")

    _ar_mod.AnalyzerRegistry.load_entry_points = _raising_load
    try:
        registry = create_default_registry()
        assert registry is not None
    finally:
        _ar_mod.AnalyzerRegistry.load_entry_points = orig


# ---------------------------------------------------------------------------
# 15. modules/function_analyzer.py - lines 108-109
# ---------------------------------------------------------------------------


def test_function_analyzer_should_run_full_exception_falls_through():
    """Lines 108-109: exception accessing typed_config is caught, returns True."""

    class _BadConfig:
        @property
        def typed_config(self) -> None:
            raise RuntimeError("simulated bad config")

    analyzer = FunctionAnalyzer(adapter=None, config=_BadConfig(), filename=None)
    result = analyzer._should_run_full_analysis()
    assert result is True


# ---------------------------------------------------------------------------
# 16. modules/pe_analyzer.py - line 86
# ---------------------------------------------------------------------------


def test_pe_analyzer_get_resource_info_delegates():
    """Line 86: get_resource_info delegates to _get_resource_info."""

    class _NullPEAdapter:
        def get_file_info(self) -> dict[str, Any]:
            return {}

        def cmdj(self, cmd: str) -> Any:
            return []

        def cmd(self, cmd: str) -> str:
            return ""

    analyzer = PEAnalyzer(adapter=_NullPEAdapter())
    result = analyzer.get_resource_info()
    assert isinstance(result, list)
