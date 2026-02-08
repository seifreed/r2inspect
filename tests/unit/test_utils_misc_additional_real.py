from __future__ import annotations

import builtins
import struct
import threading
import time
from pathlib import Path

import pytest

from r2inspect.utils import ssdeep_loader
from r2inspect.utils.analyzer_factory import create_analyzer, run_analysis_method
from r2inspect.utils.circuit_breaker import CircuitBreaker, CircuitState, r2_circuit_breaker
from r2inspect.utils.command_helpers import _handle_bytes, _parse_size
from r2inspect.utils.error_handler import (
    ErrorCategory,
    ErrorClassifier,
    ErrorInfo,
    global_error_manager,
)
from r2inspect.utils.hashing import calculate_ssdeep
from r2inspect.utils.magic_detector import MagicByteDetector
from r2inspect.utils.memory_manager import MemoryAwareAnalyzer, MemoryMonitor
from r2inspect.utils.output import OutputFormatter
from r2inspect.utils.r2_helpers import get_macho_headers
from r2inspect.utils.r2_suppress import silent_cmdj
from r2inspect.utils.rate_limiter import cleanup_memory
from r2inspect.utils.retry_manager import RetryManager


class _SigError:
    @property
    def __signature__(self) -> object:  # type: ignore[override]
        raise ValueError("bad signature")


class _NeedsArgs:
    def __init__(self, adapter: object, config: object) -> None:
        self.adapter = adapter
        self.config = config


class _Analyzer:
    def analyze(self) -> dict[str, object]:
        return {"ok": True}


class _FallbackAnalyzer:
    def __init__(self, adapter: object | None = None, config: object | None = None) -> None:
        if adapter is not None:
            raise TypeError("force fallback")
        self.adapter = adapter
        self.config = config


class _R2Stub:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def cmd(self, command: str) -> str:
        self.calls.append(command)
        return ""

    def cmdj(self, command: str) -> object | None:
        self.calls.append(command)
        return None


def test_analyzer_factory_fallbacks() -> None:
    adapter = object()
    config = object()
    analyzer = create_analyzer(_NeedsArgs, adapter=adapter, config=config)
    assert isinstance(analyzer, _NeedsArgs)

    analyzer = create_analyzer(_SigError, adapter=adapter, config=config)
    assert isinstance(analyzer, _SigError)

    analyzer = create_analyzer(_FallbackAnalyzer, adapter=adapter, config=config)
    assert isinstance(analyzer, _FallbackAnalyzer)

    analyzer = create_analyzer(_Analyzer)
    assert run_analysis_method(analyzer, ["analyze"]) == {"ok": True}


def test_circuit_breaker_reset_and_error() -> None:
    breaker = CircuitBreaker()
    assert breaker._should_attempt_reset() is False

    r2 = _R2Stub()
    breaker = r2_circuit_breaker.get_breaker("generic")
    breaker.state = CircuitState.OPEN
    breaker.last_failure_time = time.time()
    assert r2_circuit_breaker.execute_command(r2, "pi") == ""


def test_command_helpers_parse_size_and_bytes() -> None:
    assert _parse_size("pdj") is None

    class _Adapter:
        def read_bytes_list(self, *_args: object) -> list[int]:
            return [1, 2, 3]

    assert _handle_bytes(_Adapter(), "p8j", address=0x10) is None
    assert _handle_bytes(_Adapter(), "p8", address=0x10) is None


def test_error_handler_inheritance_and_dependency_action() -> None:
    class _CustomMemoryError(MemoryError):
        pass

    info = ErrorClassifier.classify(_CustomMemoryError("mem"), {})
    assert info.category == ErrorCategory.MEMORY

    dep_info = ErrorClassifier.classify(ImportError("missing"), {})
    assert dep_info.category == ErrorCategory.DEPENDENCY
    assert "Install missing dependency" in dep_info.suggested_action

    recoverable = ErrorInfo(
        exception=MemoryError("mem"),
        severity=info.severity,
        category=ErrorCategory.MEMORY,
        recoverable=True,
    )
    recovered, _ = global_error_manager.handle_error(recoverable)
    assert recovered is True


def test_calculate_ssdeep_import_failure(tmp_path: Path) -> None:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"data")

    original_import = builtins.__import__

    def _fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "ssdeep":
            raise ImportError("forced")
        return original_import(name, *args, **kwargs)

    ssdeep_loader._ssdeep_module = None
    builtins.__import__ = _fake_import
    try:
        assert calculate_ssdeep(str(path)) is None
    finally:
        builtins.__import__ = original_import


def test_magic_detector_edges() -> None:
    detector = MagicByteDetector()

    class _BadFile:
        def seek(self, _offset: int) -> None:
            raise OSError("seek fail")

        def read(self, _size: int = -1) -> bytes:
            raise OSError("read fail")

    assert detector._validate_docx_format(_BadFile()) == 0.0

    header = b"MZ" + b"\x00" * 62 + struct.pack("<I", 0x100)
    assert detector._analyze_pe_details(header, _BadFile())["architecture"].startswith("Unknown")

    macho_header = struct.pack("<I", 0xFEEDFACE) + struct.pack("<I", 0x1234)
    details = detector._analyze_macho_details(macho_header)
    assert details["architecture"].startswith("Unknown")

    elf_header = bytearray(b"\x7fELF\x01" + b"\x02" + b"\x00" * 14)
    elf_header[5] = 2
    details = detector._analyze_elf_details(bytes(elf_header))
    assert details["endianness"] == "Big"


def test_memory_manager_warning_and_safe_execute() -> None:
    monitor = MemoryMonitor()

    def _warning(_stats: dict[str, object]) -> None:
        raise RuntimeError("warn")

    monitor.warning_callback = _warning
    monitor._handle_warning_memory({"process_memory_mb": 1.0, "process_usage_percent": 0.5})

    analyzer = MemoryAwareAnalyzer(monitor)
    assert (
        analyzer.safe_large_operation(
            lambda: (_ for _ in ()).throw(ValueError("boom")), estimated_memory_mb=0.0
        )
        is None
    )


def test_output_compile_time_and_helpers() -> None:
    formatter = OutputFormatter({"macho_info": {"compile_time": "2024-01-01"}})
    assert (
        formatter._extract_compile_time({"macho_info": {"compile_time": "2024-01-01"}})
        == "2024-01-01"
    )


def test_r2_helpers_macho_headers_fallback() -> None:
    class _R2:
        def get_header_text(self) -> str:
            return "header text"

    assert get_macho_headers(_R2()) == []


def test_r2_suppress_error_paths() -> None:
    class _R2:
        def cmdj(self, _cmd: str) -> object:
            raise RuntimeError("cmdj fail")

        def cmd(self, _cmd: str) -> str:
            raise OSError("cmd fail")

    assert silent_cmdj(_R2(), "ij", default=None) is None


def test_rate_limiter_cleanup_memory_exception() -> None:
    import psutil

    original_process = psutil.Process

    def _fail_process(_pid: int) -> object:
        raise RuntimeError("fail")

    psutil.Process = _fail_process  # type: ignore[assignment]
    try:
        assert cleanup_memory() is None
    finally:
        psutil.Process = original_process  # type: ignore[assignment]


def test_retry_manager_breaks_on_handle_exception() -> None:
    class _RetryManager(RetryManager):
        def _handle_retry_exception(self, *_args: object, **_kwargs: object) -> bool:
            return False

    manager = _RetryManager()
    with pytest.raises(OSError):
        manager.retry_operation(lambda: (_ for _ in ()).throw(OSError("boom")))


def test_ssdeep_loader_inner_lock_path() -> None:
    ssdeep_loader._ssdeep_module = None
    ssdeep_loader._import_lock.acquire()
    try:
        result: dict[str, object] = {}

        def _call_get() -> None:
            result["value"] = ssdeep_loader.get_ssdeep()

        thread = threading.Thread(target=_call_get, daemon=True)
        thread.start()
        ssdeep_loader._ssdeep_module = object()
    finally:
        ssdeep_loader._import_lock.release()
    thread.join(timeout=1.0)
    assert result["value"] is ssdeep_loader._ssdeep_module
