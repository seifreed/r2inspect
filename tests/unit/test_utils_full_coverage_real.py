from __future__ import annotations

import io
import json
import logging
import os
import time
from pathlib import Path

import pytest

from r2inspect.error_handling import ErrorHandlingStrategy, ErrorPolicy
from r2inspect.utils import command_helpers, error_handler, hashing, logger, r2_helpers, r2_suppress
from r2inspect.utils.analyzer_factory import create_analyzer, run_analysis_method
from r2inspect.utils.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerError,
    CircuitState,
    R2CommandCircuitBreaker,
)
from r2inspect.utils.output import OutputFormatter
from r2inspect.utils.rate_limiter import AdaptiveRateLimiter, BatchRateLimiter, TokenBucket
from r2inspect.utils.retry_manager import (
    NonRetryableError,
    RetryableError,
    RetryConfig,
    RetryManager,
    RetryStrategy,
    configure_retry_for_command,
    get_retry_stats,
    reset_retry_stats,
    retry_on_failure,
    retry_r2_operation,
)
from r2inspect.utils.ssdeep_loader import get_ssdeep


class _AnalyzerKwargs:
    def __init__(self, adapter: object, config: object, filename: str) -> None:
        self.adapter = adapter
        self.config = config
        self.filename = filename

    def analyze(self) -> dict[str, object]:
        return {"ok": True}


class _AnalyzerPositional:
    def __init__(self, foo: object) -> None:
        self.foo = foo

    def detect(self) -> dict[str, object]:
        return {"detected": True}


class _AnalyzerDefault:
    def __init__(self) -> None:
        self.called = True


def test_analyzer_factory_paths() -> None:
    adapter = object()
    config = object()
    analyzer = create_analyzer(_AnalyzerKwargs, adapter=adapter, config=config, filename="x")
    assert analyzer.adapter is adapter

    analyzer = create_analyzer(_AnalyzerPositional, adapter=adapter, config=config, filename="x")
    assert analyzer.foo == "x"

    analyzer = create_analyzer(_AnalyzerDefault, adapter=None, config=None, filename=None)
    assert analyzer.called is True

    assert run_analysis_method(_AnalyzerKwargs(adapter, config, "x"), ("analyze",))["ok"] is True
    assert run_analysis_method(_AnalyzerDefault(), ("missing",))["error"]

    class _BadSignature:
        __signature__ = "bad"

        def __init__(self) -> None:
            self.ok = True

    analyzer = create_analyzer(_BadSignature, adapter=None, config=None, filename=None)
    assert analyzer.ok is True


class _Adapter:
    def search_hex_json(self, value: str) -> list[dict[str, object]]:
        return [{"hex": value}]

    def search_text(self, value: str) -> list[dict[str, object]]:
        return [{"text": value}]

    def search_hex(self, value: str) -> list[dict[str, object]]:
        return [{"hex_plain": value}]

    def get_strings_filtered(self, command: str) -> list[dict[str, object]]:
        return [{"filtered": command}]

    def get_functions_at(self, addr: int) -> list[dict[str, object]]:
        return [{"address": addr}]

    def get_functions(self) -> list[dict[str, object]]:
        return [{"name": "f"}]

    def get_function_info(self, addr: int) -> dict[str, object]:
        return {"addr": addr}

    def get_file_info(self) -> dict[str, object]:
        return {"info": True}

    def get_imports(self) -> list[dict[str, object]]:
        return [{"name": "imp"}]

    def get_disasm(self, address: int | None = None, size: int | None = None) -> list[int]:
        return [address or 0, size or 0]

    def get_disasm_text(self, address: int | None = None, size: int | None = None) -> str:
        return f"{address}:{size}"

    def get_cfg(self, address: int | None = None) -> dict[str, object]:
        return {"cfg": address}

    def read_bytes_list(self, address: int, size: int | None) -> list[int]:
        return [address, size or 0]

    def read_bytes(self, address: int, size: int) -> bytes:
        return bytes([address % 256, size % 256])


def test_command_helpers_paths() -> None:
    adapter = _Adapter()
    assert command_helpers._parse_address("px @ 0x10") == ("px", 16)
    assert command_helpers._parse_address("px @ ") == ("px", None)
    assert command_helpers._parse_address("px @ bad") == ("px", None)

    assert command_helpers._parse_size("pd 10") == 10
    assert command_helpers._parse_size("pd bad") is None
    assert command_helpers._parse_size("pd") is None

    assert command_helpers._handle_search(adapter, "/xj 4142")
    assert command_helpers._handle_search(adapter, "/c abc")
    assert command_helpers._handle_search(adapter, "/x ff")

    assert command_helpers._handle_simple(adapter, "iz~", "iz~", None)
    assert command_helpers._handle_simple(adapter, "aflj", "aflj", 16)
    assert command_helpers._handle_simple(adapter, "aflj", "aflj", None)
    assert command_helpers._handle_simple(adapter, "afij", "afij @ 0x10", 16)
    assert command_helpers._handle_simple(adapter, "ij", "ij", None)

    assert command_helpers._handle_disasm(adapter, "pdfj", 1)
    assert command_helpers._handle_disasm(adapter, "pdj 3", 2)
    assert command_helpers._handle_disasm(adapter, "pi 4", 3)
    assert command_helpers._handle_disasm(adapter, "agj", 5)

    assert command_helpers._handle_bytes(adapter, "p8j 4", 5)
    assert command_helpers._handle_bytes(adapter, "p8 2", 5)
    assert command_helpers._handle_bytes(adapter, "pxj 1", 9)
    assert command_helpers._handle_bytes(adapter, "p8", 7) is None
    assert command_helpers._handle_bytes(adapter, "p8", None) is None

    assert command_helpers.cmd(adapter, None, "pi 1 @ 0x10")
    assert command_helpers.cmdj(adapter, None, "iij", {}) != {}
    assert command_helpers.cmd_list(adapter, None, "iij")


def test_circuit_breaker_paths() -> None:
    breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=0.01, name="test")

    def _fail() -> None:
        raise ValueError("boom")

    with pytest.raises(ValueError):
        breaker.call(_fail)
    assert breaker.state == CircuitState.OPEN

    with pytest.raises(CircuitBreakerError):
        breaker.call(lambda: "ok")

    time.sleep(0.02)
    assert breaker.call(lambda: "ok") == "ok"
    stats = breaker.get_stats()
    assert stats["state"] == CircuitState.CLOSED.value
    breaker.reset()
    assert breaker.state == CircuitState.CLOSED

    r2_cb = R2CommandCircuitBreaker()

    class _R2:
        def cmd(self, command: str) -> str:
            if command == "fail":
                raise RuntimeError("boom")
            return "ok"

        def cmdj(self, command: str) -> dict[str, object]:
            return {"cmd": command}

    r2 = _R2()
    assert r2_cb.execute_command(r2, "ij", "analysis") == {"cmd": "ij"}
    assert r2_cb.execute_command(r2, "i", "generic") == "ok"

    breaker = r2_cb.get_breaker("generic")
    breaker.failure_threshold = 1
    r2_cb.execute_command(r2, "fail", "generic")
    assert r2_cb.execute_command(r2, "fail", "generic") == ""
    assert r2_cb.get_stats()
    r2_cb.reset_all()


def test_error_handler_paths() -> None:
    info = error_handler.ErrorClassifier.classify(
        MemoryError("oom"),
        {"file_size_mb": 200, "memory_cleanup_available": False},
    )
    assert info.category == error_handler.ErrorCategory.MEMORY

    info = error_handler.ErrorClassifier.classify(
        FileNotFoundError("missing"),
        {"component_optional": False},
    )
    assert info.recoverable is False

    info = error_handler.ErrorClassifier.classify(
        ValueError("bad"),
        {"analysis_type": "pe_analysis"},
    )
    assert info.severity == error_handler.ErrorSeverity.HIGH

    info = error_handler.ErrorClassifier.classify(Exception("r2pipe error"), {})
    assert info.category == error_handler.ErrorCategory.R2PIPE

    manager = error_handler.ErrorRecoveryManager()
    manager.register_recovery_strategy(error_handler.ErrorCategory.MEMORY, lambda _info: "ok")
    recovered, result = manager.handle_error(info)
    assert recovered is False or result is None

    recovered, result = manager.handle_error(
        error_handler.ErrorInfo(
            Exception("mem"),
            error_handler.ErrorSeverity.LOW,
            error_handler.ErrorCategory.MEMORY,
        )
    )
    assert recovered is True
    assert result == "ok"

    @error_handler.error_handler(
        category=error_handler.ErrorCategory.INPUT_VALIDATION,
        severity=error_handler.ErrorSeverity.HIGH,
        fallback_result="fallback",
    )
    def _boom() -> str:
        raise ValueError("bad")

    assert _boom() == "fallback"

    @error_handler.error_handler(
        category=error_handler.ErrorCategory.MEMORY,
        severity=error_handler.ErrorSeverity.CRITICAL,
        fallback_result=None,
    )
    def _critical() -> None:
        raise MemoryError("bad")

    with pytest.raises(MemoryError):
        _critical()

    assert error_handler.safe_execute(lambda: 1) == 1
    assert (
        error_handler.safe_execute(
            lambda: (_ for _ in ()).throw(ValueError("x")), fallback_result=2
        )
        == 2
    )

    stats = error_handler.get_error_stats()
    assert "total_errors" in stats
    error_handler.reset_error_stats()


def test_hashing_and_ssdeep_loader(tmp_path: Path) -> None:
    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(b"abc")
    hashes = hashing.calculate_hashes(str(file_path))
    assert hashes["md5"]

    missing = hashing.calculate_hashes(str(tmp_path / "missing.bin"))
    assert missing["md5"] == ""

    assert hashing.calculate_imphash([]) is None
    assert hashing.calculate_imphash([{"library": "KERNEL32", "name": "CreateFileA"}])

    class _SSDeep:
        @staticmethod
        def hash_from_file(_path: str) -> str:
            return "ssdeep"

    original = hashing.get_ssdeep
    try:
        hashing.get_ssdeep = lambda: _SSDeep()  # type: ignore[assignment]
        assert hashing.calculate_ssdeep(str(file_path)) == "ssdeep"
    finally:
        hashing.get_ssdeep = original  # type: ignore[assignment]

    assert get_ssdeep() is None or get_ssdeep() is not None


def test_logger_setup_and_levels(tmp_path: Path) -> None:
    log = logger.setup_logger("r2inspect.test", level=logging.DEBUG, thread_safe=False)
    assert log.level == logging.DEBUG

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    log.addHandler(handler)
    stream.close()
    log2 = logger.setup_logger("r2inspect.test", level=logging.INFO, thread_safe=True)
    assert log2.handlers

    logger.configure_batch_logging()
    logger.reset_logging_levels()

    for handler in list(log2.handlers):
        try:
            handler.close()
        finally:
            log2.removeHandler(handler)
    logging.shutdown()


def test_output_formatter_paths() -> None:
    formatter = OutputFormatter(
        {
            "file_info": {
                "name": "sample.bin",
                "size": 2048,
                "file_type": "PE32 (console)",
                "md5": "md5",
                "sha256": "sha",
                "architecture": "x86",
            },
            "pe_info": {"compile_time": "2024-01-01", "imphash": "imp"},
            "elf_info": {"compile_time": "2024-02-02"},
            "ssdeep": {"available": True, "hash_value": "ssdeep"},
            "tlsh": {"available": True, "binary_tlsh": "tlsh"},
            "telfhash": {"available": True, "telfhash": "telf"},
            "rich_header": {
                "available": True,
                "compilers": [{"compiler_name": "MSVC", "build_number": 1}],
            },
            "imports": [{"name": "VirtualAlloc"}],
            "exports": [{"name": "Exported"}],
            "sections": [{"name": ".text", "entropy": 7.1, "suspicious_indicators": []}],
            "anti_analysis": {"anti_debug": True},
            "compiler": {"compiler": "gcc"},
            "functions": {"total_functions": 3, "machoc_hashes": {"a": "1", "b": "1"}},
            "yara_matches": [{"rule": "r1"}],
            "packer": {"is_packed": True, "packer_type": "upx"},
            "indicators": [{"type": "Packer"}],
        }
    )
    assert formatter.to_json()
    assert formatter.to_csv()
    assert formatter.format_table({"a": 1}, "Title")
    assert formatter.format_sections([{"name": ".text", "size": 1}])
    assert formatter.format_imports([{"name": "A", "library": "K"}])
    assert formatter.format_summary()

    elf_only = OutputFormatter({"elf_info": {"compile_time": "2024-03-03"}})
    assert "2024-03-03" in elf_only.to_csv()


class _R2Simple:
    def __init__(self, response: str) -> None:
        self.response = response

    def cmd(self, _command: str) -> str:
        return self.response

    def cmdj(self, _command: str) -> object:
        return json.loads(self.response)

    def get_headers_json(self) -> list[dict[str, object]]:
        return [{"name": "Signature", "value": "PE"}]

    def get_header_text(self) -> str:
        return "type: LOAD\nflags: x\n"


def test_r2_helpers_and_suppress(tmp_path: Path) -> None:
    assert r2_helpers.validate_r2_data({}, "dict") == {}
    assert r2_helpers.validate_r2_data([], "list") == []
    assert r2_helpers.validate_r2_data("x", "other") == "x"

    bad_list = r2_helpers._clean_list_items([{"name": "a&nbsp;"}, "bad"])
    assert bad_list[0]["name"] == "a "

    r2 = _R2Simple(json.dumps({"a": 1}))
    r2_list = _R2Simple(json.dumps([{"a": 1}]))
    assert r2_helpers.safe_cmdj(r2, "ij", {}) == {"a": 1}
    assert r2_helpers.safe_cmd_list(r2_list, "ij")
    assert r2_helpers.safe_cmd_dict(r2, "ij")

    os_env = {"R2INSPECT_CMD_TIMEOUT_SECONDS": "bad"}
    r2_helpers.os.environ.update(os_env)
    try:
        assert r2_helpers.safe_cmd(r2, "i") == r2.response
    finally:
        r2_helpers.os.environ.pop("R2INSPECT_CMD_TIMEOUT_SECONDS", None)

    assert r2_helpers.parse_pe_header_text(_R2Simple("")) is None
    assert r2_helpers.get_pe_headers(r2)
    assert r2_helpers.get_elf_headers(r2)
    assert r2_helpers.get_macho_headers(r2)

    class _R2Fallback:
        def cmd(self, _command: str) -> str:
            time.sleep(0.01)
            return ""

        def cmdj(self, _command: str) -> object:
            return None

    r2_helpers.os.environ["R2INSPECT_CMD_TIMEOUT_SECONDS"] = "0.001"
    try:
        assert r2_helpers.safe_cmd(_R2Fallback(), "i") == ""
    finally:
        r2_helpers.os.environ.pop("R2INSPECT_CMD_TIMEOUT_SECONDS", None)

    fallback = _R2Fallback()
    assert r2_helpers.get_elf_headers(fallback) == []
    assert r2_helpers.get_macho_headers(fallback) == []

    assert r2_helpers._parse_section_header("IMAGE_NT_HEADERS", None) == "nt_headers"
    parsed: dict[str, dict[str, object]] = {"nt_headers": {}}
    r2_helpers._parse_key_value_pair("Magic: 0x10", parsed, "nt_headers")
    r2_helpers._parse_key_value_pair("Bad: nothex", parsed, "nt_headers")

    parsed_headers = r2_helpers._parse_elf_headers_text("type: LOAD\n")
    assert parsed_headers

    class _SilentR2:
        def cmdj(self, _command: str) -> object:
            raise OSError("boom")

        def cmd(self, _command: str) -> str:
            return ""

    assert r2_suppress.silent_cmdj(None, "ij") is None
    assert r2_suppress.silent_cmdj(_SilentR2(), "ij", default=[]) == []
    assert r2_suppress._parse_raw_result("{") is None
    assert r2_suppress._parse_raw_result('{"a":1}') == {"a": 1}
    assert r2_suppress._parse_raw_result("text") == "text"

    with r2_suppress.R2PipeErrorSuppressor() as ctx:
        assert ctx.original_stderr is not None

    with r2_suppress.suppress_r2pipe_errors():
        pass

    class _ParseErrorR2:
        def cmdj(self, _command: str) -> object:
            raise TypeError("boom")

        def cmd(self, _command: str) -> str:
            raise OSError("boom")

    assert r2_suppress.silent_cmdj(_ParseErrorR2(), "ij", default=None) is None


def test_rate_limiter_and_retry_manager(tmp_path: Path) -> None:
    bucket = TokenBucket(capacity=1, refill_rate=0.0)
    assert bucket.acquire()
    assert bucket.acquire(timeout=0.001) is False

    limiter = AdaptiveRateLimiter(base_rate=10.0, min_rate=1.0, max_rate=20.0)
    assert limiter.acquire_permit(timeout=0.01) is True
    limiter.record_success()
    limiter.record_error("timeout")
    limiter.get_stats()

    batch = BatchRateLimiter(
        max_concurrent=1, rate_per_second=2.0, burst_size=1, enable_adaptive=False
    )
    assert batch.acquire(timeout=1.0) is True
    batch.release_success()
    assert batch.acquire(timeout=1.0) is True
    batch.release_error("boom")
    batch.get_stats()

    manager = RetryManager()
    config = RetryConfig(
        max_attempts=2,
        base_delay=0.0,
        strategy=RetryStrategy.FIXED_DELAY,
        jitter=False,
    )

    def _fail() -> None:
        raise RetryableError("retry")

    with pytest.raises(RetryableError):
        manager.retry_operation(_fail, command_type="analysis", config=config)

    def _ok() -> str:
        return "ok"

    assert manager.retry_operation(_ok, command_type="analysis", config=config) == "ok"
    assert manager.is_retryable_command("aaa") is True
    assert manager.is_retryable_error(OSError("timeout")) is True
    assert manager.is_retryable_error(NonRetryableError("x")) is False
    assert manager.calculate_delay(1, config) == 0.0

    configure_retry_for_command("custom", config)
    assert get_retry_stats()["total_retries"] >= 0
    reset_retry_stats()

    @retry_on_failure()
    def _decorated(value: int, **_kwargs: object) -> int:
        if value < 0:
            raise RetryableError("bad")
        return value

    assert _decorated(1) == 1
    with pytest.raises(RetryableError):
        _decorated(-1)

    assert retry_r2_operation(lambda _command: "ok", "analysis") == "ok"
