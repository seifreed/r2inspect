import json
import logging
import sys
from types import ModuleType

import pytest

from r2inspect.utils import analyzer_factory, circuit_breaker, command_helpers, error_handler
from r2inspect.utils import hashing as hashing_utils
from r2inspect.utils import logger as logger_utils
from r2inspect.utils import magic_detector, memory_manager
from r2inspect.utils import output as output_utils
from r2inspect.utils import r2_helpers, r2_suppress, rate_limiter, retry_manager, ssdeep_loader


class DummyAdapter:
    def __init__(self) -> None:
        self.calls = []

    def search_hex_json(self, value: str):
        self.calls.append(("search_hex_json", value))
        return {"hex": value}

    def search_text(self, value: str):
        self.calls.append(("search_text", value))
        return [value]

    def search_hex(self, value: str):
        self.calls.append(("search_hex", value))
        return value

    def get_functions(self):
        self.calls.append(("get_functions", None))
        return ["f1"]

    def get_disasm(self, address=None, size=None):
        self.calls.append(("get_disasm", address, size))
        return [{"addr": address, "size": size}]

    def read_bytes(self, address, size):
        self.calls.append(("read_bytes", address, size))
        return b"\x01\x02"

    def read_bytes_list(self, address, size):
        self.calls.append(("read_bytes_list", address, size))
        return [1, 2]


class DummyR2:
    def __init__(self, cmd_text: str | None = None, cmdj_value=None) -> None:
        self._cmd_text = cmd_text or ""
        self._cmdj_value = cmdj_value

    def cmd(self, _cmd: str):
        return self._cmd_text

    def cmdj(self, _cmd: str):
        if isinstance(self._cmdj_value, Exception):
            raise self._cmdj_value
        return self._cmdj_value

    def get_headers_json(self):
        return self._cmdj_value

    def get_header_text(self):
        return self._cmd_text


class DummyAnalyzer:
    def __init__(self, adapter=None, config=None, filename=None) -> None:
        self.adapter = adapter
        self.config = config
        self.filename = filename

    def analyze(self):
        return {"ok": True}


class DummyAnalyzerAlt:
    def __init__(self, backend, config):
        self.backend = backend
        self.config = config


class DummyAnalyzerNoArgs:
    def __init__(self):
        self.value = 1


def test_command_helpers_adapter_paths() -> None:
    adapter = DummyAdapter()

    assert command_helpers.cmdj(adapter, None, "/xj 4142", {}) == {"hex": "4142"}
    assert command_helpers.cmdj(adapter, None, "/c hello", []) == ["hello"]
    assert command_helpers.cmd(adapter, None, "/x ab") == "ab"
    assert command_helpers.cmdj(adapter, None, "aflj", []) == ["f1"]

    result = command_helpers.cmdj(adapter, None, "pdj 4 @ 0x10", {})
    assert result[0]["addr"] == 0x10

    result = command_helpers.cmdj(adapter, None, "p8 2 @ 0x10", {})
    assert result == "0102"

    result = command_helpers.cmd_list(adapter, None, "p8j 2 @ 0x10")
    assert result == [1, 2]

    assert command_helpers.cmd_list(adapter, None, "unknown") == []


def test_command_helpers_parsing_helpers() -> None:
    assert command_helpers._parse_address("ij") == ("ij", None)
    assert command_helpers._parse_address("ij @ 0x10") == ("ij", 0x10)
    assert command_helpers._parse_address("ij @ bad") == ("ij", None)
    assert command_helpers._parse_address("ij @") == ("ij", None)

    assert command_helpers._parse_size("pdj 4") == 4
    assert command_helpers._parse_size("pdj bad") is None


def test_output_formatter_json_and_csv(tmp_path) -> None:
    class BadStr:
        def __str__(self) -> str:
            raise RuntimeError("nope")

    formatter = output_utils.OutputFormatter({"bad": BadStr()})
    text = formatter.to_json()
    assert "JSON serialization failed" in text

    formatter = output_utils.OutputFormatter(
        {
            "file_info": {
                "name": "file.exe",
                "size": 1024,
                "file_type": "PE32+ executable, 7 sections",
                "md5": "md5",
                "sha1": "sha1",
                "sha256": "sha256",
                "sha512": "sha512",
            },
            "pe_info": {"compile_time": "now", "imphash": "imp"},
            "ssdeep": {"hash_value": "ss"},
            "tlsh": {"binary_tlsh": "bt", "text_section_tlsh": "tt", "stats": {}},
            "telfhash": {"telfhash": "tf", "filtered_symbols": 2},
            "rich_header": {
                "xor_key": 1,
                "checksum": 2,
                "richpe_hash": "rh",
                "compilers": [{"compiler_name": "MSVC", "count": 2}],
            },
            "imports": [{"name": "imp"}],
            "exports": ["exp"],
            "sections": [{"name": ".text"}],
            "anti_analysis": {"anti_debug": True, "anti_vm": False, "anti_sandbox": False},
            "yara_matches": [{"rule": "R1"}],
            "compiler": {"compiler": "c", "version": "1", "confidence": 0.9},
            "functions": {"total_functions": 3, "machoc_hashes": {"a": "x", "b": "x"}},
        }
    )

    csv_text = formatter.to_csv()
    assert "file.exe" in csv_text
    assert "PE32+ executable" in csv_text

    summary = formatter.format_summary()
    assert "R2INSPECT ANALYSIS SUMMARY" in summary

    table = formatter.format_table({"key": "value"})
    assert table.title == "Analysis Results"

    table = formatter.format_sections([{"name": ".text", "raw_size": 10}])
    assert table.title == "Section Analysis"

    table = formatter.format_imports(
        [{"name": "A", "library": "B", "category": "C", "risk_score": 50, "risk_level": "High"}]
    )
    assert table.title == "Import Analysis"

    formatter = output_utils.OutputFormatter("bad")
    csv_text = formatter.to_csv()
    assert "CSV Export Failed" in csv_text


def test_hashing_utils(tmp_path) -> None:
    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(b"abc")

    hashes = hashing_utils.calculate_hashes(str(file_path))
    assert hashes["md5"]

    assert hashing_utils.calculate_hashes("/does/not/exist")

    directory_hashes = hashing_utils.calculate_hashes(str(tmp_path))
    assert directory_hashes["md5"].startswith("Error:")

    imports = [{"library": "KERNEL32", "name": "CreateFile"}]
    imphash = hashing_utils.calculate_imphash(imports)
    assert imphash

    assert hashing_utils.calculate_imphash([]) is None
    assert hashing_utils.calculate_imphash([{"library": "", "name": ""}]) is None

    class BadImport:
        def get(self, _key: str, _default: str = "") -> str:
            raise RuntimeError("boom")

    assert hashing_utils.calculate_imphash([BadImport()]) is None

    ssdeep = hashing_utils.calculate_ssdeep(str(file_path))
    assert ssdeep is None or isinstance(ssdeep, str)


def test_ssdeep_loader_cache() -> None:
    sentinel = object()
    ssdeep_loader._ssdeep_module = sentinel
    assert ssdeep_loader.get_ssdeep() is sentinel

    ssdeep_loader._ssdeep_module = None
    fake = ModuleType("ssdeep")

    def _hash_from_file(_path: str):
        return "hash"

    fake.hash_from_file = _hash_from_file
    sys.modules["ssdeep"] = fake
    try:
        module = ssdeep_loader.get_ssdeep()
        assert module is fake
    finally:
        sys.modules.pop("ssdeep", None)
        ssdeep_loader._ssdeep_module = None

    class BadModule:
        def hash_from_file(self, _path: str) -> str:
            raise RuntimeError("boom")

    ssdeep_loader._ssdeep_module = BadModule()
    assert hashing_utils.calculate_ssdeep("/tmp/missing") is None


def test_error_handler_and_recovery() -> None:
    error_handler.reset_error_stats()

    info = error_handler.ErrorClassifier.classify(ValueError("bad"))
    assert info.category == error_handler.ErrorCategory.INPUT_VALIDATION

    info = error_handler.ErrorClassifier.classify(
        ValueError("bad"), {"analysis_type": "pe_analysis"}
    )
    assert info.severity == error_handler.ErrorSeverity.HIGH

    @error_handler.error_handler(fallback_result="fallback")
    def fail() -> str:
        raise ValueError("bad")

    assert fail() == "fallback"

    @error_handler.error_handler()
    def critical() -> None:
        raise MemoryError("oops")

    with pytest.raises(MemoryError):
        critical()

    def ok_func():
        return "ok"

    assert error_handler.safe_execute(ok_func) == "ok"
    assert error_handler.safe_execute(lambda: (_ for _ in ()).throw(ValueError("x"))) is None

    info = error_handler.ErrorClassifier.classify(
        Exception("r2pipe cmdj error"), {"phase": "initialization"}
    )
    assert info.category == error_handler.ErrorCategory.R2PIPE
    assert info.severity == error_handler.ErrorSeverity.CRITICAL

    info = error_handler.ErrorClassifier.classify(
        FileNotFoundError("missing"), {"batch_mode": True}
    )
    assert info.severity in {error_handler.ErrorSeverity.MEDIUM, error_handler.ErrorSeverity.HIGH}

    manager = error_handler.ErrorRecoveryManager()

    def recovery(_info: error_handler.ErrorInfo) -> str:
        return "recovered"

    manager.register_recovery_strategy(error_handler.ErrorCategory.INPUT_VALIDATION, recovery)
    err = error_handler.ErrorClassifier.classify(ValueError("oops"))
    recovered, result = manager.handle_error(err)
    assert recovered is True
    assert result == "recovered"


def test_r2_suppress_and_helpers() -> None:
    r2 = DummyR2(cmd_text='{"a": 1}', cmdj_value=TypeError("bad"))
    result = r2_suppress.silent_cmdj(r2, "ij", default=None)
    assert result == {"a": 1}

    r2 = DummyR2(cmdj_value=OSError("bad"), cmd_text='{"b": 2}')
    result = r2_suppress.silent_cmdj(r2, "ij", default=None)
    assert result is None

    assert r2_suppress.silent_cmdj(None, "ij", default=[]) == []

    assert r2_suppress._parse_raw_result('{"c": 3}') == {"c": 3}
    assert r2_suppress._parse_raw_result("text") == "text"
    assert r2_suppress._parse_raw_result(" ") is None

    with r2_suppress.suppress_r2pipe_errors():
        assert True


def test_r2_helpers_parsing() -> None:
    r2 = DummyR2(cmd_text='{"key": 1}')
    assert r2_helpers.safe_cmdj(r2, "ij", {}) == {"key": 1}

    r2 = DummyR2(cmd_text='[{"a": 1}]')
    assert r2_helpers.safe_cmd_list(r2, "ij") == [{"a": 1}]

    text = "IMAGE_NT_HEADERS\nSignature: 0x5\nIMAGE_FILE_HEADERS\nMachine: 0x14c"
    r2 = DummyR2(cmd_text=text)
    parsed = r2_helpers.parse_pe_header_text(r2)
    assert parsed["file_header"]["Machine"] == 0x14C

    headers_list = [{"name": "Machine", "value": 0x14C}, {"name": "Magic", "value": 0x20B}]
    r2 = DummyR2(cmdj_value=headers_list)
    pe_headers = r2_helpers.get_pe_headers(r2)
    assert pe_headers["file_header"]["Machine"] == 0x14C

    r2 = DummyR2(cmdj_value={"type": "LOAD"})
    assert r2_helpers.get_macho_headers(r2)

    text = "Type: LOAD\nFlags: R\nOffset: 0x1"
    r2 = DummyR2(cmd_text=text, cmdj_value=None)
    elf_headers = r2_helpers.get_elf_headers(r2)
    assert elf_headers

    assert r2_helpers.validate_r2_data("value", "unknown") == "value"


def test_analyzer_factory_and_runner() -> None:
    analyzer = analyzer_factory.create_analyzer(DummyAnalyzer, adapter="backend", config=1)
    assert analyzer.adapter == "backend"

    analyzer = analyzer_factory.create_analyzer(DummyAnalyzerAlt, adapter="b", config=2)
    assert analyzer.backend == "b"

    analyzer = analyzer_factory.create_analyzer(DummyAnalyzerNoArgs, adapter="b")
    assert analyzer.value == 1

    class PositionalAnalyzer:
        def __init__(self, backend, config, filename):
            self.args = (backend, config, filename)

    analyzer = analyzer_factory.create_analyzer(
        PositionalAnalyzer, adapter="b", config=2, filename="file"
    )
    assert analyzer.args == ("b", 2, "file")

    result = analyzer_factory.run_analysis_method(DummyAnalyzerNoArgs(), ["missing", "analyze"])
    assert result == {"error": "No suitable analysis method found"}


def test_circuit_breaker_and_command_breaker() -> None:
    breaker = circuit_breaker.CircuitBreaker(failure_threshold=2, recovery_timeout=0)

    def fail():
        raise ValueError("bad")

    with pytest.raises(ValueError):
        breaker.call(fail)

    with pytest.raises(ValueError):
        breaker.call(fail)

    assert breaker.state == circuit_breaker.CircuitState.OPEN

    # Next call attempts half-open, still fails
    with pytest.raises(ValueError):
        breaker.call(fail)

    stats = breaker.get_stats()
    assert stats["total_failures"] >= 2

    r2 = DummyR2(cmd_text="ok", cmdj_value={"a": 1})
    command_breaker = circuit_breaker.R2CommandCircuitBreaker()
    assert command_breaker.execute_command(r2, "ij", "info") == {"a": 1}
    assert command_breaker.execute_command(r2, "i") == "ok"

    stats = command_breaker.get_stats()
    assert "command_info" in stats


def test_rate_limiter_and_retry_manager() -> None:
    bucket = rate_limiter.TokenBucket(capacity=1, refill_rate=1.0)
    assert bucket.acquire(tokens=1, timeout=0.1) is True

    adaptive = rate_limiter.AdaptiveRateLimiter(base_rate=1.0, max_rate=2.0, min_rate=0.1)
    adaptive.record_success()
    adaptive.record_error()
    stats = adaptive.get_stats()
    assert "current_rate" in stats

    limiter = rate_limiter.BatchRateLimiter(max_concurrent=1, rate_per_second=1.0, burst_size=1)
    assert limiter.acquire(timeout=0.1) is True
    limiter.release_success()
    assert limiter.get_stats()["files_processed"] == 1

    limiter = rate_limiter.BatchRateLimiter(
        max_concurrent=1, rate_per_second=1.0, burst_size=0, enable_adaptive=False
    )
    assert limiter.acquire(timeout=0.01) is False

    assert rate_limiter.cleanup_memory() is None or isinstance(rate_limiter.cleanup_memory(), dict)

    manager = retry_manager.RetryManager()

    attempts = {"count": 0}

    def flaky():
        attempts["count"] += 1
        if attempts["count"] < 2:
            raise ConnectionError("timeout")
        return "ok"

    config = retry_manager.RetryConfig(max_attempts=2, base_delay=0.0, jitter=False)
    assert manager.retry_operation(flaky, config=config) == "ok"

    with pytest.raises(ValueError):
        manager.retry_operation(lambda: (_ for _ in ()).throw(ValueError("bad")))

    assert manager.is_retryable_command("aaa") is True

    assert manager.is_retryable_error(Exception("expecting value: line 1 column 1")) is True

    config = retry_manager.RetryConfig(max_attempts=1, timeout=-1, jitter=False)
    with pytest.raises(TimeoutError):
        manager.retry_operation(lambda: "ok", config=config)

    @retry_manager.retry_on_failure(command_type="generic", auto_retry=False)
    def passthrough(*_args: object, **_kwargs: object) -> str:
        return "ok"

    assert passthrough("ij") == "ok"

    retry_manager.configure_retry_for_command("custom", retry_manager.RetryConfig(max_attempts=1))


def test_memory_manager_and_logger() -> None:
    limits = memory_manager.MemoryLimits(max_process_memory_mb=1)
    monitor = memory_manager.MemoryMonitor(limits=limits)

    assert monitor.validate_file_size(10) is True
    assert monitor.validate_file_size(10 * 1024 * 1024 * 1024) is False

    assert monitor.validate_section_size(10) is True

    limited = monitor.limit_collection_size(list(range(5)), max_size=2, name="items")
    assert limited == [0, 1]

    analyzer = memory_manager.MemoryAwareAnalyzer(memory_monitor=monitor)
    assert analyzer.should_skip_analysis(estimated_memory_mb=100.0) is True
    assert analyzer.safe_large_operation(lambda: "ok", estimated_memory_mb=100.0) is None

    stats = memory_manager.cleanup_memory()
    assert "process_memory_mb" in stats

    logger = logger_utils.setup_logger("test_logger_block341", level=logging.INFO)
    assert logger.name == "test_logger_block341"
    assert logger.handlers

    closed_handler = logging.StreamHandler(stream=sys.stderr)
    closed_handler.close()
    logger_closed = logging.getLogger("test_logger_closed_block341")
    logger_closed.addHandler(closed_handler)
    logger_utils.setup_logger("test_logger_closed_block341", level=logging.INFO)

    class BadPath:
        @staticmethod
        def home():
            raise RuntimeError("boom")

    original_path = logger_utils.Path
    logger_utils.Path = BadPath  # type: ignore[assignment]
    try:
        logger_utils.setup_logger("test_logger_fallback_block341", level=logging.INFO)
    finally:
        logger_utils.Path = original_path

    logger_utils.configure_batch_logging()
    logger_utils.reset_logging_levels()


def test_magic_detector_with_temp_files(tmp_path) -> None:
    detector = magic_detector.MagicByteDetector()

    pe_path = tmp_path / "sample.exe"
    header = bytearray(128)
    header[0:2] = b"MZ"
    header[60:64] = (64).to_bytes(4, "little")
    header[64:68] = b"PE\x00\x00"
    pe_path.write_bytes(header)

    result = detector.detect_file_type(str(pe_path))
    assert result["file_format"].startswith("PE")
    assert result["is_executable"] is True

    elf_path = tmp_path / "sample.elf"
    elf_path.write_bytes(b"\x7fELF\x02" + b"\x00" * 20)
    result = detector.detect_file_type(str(elf_path))
    assert result["file_format"].startswith("ELF")

    doc_path = tmp_path / "sample.docx"
    doc_path.write_bytes(b"PK\x03\x04" + b"word/" + b"[Content_Types].xml")
    result = detector.detect_file_type(str(doc_path))
    assert result["file_format"] in {"DOCX", "ZIP"}

    unknown = tmp_path / "script.ps1"
    unknown.write_bytes(b"#! /bin/bash")
    result = detector.detect_file_type(str(unknown))
    assert result["format_category"] in {"Executable", "Script", "Unknown"}

    assert magic_detector.is_executable_file(str(pe_path)) is True
    assert magic_detector.get_file_threat_level(str(pe_path)) in {"High", "Medium", "Low"}

    # Cache hit
    cached = detector.detect_file_type(str(pe_path))
    assert cached["file_format"].startswith("PE")

    detector.clear_cache()


def test_logger_output_formatter_helpers() -> None:
    formatter = output_utils.OutputFormatter({"file_info": {"file_type": "PE, 7 sections"}})
    cleaned = formatter._clean_file_type("PE, 7 sections")
    assert cleaned == "PE"

    assert formatter._format_file_size(0) == "0 B"
    assert formatter._format_file_size(1024).endswith("KB")
    assert formatter._format_file_size("bad") == "bad"

    names = formatter._extract_names_from_list(
        {"items": [{"name": "a"}, {"name": "b"}, "c"]}, "items"
    )
    assert names == "a, b, c"
