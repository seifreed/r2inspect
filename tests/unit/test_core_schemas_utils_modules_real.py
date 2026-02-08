import hashlib
import os
from datetime import datetime
from pathlib import Path

import pytest

from r2inspect.core.constants import MIN_EXECUTABLE_SIZE_BYTES, MIN_HEADER_SIZE_BYTES
from r2inspect.core.file_validator import FileValidator
from r2inspect.core.inspector_helpers import InspectorExecutionMixin
from r2inspect.core.result_aggregator import ResultAggregator
from r2inspect.modules.anti_analysis_helpers import (
    add_simple_evidence,
    collect_artifact_strings,
    count_opcode_occurrences,
    detect_api_hashing,
    detect_environment_checks,
    detect_injection_apis,
    detect_obfuscation,
    detect_self_modifying,
    match_suspicious_api,
)
from r2inspect.modules.domain_helpers import (
    clamp_score,
    count_suspicious_imports,
    entropy_from_ints,
    shannon_entropy,
    suspicious_section_name_indicator,
)
from r2inspect.modules.string_domain import (
    build_xor_matches,
    decode_base64,
    decode_hex,
    filter_strings,
    find_suspicious,
    is_base64,
    is_hex,
    parse_search_results,
    xor_string,
)
from r2inspect.schemas.format import FormatAnalysisResult, SectionInfo, SecurityFeatures
from r2inspect.schemas.hashing import HashAnalysisResult
from r2inspect.schemas.results import AnalysisResult, FileInfo, HashingResult, from_dict
from r2inspect.schemas.security import (
    SecurityAnalysisResult,
    SecurityIssue,
    SecurityScore,
    SeverityLevel,
)
from r2inspect.utils.analyzer_factory import create_analyzer, run_analysis_method
from r2inspect.utils.command_helpers import cmd, cmd_list, cmdj
from r2inspect.utils.error_handler import (
    ErrorCategory,
    ErrorClassifier,
    ErrorSeverity,
    error_handler,
    get_error_stats,
    reset_error_stats,
    safe_execute,
)
from r2inspect.utils.hashing import calculate_hashes, calculate_imphash, calculate_ssdeep
from r2inspect.utils.memory_manager import (
    MemoryAwareAnalyzer,
    MemoryLimits,
    MemoryMonitor,
    configure_memory_limits,
    global_memory_monitor,
)


def test_file_validator_missing_dir_size_and_readable(tmp_path: Path) -> None:
    missing = tmp_path / "missing.bin"
    assert FileValidator(missing).validate() is False

    dir_path = tmp_path / "not_a_file"
    dir_path.mkdir()
    assert FileValidator(dir_path).validate() is False

    empty_file = tmp_path / "empty.bin"
    empty_file.write_bytes(b"")
    assert FileValidator(empty_file).validate() is False

    small_file = tmp_path / "small.bin"
    small_file.write_bytes(b"\x00" * (MIN_EXECUTABLE_SIZE_BYTES - 1))
    validator = FileValidator(small_file)
    assert validator._is_size_valid(small_file.stat().st_size) is False
    assert validator._file_size_mb() >= 0.0

    unreadable = tmp_path / "unreadable.bin"
    unreadable.write_bytes(b"\x00" * MIN_HEADER_SIZE_BYTES)
    try:
        os.chmod(unreadable, 0)
        assert FileValidator(unreadable)._is_readable() is False
    finally:
        os.chmod(unreadable, 0o600)


def test_file_validator_memory_limit_failure(tmp_path: Path) -> None:
    original_limit = global_memory_monitor.limits.max_file_size_mb
    configure_memory_limits(max_file_size_mb=0)
    try:
        sized = tmp_path / "sized.bin"
        sized.write_bytes(b"\x00" * MIN_EXECUTABLE_SIZE_BYTES)
        assert FileValidator(sized).validate() is False
    finally:
        configure_memory_limits(max_file_size_mb=original_limit)


def test_result_aggregator_indicators_and_summary() -> None:
    results = {
        "file_info": {
            "name": "sample.bin",
            "file_type": "PE",
            "size": 1234,
            "architecture": "x86",
            "md5": "md5",
            "sha256": "sha256",
        },
        "pe_info": {"compilation_timestamp": "2025-01-01"},
        "rich_header": {
            "available": True,
            "compilers": [{"compiler_name": "MSVC", "build_number": 123}],
        },
        "security": {"authenticode": False, "aslr": True, "dep": True, "cfg": False},
        "packer": {"is_packed": True, "packer_type": "UPX"},
        "anti_analysis": {"anti_debug": True, "anti_vm": True},
        "imports": [{"name": "VirtualAlloc"}],
        "yara_matches": [{"rule": "evil"}],
        "sections": [{"entropy": 7.5, "name": ".textbss", "suspicious_indicators": ["x"]}],
        "functions": {"count": 2},
        "crypto": {"matches": [1, 2]},
    }
    aggregator = ResultAggregator()
    indicators = aggregator.generate_indicators(results)
    assert any(ind["type"] == "Packer" for ind in indicators)
    summary = aggregator.generate_executive_summary(results)
    assert summary["file_overview"]["toolset"][0].startswith("MSVC")
    assert summary["threat_indicators"]["entropy_warnings"] == 1


def test_result_aggregator_summary_error_path() -> None:
    aggregator = ResultAggregator()
    bad_results = {
        "file_info": {},
        "pe_info": {},
        "rich_header": {"available": True, "compilers": [None]},
    }
    summary = aggregator.generate_executive_summary(bad_results)
    assert "error" in summary


class _SimpleAnalyzer:
    def __init__(self, adapter=None, config=None, filename=None) -> None:
        self.adapter = adapter
        self.config = config
        self.filename = filename

    def analyze(self) -> dict[str, str]:
        return {"ok": "yes"}

    def custom(self) -> list[str]:
        return ["custom"]


class _AnalyzerWithoutMethod:
    pass


class _Registry:
    def __init__(self, mapping: dict[str, type]) -> None:
        self._mapping = mapping

    def get_analyzer_class(self, name: str) -> type | None:
        return self._mapping.get(name)

    def list_analyzers(self) -> list[dict[str, str]]:
        return []


class _Inspector(InspectorExecutionMixin):
    def __init__(self, registry: _Registry) -> None:
        self.registry = registry
        self.adapter = object()
        self.config = object()
        self.filename = "sample.bin"
        self._result_aggregator = ResultAggregator()


def test_inspector_helpers_execute_analyzer_paths() -> None:
    inspector = _Inspector(_Registry({}))
    assert inspector._execute_analyzer("missing") == {}

    inspector = _Inspector(_Registry({"simple": _SimpleAnalyzer}))
    assert inspector._execute_analyzer("simple") == {"ok": "yes"}
    assert inspector._execute_analyzer("simple", "custom") == ["custom"]
    assert inspector._execute_analyzer("simple", "nope") == {}

    inspector = _Inspector(_Registry({"bad": _AnalyzerWithoutMethod}))
    assert inspector._execute_analyzer("bad", "nope") == {}

    assert inspector._as_bool_dict({"a": 1, "b": 0}) == {"a": True, "b": False}
    assert inspector._as_bool_dict("nope") == {}
    assert inspector._as_str(5, "fallback") == "fallback"


def test_inspector_helpers_detect_crypto_analyzer_missing() -> None:
    inspector = _Inspector(_Registry({}))
    result = inspector.detect_crypto()
    assert result["error"] == "Analyzer not found"


def test_analyzer_factory_build_and_run() -> None:
    class _FilenameAnalyzer:
        def __init__(self, filename: str) -> None:
            self.filename = filename

        def analyze(self) -> str:
            return self.filename

    instance = create_analyzer(_FilenameAnalyzer, filename="sample.bin")
    assert instance.analyze() == "sample.bin"
    assert run_analysis_method(instance, ("missing", "analyze")) == "sample.bin"


def test_memory_monitor_warning_and_critical_callbacks() -> None:
    warnings: list[str] = []
    criticals: list[str] = []

    warn_limits = MemoryLimits(
        max_process_memory_mb=1000,
        memory_warning_threshold=0.0001,
        memory_critical_threshold=1.0,
    )
    monitor = MemoryMonitor(warn_limits)
    monitor.set_callbacks(
        warning_callback=lambda _stats: warnings.append("warn"),
        critical_callback=lambda _stats: criticals.append("crit"),
    )
    warn_stats = monitor.check_memory(force=True)
    assert warn_stats["status"] in {"warning", "critical"}
    assert warnings

    critical_limits = MemoryLimits(
        max_process_memory_mb=1,
        memory_warning_threshold=0.1,
        memory_critical_threshold=0.2,
    )
    critical_monitor = MemoryMonitor(critical_limits)
    critical_monitor.set_callbacks(
        warning_callback=lambda _stats: warnings.append("warn2"),
        critical_callback=lambda _stats: criticals.append("crit2"),
    )
    critical_stats = critical_monitor.check_memory(force=True)
    assert critical_stats["status"] == "critical"
    assert criticals

    cached_stats = critical_monitor.check_memory()
    assert cached_stats["status"] == "cached"


def test_memory_monitor_limits_and_safe_operations() -> None:
    monitor = MemoryMonitor(MemoryLimits(max_file_size_mb=0, section_size_limit_mb=0))
    assert monitor.validate_file_size(10) is False
    assert monitor.validate_section_size(10) is False
    assert monitor.limit_collection_size([1, 2, 3], 2, "items") == [1, 2]

    analyzer = MemoryAwareAnalyzer(monitor)
    assert analyzer.should_skip_analysis(1000, "big") is True

    def _raise_memory() -> None:
        raise MemoryError("boom")

    assert analyzer.safe_large_operation(_raise_memory, 0.1, "mem") is None

    def _raise_value() -> None:
        raise ValueError("bad")

    assert analyzer.safe_large_operation(_raise_value, 0.1, "val") is None


def test_error_handler_classifier_and_recovery() -> None:
    error_info = ErrorClassifier.classify(
        MemoryError("oom"),
        {"analysis_type": "pe_analysis", "file_size_mb": 200, "memory_cleanup_available": False},
    )
    assert error_info.category == ErrorCategory.MEMORY
    assert error_info.severity == ErrorSeverity.HIGH
    assert error_info.recoverable is False

    @error_handler(context={"command": "ij"})
    def _fail_r2() -> None:
        raise RuntimeError("r2pipe failure")

    assert _fail_r2() is None

    def _missing() -> None:
        raise FileNotFoundError("nope")

    assert safe_execute(_missing) is None

    @error_handler(fallback_result="fallback")
    def _bad_value() -> None:
        raise ValueError("bad")

    assert _bad_value() == "fallback"

    stats = get_error_stats()
    assert stats["total_errors"] >= 1
    reset_error_stats()
    assert get_error_stats()["total_errors"] == 0


def test_hashing_utils_real_file(tmp_path: Path) -> None:
    file_path = tmp_path / "data.bin"
    file_path.write_bytes(b"abc")
    hashes = calculate_hashes(str(file_path))
    assert hashes["md5"] == hashlib.md5(b"abc", usedforsecurity=False).hexdigest()
    assert hashes["sha1"] == hashlib.sha1(b"abc", usedforsecurity=False).hexdigest()
    assert hashes["sha256"] == hashlib.sha256(b"abc").hexdigest()
    assert hashes["sha512"] == hashlib.sha512(b"abc").hexdigest()

    assert calculate_hashes(str(tmp_path / "missing.bin"))["md5"] == ""

    imports = [{"library": "KERNEL32.DLL", "name": "VirtualAlloc"}]
    expected = hashlib.md5(b"kernel32.dll.virtualalloc", usedforsecurity=False).hexdigest()
    assert calculate_imphash(imports) == expected
    assert calculate_imphash([]) is None

    ssdeep = calculate_ssdeep(str(file_path))
    assert ssdeep is None or isinstance(ssdeep, str)


class _Adapter:
    def search_hex_json(self, pattern: str) -> list[dict[str, int]]:
        return [{"addr": len(pattern)}]

    def search_text(self, pattern: str) -> str:
        return f"hit:{pattern}"

    def search_hex(self, pattern: str) -> str:
        return f"hex:{pattern}"

    def get_strings_filtered(self, command: str) -> list[str]:
        return [command]

    def get_functions(self) -> list[str]:
        return ["f1"]

    def get_functions_at(self, address: int) -> list[int]:
        return [address]

    def get_function_info(self, address: int) -> dict[str, int]:
        return {"addr": address}

    def get_disasm(
        self, address: int | None = None, size: int | None = None
    ) -> dict[str, int | None]:
        return {"address": address, "size": size}

    def get_disasm_text(self, address: int | None = None, size: int | None = None) -> str:
        return f"asm:{address}:{size}"

    def get_cfg(self, address: int | None = None) -> dict[str, int | None]:
        return {"cfg": address}

    def read_bytes_list(self, address: int, size: int | None) -> list[int]:
        return [address, size or 0]

    def read_bytes(self, address: int, size: int) -> bytes:
        return b"AB"

    def get_info_text(self) -> str:
        return "info"


def test_command_helpers_with_adapter() -> None:
    adapter = _Adapter()
    assert cmdj(adapter, None, "/xj deadbeef", []) == [{"addr": 8}]
    assert cmdj(adapter, None, "/c test", None) == "hit:test"
    assert cmdj(adapter, None, "/x de", None) == "hex:de"
    assert cmdj(adapter, None, "iz~foo", None) == ["iz~foo"]
    assert cmdj(adapter, None, "aflj@0x10", None) == [16]
    assert cmdj(adapter, None, "aflj", None) == ["f1"]
    assert cmdj(adapter, None, "afij@0x20", None) == {"addr": 32}
    assert cmdj(adapter, None, "pdj 4@0x30", None) == {"address": 48, "size": 4}
    assert cmdj(adapter, None, "pi 8@0x40", None) == "asm:64:8"
    assert cmdj(adapter, None, "agj@0x50", None) == {"cfg": 80}
    assert cmdj(adapter, None, "p8 4@0x60", None) == "4142"
    assert cmdj(adapter, None, "p8j 4@0x70", None) == [112, 4]
    assert cmd_list(adapter, None, "missing") == []
    assert cmd(adapter, None, "i") == "info"


def test_domain_helpers_and_string_domain() -> None:
    assert shannon_entropy(b"") == 0.0
    assert entropy_from_ints([0, 0, 0]) == 0.0
    assert clamp_score(-5) == 0
    assert clamp_score(105) == 100
    assert count_suspicious_imports([{"name": "A"}], {"A", "B"}) == 1
    assert suspicious_section_name_indicator("UPX1", ["upx"]) == "Suspicious section name: upx"

    strings = ["\x00A", "hello", "world!!!"]
    assert filter_strings(strings, 3, 8) == ["hello", "world!!!"]
    assert parse_search_results("0x1000 foo\nnope\n0x2000 bar") == ["0x1000", "0x2000"]
    assert xor_string("A", 1) == "@"

    def _search_hex(pattern: str) -> str:
        return "0x1234" if pattern == xor_string("A", 1).encode().hex() else ""

    matches = build_xor_matches("A", _search_hex)
    assert matches and matches[0]["addresses"] == ["0x1234"]

    suspicious = find_suspicious(["http://example.com", "user@test.com", "nope"])
    assert any(item["type"] == "urls" for item in suspicious)
    assert is_base64("ZGF0YQ==") is True
    assert decode_base64("ZGF0YQ==")["decoded"] == "data"
    assert is_hex("616263") is True
    assert decode_hex("616263")["decoded"] == "abc"


def test_anti_analysis_helpers_real() -> None:
    strings = [{"string": "VirtualAlloc", "vaddr": 16}]
    artifacts = ["virtualalloc"]
    assert collect_artifact_strings(strings, artifacts)[0]["address"] == "0x10"

    result = {"detected": False, "evidence": []}
    add_simple_evidence(result, "0x1\n0x2", "Test", "Detail", "addresses", 1)
    assert result["detected"] is True
    assert result["evidence"][0]["addresses"] == ["0x1"]

    def _search_fn(pattern: str) -> str:
        if pattern == "jmp":
            return "\n".join(["x"] * 101)
        if pattern == "call":
            return "\n".join(["x"] * 201)
        return ""

    assert count_opcode_occurrences(_search_fn, "jmp") == 101
    assert detect_obfuscation(_search_fn)

    def _cmd_fn(command: str) -> str:
        if "/c mov" in command:
            return "hit"
        if "iz~hash" in command:
            return "hash"
        return ""

    assert detect_self_modifying(_cmd_fn)
    assert detect_api_hashing(_cmd_fn)

    imports = [{"name": "CreateRemoteThread"}, {"name": "WriteProcessMemory"}]
    assert detect_injection_apis(imports, {"CreateRemoteThread", "WriteProcessMemory"})

    match = match_suspicious_api({"name": "VirtualAlloc", "plt": 32}, {"mem": ["Virtual"]})
    assert match and match["address"] == "0x20"

    env_checks = detect_environment_checks(_cmd_fn, [("cmd", "type", "desc")])
    assert env_checks == []


def test_schema_format_hashing_security_results() -> None:
    section = SectionInfo(name=" .text ", entropy=6.5, is_executable=True)
    assert section.name == ".text"
    assert section.is_suspicious() is False
    assert section.has_permission("x") is True

    features = SecurityFeatures(aslr=True, dep=True, nx=True)
    assert "aslr" in features.get_enabled_features()
    assert features.security_score() > 0

    analysis = FormatAnalysisResult(
        available=True, format="PE32", bits=64, endian="LE", sections=[section]
    )
    assert analysis.is_pe() is True
    assert analysis.is_64bit() is True
    assert analysis.get_executable_sections()

    hashing = HashAnalysisResult(
        available=True, hash_type="ssdeep", hash_value="x", method_used="python_library"
    )
    assert hashing.is_valid_hash() is True

    issue = SecurityIssue(severity=SeverityLevel.HIGH, description="bad")
    score = SecurityScore(score=1, max_score=10, percentage=10.0, grade="A")
    security = SecurityAnalysisResult(
        available=True,
        issues=[issue],
        score=75,
        security_score=score,
        mitigations={"aslr": {"enabled": True, "description": "ASLR"}},
    )
    assert security.get_high_issues()
    assert security.get_enabled_mitigations() == ["aslr"]
    assert security.count_issues_by_severity()["high"] == 1
    assert security.is_secure() is True

    result = AnalysisResult(
        file_info=FileInfo(name="a", file_type="ELF", size=1, md5="m", sha256="s"),
        hashing=HashingResult(ssdeep="x"),
    )
    assert result.has_error() is False
    assert result.is_suspicious() is False
    assert result.summary()["file_name"] == "a"

    data = {
        "file_info": {"name": "b", "file_type": "PE", "size": 2},
        "hashing": {"ssdeep": "y"},
        "security": {"nx": True, "relro": "full"},
        "imports": [{"name": "CreateRemoteThread"}],
        "exports": [{"name": "exp"}],
        "sections": [{"name": ".text", "entropy": 1.0}],
        "strings": ["s1"],
        "yara_matches": [{"rule": "r1"}],
        "functions": [{"name": "f1"}],
        "anti_analysis": {"anti_debug": True},
        "packer": {"is_packed": True, "packer_type": "upx"},
        "crypto": {"algorithms": [{"name": "aes"}]},
        "indicators": [{"type": "Packer", "severity": "High"}],
        "error": "boom",
        "timestamp": datetime.utcnow().isoformat(),
        "execution_time": 1.5,
    }
    loaded = from_dict(data)
    assert loaded.file_info.name == "b"
    assert loaded.hashing.has_hash("ssdeep") is True
    assert loaded.security.security_score() > 0
    assert loaded.has_error() is True

    bad_ts = from_dict({"timestamp": "not-a-date"})
    assert isinstance(bad_ts.timestamp, datetime)
