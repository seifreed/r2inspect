"""Unit tests for application and core modules (no mocks, real data)."""

from __future__ import annotations

import io
import time
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# batch_discovery
# ---------------------------------------------------------------------------

from r2inspect.application.batch_discovery import (
    _is_executable_signature,
    _iter_files,
    discover_executables_by_magic,
    init_magic_detectors,
)


def test_is_executable_signature_known_mime():
    assert _is_executable_signature("application/x-dosexec", "") is True
    assert _is_executable_signature("application/x-executable", "") is True
    assert _is_executable_signature("application/x-pie-executable", "") is True
    assert _is_executable_signature("application/x-sharedlib", "") is True
    assert _is_executable_signature("application/octet-stream", "") is True


def test_is_executable_signature_by_description():
    assert _is_executable_signature("text/plain", "PE32 executable (console)") is True
    assert _is_executable_signature("text/plain", "ELF 64-bit LSB shared object") is True
    assert _is_executable_signature("text/plain", "Mach-O 64-bit x86_64") is True
    assert _is_executable_signature("text/plain", "dynamically linked") is True


def test_is_executable_signature_unknown():
    assert _is_executable_signature("text/plain", "ASCII text") is False
    assert _is_executable_signature("image/png", "PNG image data") is False


def test_iter_files_non_recursive(tmp_path):
    (tmp_path / "a.exe").write_bytes(b"\x00" * 10)
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.dll").write_bytes(b"\x00" * 10)

    files = _iter_files(tmp_path, recursive=False)
    names = {f.name for f in files}
    assert "a.exe" in names
    assert "b.dll" not in names


def test_iter_files_recursive(tmp_path):
    (tmp_path / "a.exe").write_bytes(b"\x00" * 10)
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.dll").write_bytes(b"\x00" * 10)

    files = _iter_files(tmp_path, recursive=True)
    names = {f.name for f in files}
    assert "a.exe" in names
    assert "b.dll" in names


def test_init_magic_detectors_none():
    assert init_magic_detectors(None) is None


def test_discover_executables_no_magic_module(tmp_path):
    executables, init_errors, file_errors, scanned = discover_executables_by_magic(
        tmp_path, magic_module=None
    )
    assert executables == []
    assert len(init_errors) == 1
    assert "not available" in init_errors[0]
    assert scanned == 0


def test_discover_executables_magic_init_raises(tmp_path):
    class BrokenMagic:
        def Magic(self, **_kwargs):
            raise RuntimeError("init failure")

    executables, init_errors, file_errors, scanned = discover_executables_by_magic(
        tmp_path, magic_module=BrokenMagic()
    )
    assert executables == []
    assert any("init failure" in e for e in init_errors)


def test_discover_executables_skips_small_files(tmp_path):
    small = tmp_path / "tiny.exe"
    small.write_bytes(b"\x00" * 10)  # < 64 bytes

    class FakeMagicInstance:
        def from_file(self, path):
            return "application/x-dosexec"

    class FakeMagicModule:
        def Magic(self, **_kwargs):
            return FakeMagicInstance()

    executables, init_errors, file_errors, scanned = discover_executables_by_magic(
        tmp_path, magic_module=FakeMagicModule()
    )
    assert executables == []
    assert scanned == 1


def test_discover_executables_finds_executable(tmp_path):
    exe = tmp_path / "sample.exe"
    exe.write_bytes(b"MZ" + b"\x00" * 100)

    class MimeMagic:
        def from_file(self, _path):
            return "application/x-dosexec"

    class DescMagic:
        def from_file(self, _path):
            return "PE32 executable"

    class FakeMagicModule:
        def __init__(self):
            self._mime = MimeMagic()
            self._desc = DescMagic()
            self._call_count = 0

        def Magic(self, mime=False):
            if mime:
                return self._mime
            return self._desc

    executables, init_errors, file_errors, scanned = discover_executables_by_magic(
        tmp_path, magic_module=FakeMagicModule()
    )
    assert exe in executables
    assert scanned == 1


def test_discover_executables_file_error(tmp_path):
    exe = tmp_path / "sample.exe"
    exe.write_bytes(b"MZ" + b"\x00" * 100)

    class ErrorMagic:
        def from_file(self, _path):
            raise OSError("permission denied")

    class FakeMagicModule:
        def Magic(self, **_kwargs):
            return ErrorMagic()

    executables, init_errors, file_errors, scanned = discover_executables_by_magic(
        tmp_path, magic_module=FakeMagicModule()
    )
    assert executables == []
    assert len(file_errors) == 1
    assert "permission denied" in file_errors[0][1]


# ---------------------------------------------------------------------------
# analysis_service
# ---------------------------------------------------------------------------

from r2inspect.application.analysis_service import AnalysisService


def test_reset_stats_runs_without_error():
    svc = AnalysisService()
    svc.reset_stats()  # must not raise


def test_execute_calls_inspector_analyze():
    class FakeInspector:
        def analyze(self, **options):
            return {"ok": True, "opts": options}

    svc = AnalysisService()
    result = svc.execute(FakeInspector(), {"full_analysis": True})
    assert result["ok"] is True
    assert result["opts"]["full_analysis"] is True


def test_add_statistics_no_errors():
    svc = AnalysisService()
    svc.reset_stats()
    results: dict[str, Any] = {}
    svc.add_statistics(results)
    # No errors recorded → no error_statistics key injected
    assert "error_statistics" not in results


def test_validate_results_env_flag_off(monkeypatch):
    monkeypatch.setenv("R2INSPECT_VALIDATE_SCHEMAS", "0")
    svc = AnalysisService()
    svc.validate_results({"something": {"data": 1}})  # must not raise


def test_validate_results_env_flag_on(monkeypatch):
    monkeypatch.setenv("R2INSPECT_VALIDATE_SCHEMAS", "1")
    svc = AnalysisService()
    svc.validate_results({})  # empty results – must not raise


def test_has_circuit_breaker_data_empty():
    assert AnalysisService.has_circuit_breaker_data({}) is False


def test_has_circuit_breaker_data_all_zero():
    assert AnalysisService.has_circuit_breaker_data({"trips": 0, "calls": 0}) is False


def test_has_circuit_breaker_data_positive_int():
    assert AnalysisService.has_circuit_breaker_data({"trips": 1}) is True


def test_has_circuit_breaker_data_nested_positive():
    stats = {"breaker_a": {"trips": 0, "calls": 5}}
    assert AnalysisService.has_circuit_breaker_data(stats) is True


def test_has_circuit_breaker_data_non_closed_state():
    stats = {"breaker_a": {"state": "open"}}
    assert AnalysisService.has_circuit_breaker_data(stats) is True


def test_has_circuit_breaker_data_closed_state():
    stats = {"breaker_a": {"state": "closed"}}
    assert AnalysisService.has_circuit_breaker_data(stats) is False


# ---------------------------------------------------------------------------
# batch_service
# ---------------------------------------------------------------------------

from r2inspect.application.batch_service import BatchAnalysisService, BatchDependencies


def test_batch_run_returns_early_when_no_files():
    no_files_called = []

    def find_files(*_args, **_kwargs):
        return []

    def no_files_msg(auto_detect, extensions):
        no_files_called.append((auto_detect, extensions))

    deps = BatchDependencies(
        find_files_to_process=find_files,
        display_no_files_message=no_files_msg,
        setup_output_directory=lambda *_a, **_k: Path("/tmp"),
        setup_rate_limiter=lambda *_a, **_k: None,
        process_files_parallel=lambda *_a, **_k: None,
        create_batch_summary=lambda *_a, **_k: None,
        display_batch_results=lambda *_a, **_k: None,
    )
    svc = BatchAnalysisService()
    svc.run_batch_analysis(
        batch_dir="/tmp",
        options={},
        output_json=False,
        output_csv=False,
        output_dir=None,
        recursive=False,
        extensions=None,
        verbose=False,
        config_obj=None,
        auto_detect=True,
        threads=1,
        quiet=False,
        deps=deps,
    )
    assert len(no_files_called) == 1
    assert no_files_called[0] == (True, None)


def test_batch_run_full_pipeline(tmp_path):
    fake_file = tmp_path / "sample.exe"
    fake_file.write_bytes(b"MZ" + b"\x00" * 100)

    calls: list[str] = []

    def find_files(*_args, **_kwargs):
        return [fake_file]

    deps = BatchDependencies(
        find_files_to_process=find_files,
        display_no_files_message=lambda *_a, **_k: None,
        setup_output_directory=lambda *_a, **_k: tmp_path,
        setup_rate_limiter=lambda *_a, **_k: "limiter",
        process_files_parallel=lambda *_a, **_k: calls.append("parallel"),
        create_batch_summary=lambda *_a, **_k: "summary.json",
        display_batch_results=lambda *_a, **_k: calls.append("display"),
        display_found_files=lambda count, threads: calls.append(f"found:{count}"),
        configure_batch_logging=lambda: calls.append("batch_log"),
        configure_quiet_logging=lambda: calls.append("quiet_log"),
        now=time.time,
    )
    svc = BatchAnalysisService()
    svc.run_batch_analysis(
        batch_dir=str(tmp_path),
        options={},
        output_json=True,
        output_csv=False,
        output_dir=None,
        recursive=False,
        extensions=None,
        verbose=False,
        config_obj=None,
        auto_detect=True,
        threads=2,
        quiet=False,
        deps=deps,
    )
    assert "parallel" in calls
    assert "display" in calls
    assert "found:1" in calls
    assert "batch_log" in calls


def test_batch_run_quiet_mode(tmp_path):
    fake_file = tmp_path / "sample.exe"
    fake_file.write_bytes(b"MZ" + b"\x00" * 100)

    calls: list[str] = []

    deps = BatchDependencies(
        find_files_to_process=lambda *_a, **_k: [fake_file],
        display_no_files_message=lambda *_a, **_k: None,
        setup_output_directory=lambda *_a, **_k: tmp_path,
        setup_rate_limiter=lambda *_a, **_k: None,
        process_files_parallel=lambda *_a, **_k: None,
        create_batch_summary=lambda *_a, **_k: None,
        display_batch_results=lambda *_a, **_k: None,
        configure_quiet_logging=lambda: calls.append("quiet"),
    )
    svc = BatchAnalysisService()
    svc.run_batch_analysis(
        batch_dir=str(tmp_path),
        options={},
        output_json=False,
        output_csv=False,
        output_dir=None,
        recursive=False,
        extensions=None,
        verbose=False,
        config_obj=None,
        auto_detect=False,
        threads=1,
        quiet=True,
        deps=deps,
    )
    assert "quiet" in calls


# ---------------------------------------------------------------------------
# analyzer_runner (application re-export of utils)
# ---------------------------------------------------------------------------

from r2inspect.application.analyzer_runner import run_analyzer_on_file


def test_run_analyzer_on_file_returns_none_for_nonexistent():
    # run_analyzer_on_file wraps everything in try/except and returns None on failure
    result = run_analyzer_on_file(lambda _a, _f: None, "/nonexistent/path/fake.exe")
    assert result is None


def test_run_analyzer_on_file_returns_none_when_no_analyze_method():
    class NoAnalyze:
        pass

    result = run_analyzer_on_file(lambda _a, _f: NoAnalyze(), "/nonexistent/file.bin")
    assert result is None


# ---------------------------------------------------------------------------
# analyze_binary use case
# ---------------------------------------------------------------------------

from r2inspect.application.use_cases.analyze_binary import AnalyzeBinaryUseCase
from r2inspect.application.analysis_service import AnalysisService


class _FakeInspector:
    def analyze(self, **_opts):
        return {"result": "ok"}


def test_analyze_binary_use_case_basic():
    use_case = AnalyzeBinaryUseCase()
    result = use_case.run(_FakeInspector(), {}, reset_stats=True, include_statistics=True)
    assert result["result"] == "ok"


def test_analyze_binary_use_case_no_reset_no_stats():
    use_case = AnalyzeBinaryUseCase()
    result = use_case.run(
        _FakeInspector(),
        {},
        reset_stats=False,
        include_statistics=False,
        validate_schemas=False,
    )
    assert result["result"] == "ok"
    assert "error_statistics" not in result


def test_analyze_binary_use_case_custom_service():
    class CustomService(AnalysisService):
        def execute(self, inspector, options):
            return {"custom": True}

    use_case = AnalyzeBinaryUseCase(analysis_service=CustomService())
    result = use_case.run(_FakeInspector(), {})
    assert result["custom"] is True


# ---------------------------------------------------------------------------
# options (build_analysis_options)
# ---------------------------------------------------------------------------

from r2inspect.application.options import build_analysis_options


def test_build_analysis_options_defaults():
    opts = build_analysis_options(yara=None, sanitized_xor=None)
    assert opts["detect_packer"] is True
    assert opts["detect_crypto"] is True
    assert opts["detect_av"] is True
    assert opts["full_analysis"] is True
    assert opts["custom_yara"] is None
    assert opts["xor_search"] is None


def test_build_analysis_options_with_values():
    opts = build_analysis_options(yara="/rules/custom.yar", sanitized_xor="deadbeef")
    assert opts["custom_yara"] == "/rules/custom.yar"
    assert opts["xor_search"] == "deadbeef"


# ---------------------------------------------------------------------------
# result_aggregator
# ---------------------------------------------------------------------------

from r2inspect.core.result_aggregator import (
    ResultAggregator,
    _build_file_overview,
    _build_security_assessment,
    _build_threat_indicators,
)


def _make_results(**overrides) -> dict[str, Any]:
    base: dict[str, Any] = {
        "file_info": {},
        "pe_info": {},
        "security": {},
        "packer": {},
        "anti_analysis": {},
        "imports": [],
        "yara_matches": [],
        "sections": [],
        "functions": {},
        "crypto": {},
        "rich_header": {},
    }
    base.update(overrides)
    return base


def test_build_file_overview_defaults():
    ov = _build_file_overview(_make_results())
    assert ov["filename"] == "Unknown"
    assert ov["md5"] == "Unknown"
    assert ov["sha256"] == "Unknown"


def test_build_file_overview_with_data():
    results = _make_results(
        file_info={"name": "sample.exe", "file_type": "PE32", "size": 1024,
                   "architecture": "x86", "md5": "aabbcc", "sha256": "ddeeff"},
        pe_info={"compilation_timestamp": "2020-01-01"},
    )
    ov = _build_file_overview(results)
    assert ov["filename"] == "sample.exe"
    assert ov["compiled"] == "2020-01-01"
    assert ov["size"] == 1024


def test_build_file_overview_rich_header_toolset():
    results = _make_results(
        rich_header={
            "available": True,
            "compilers": [
                {"compiler_name": "MSVC", "build_number": 1900},
                {"compiler_name": "MASM", "build_number": 14},
            ],
        }
    )
    ov = _build_file_overview(results)
    assert "toolset" in ov
    assert any("MSVC" in t for t in ov["toolset"])


def test_build_security_assessment_defaults():
    sa = _build_security_assessment(_make_results())
    assert sa["is_signed"] is False
    assert sa["is_packed"] is False
    assert sa["packer_type"] is None
    for flag in ("aslr", "dep", "cfg", "stack_canary", "safe_seh"):
        assert sa["security_features"][flag] is False


def test_build_security_assessment_packed():
    results = _make_results(
        packer={"is_packed": True, "packer_type": "UPX"},
        security={"authenticode": True, "aslr": True},
    )
    sa = _build_security_assessment(results)
    assert sa["is_packed"] is True
    assert sa["packer_type"] == "UPX"
    assert sa["is_signed"] is True
    assert sa["security_features"]["aslr"] is True


def test_build_threat_indicators_empty():
    ti = _build_threat_indicators(_make_results())
    assert ti["suspicious_imports"] == 0
    assert ti["yara_matches"] == 0
    assert ti["entropy_warnings"] == 0
    assert ti["suspicious_sections"] == 0
    assert ti["crypto_indicators"] == 0


def test_build_threat_indicators_with_data():
    results = _make_results(
        imports=[{"name": "VirtualAlloc"}, {"name": "WriteProcessMemory"}, {"name": "LoadLibrary"}],
        yara_matches=[{"rule": "Trojan.Generic"}],
        sections=[{"entropy": 7.5}, {"entropy": 6.0}, {"name": "UPX0"}],
        crypto={"matches": [{"name": "AES"}, {"name": "RC4"}]},
    )
    ti = _build_threat_indicators(results)
    assert ti["suspicious_imports"] == 2
    assert ti["yara_matches"] == 1
    assert ti["entropy_warnings"] == 1
    assert ti["suspicious_sections"] == 1
    assert ti["crypto_indicators"] == 2


def test_result_aggregator_generate_indicators_empty():
    agg = ResultAggregator()
    indicators = agg.generate_indicators({})
    assert isinstance(indicators, list)
    assert len(indicators) == 0


def test_result_aggregator_generate_indicators_packed():
    results = _make_results(packer={"is_packed": True, "packer_type": "UPX"})
    agg = ResultAggregator()
    indicators = agg.generate_indicators(results)
    types = [i["type"] for i in indicators]
    assert "Packer" in types


def test_result_aggregator_generate_indicators_yara():
    results = _make_results(yara_matches=[{"rule": "Ransom.WannaCry"}])
    agg = ResultAggregator()
    indicators = agg.generate_indicators(results)
    types = [i["type"] for i in indicators]
    assert "YARA Match" in types


def test_result_aggregator_generate_indicators_suspicious_api():
    results = _make_results(imports=[{"name": "CreateRemoteThread"}])
    agg = ResultAggregator()
    indicators = agg.generate_indicators(results)
    types = [i["type"] for i in indicators]
    assert "Suspicious API" in types


def test_result_aggregator_executive_summary_keys():
    agg = ResultAggregator()
    summary = agg.generate_executive_summary({})
    for key in ("file_overview", "security_assessment", "threat_indicators",
                "technical_details", "recommendations"):
        assert key in summary


def test_result_aggregator_executive_summary_recommendations_fallback():
    agg = ResultAggregator()
    summary = agg.generate_executive_summary({})
    recs = summary["recommendations"]
    assert isinstance(recs, list)
    assert len(recs) >= 1


# ---------------------------------------------------------------------------
# file_validator
# ---------------------------------------------------------------------------

from r2inspect.core.file_validator import FileValidator


def test_file_validator_nonexistent():
    fv = FileValidator("/nonexistent/path/fake_file.exe")
    assert fv.validate() is False


def test_file_validator_empty_file(tmp_path):
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    fv = FileValidator(str(empty))
    assert fv.validate() is False


def test_file_validator_too_small(tmp_path):
    small = tmp_path / "small.bin"
    small.write_bytes(b"\x00" * 10)
    fv = FileValidator(str(small))
    assert fv.validate() is False


def test_file_validator_valid_file(tmp_path):
    valid = tmp_path / "sample.bin"
    valid.write_bytes(b"MZ" + b"\x00" * 200)
    fv = FileValidator(str(valid))
    assert fv.validate() is True


def test_file_validator_caches_result(tmp_path):
    valid = tmp_path / "sample2.bin"
    valid.write_bytes(b"MZ" + b"\x00" * 200)
    fv = FileValidator(str(valid))
    r1 = fv.validate()
    r2 = fv.validate()
    assert r1 == r2
    assert fv._validated is True


def test_file_validator_directory_path(tmp_path):
    fv = FileValidator(str(tmp_path))
    assert fv.validate() is False


# ---------------------------------------------------------------------------
# lazy_loader_stats
# ---------------------------------------------------------------------------

from r2inspect.lazy_loader_stats import build_stats, print_stats


class _StubLoader:
    def __init__(self, registry, cache, stats):
        self._registry = registry
        self._cache = cache
        self._stats = stats


def _make_loader(registered=("a", "b", "c"), loaded=("a",),
                 hits=5, misses=3, load_count=4,
                 failed=0, load_times=None):
    registry = {k: object() for k in registered}
    cache = {k: object() for k in loaded}
    stats = {
        "cache_hits": hits,
        "cache_misses": misses,
        "load_count": load_count,
        "failed_loads": failed,
        "load_times": load_times or {},
    }
    return _StubLoader(registry, cache, stats)


def test_build_stats_basic():
    loader = _make_loader()
    stats = build_stats(loader)
    assert stats["registered"] == 3
    assert stats["loaded"] == 1
    assert stats["unloaded"] == 2
    assert stats["load_count"] == 4
    assert stats["cache_hits"] == 5
    assert stats["cache_misses"] == 3
    assert stats["failed_loads"] == 0
    assert abs(stats["cache_hit_rate"] - 5 / 8) < 1e-9
    assert abs(stats["lazy_ratio"] - (1 - 1 / 3)) < 1e-9


def test_build_stats_zero_accesses():
    loader = _make_loader(hits=0, misses=0, load_count=0)
    stats = build_stats(loader)
    assert stats["cache_hit_rate"] == 0.0


def test_build_stats_empty_registry():
    loader = _make_loader(registered=(), loaded=())
    stats = build_stats(loader)
    assert stats["registered"] == 0
    assert stats["loaded"] == 0
    assert stats["lazy_ratio"] == 0.0


def test_build_stats_load_times_copy():
    times = {"analyzer_x": 12.5}
    loader = _make_loader(load_times=times)
    stats = build_stats(loader)
    stats["load_times"]["new_key"] = 99.0
    assert "new_key" not in times


def test_print_stats_outputs_text(capsys):
    loader = _make_loader(
        registered=("a", "b"),
        loaded=("a",),
        hits=4,
        misses=2,
        load_count=3,
        failed=1,
        load_times={"a": 10.5},
    )
    print_stats(loader)
    captured = capsys.readouterr().out
    assert "Registered analyzers:" in captured
    assert "Cache hits:" in captured
    assert "10.50 ms" in captured
