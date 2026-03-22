"""Remaining edge coverage for wave10 top10 modules."""

from __future__ import annotations

import os
from types import SimpleNamespace

from r2inspect.adapters.magic_adapter import MagicAdapter
from r2inspect.application.analysis_service import AnalysisService
from r2inspect.domain.analysis_runtime import AnalysisRuntimeStats
from r2inspect.modules.binbloom_analysis import run_binbloom_analysis
from r2inspect.modules.crypto_analyzer import CryptoAnalyzer
from r2inspect.modules.overlay_analyzer import OverlayAnalyzer
from r2inspect.modules.pe_imports import calculate_imphash
from r2inspect.domain.formats.similarity import (
    jaccard_similarity,
    normalized_difference_similarity,
)
from r2inspect.registry.analyzer_registry import AnalyzerRegistry
from r2inspect.registry.entry_points import EntryPointLoader


def test_similarity_scoring_helpers() -> None:
    assert jaccard_similarity(set(), set()) == 1.0
    assert jaccard_similarity({"a"}, set()) == 0.0
    assert jaccard_similarity({"a", "b"}, {"b", "c"}) == 1 / 3
    assert normalized_difference_similarity(10, 10) == 1.0
    assert normalized_difference_similarity(0, 10) == 0.0


def test_analysis_service_paths(monkeypatch) -> None:
    runtime = SimpleNamespace(
        reset=lambda: called.__setitem__("reset", 1),
        collect=lambda: AnalysisRuntimeStats(
            {"total_errors": 1},
            {"total_retries": 2},
            {"state": {"x": "open"}},
        ),
    )
    validator = SimpleNamespace(
        validate=lambda results, enabled: called.__setitem__(
            "convert",
            called["convert"] + (1 if enabled and isinstance(results.get("a"), dict) else 0),
        )
    )
    svc = AnalysisService(runtime=runtime, result_validator=validator)
    called = {"reset": 0, "convert": 0}
    svc.reset_stats()
    assert called["reset"] == 1

    inspector = SimpleNamespace(analyze=lambda **opts: {"ok": True, "opts": opts})
    assert svc.execute(inspector, {"a": 1})["ok"] is True

    results: dict[str, object] = {}
    svc.add_statistics(results)
    assert "error_statistics" in results
    assert "retry_statistics" in results
    assert "circuit_breaker_statistics" in results

    monkeypatch.setenv("R2INSPECT_VALIDATE_SCHEMAS", "1")
    svc.validate_results({"a": {"x": 1}, "b": "no-dict"})
    assert called["convert"] == 1

    monkeypatch.setenv("R2INSPECT_VALIDATE_SCHEMAS", "0")
    assert AnalysisService._should_validate_schemas() is False
    prev_convert = called["convert"]
    svc.validate_results({"a": {"x": 1}})
    assert called["convert"] == prev_convert
    monkeypatch.setenv("R2INSPECT_VALIDATE_SCHEMAS", "yes")
    assert AnalysisService._should_validate_schemas() is True
    assert AnalysisService.has_circuit_breaker_data({}) is False
    assert AnalysisService.has_circuit_breaker_data({"k": 1}) is True
    assert AnalysisService.has_circuit_breaker_data({"a": {"state": "open"}}) is True
    assert AnalysisService.has_circuit_breaker_data({"a": {"errors": 1}}) is True
    assert AnalysisService.has_circuit_breaker_data({"a": {"state": "closed", "count": 0}}) is False


def test_magic_adapter_paths(monkeypatch) -> None:
    # win32 branch (lines 16-17) and create_detectors no-magic (line 31)
    monkeypatch.setattr("r2inspect.adapters.magic_adapter.sys.platform", "win32")
    win = MagicAdapter()
    assert win.available is False
    assert win.create_detectors() is None

    # import success (22-23)
    monkeypatch.setattr("r2inspect.adapters.magic_adapter.sys.platform", "darwin")
    real_import = __import__

    class _MagicModule:
        @staticmethod
        def Magic(mime=False):
            _ = mime
            return object()

    def _import_ok(name, *args, **kwargs):
        if name == "magic":
            return _MagicModule
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", _import_ok)
    ok = MagicAdapter()
    assert ok.available is True
    assert ok.create_detectors() is not None

    # import failure (line 27)
    def _import_fail(name, *args, **kwargs):
        if name == "magic":
            raise RuntimeError("no magic")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", _import_fail)
    fail = MagicAdapter()
    assert fail.available is False

    # create_detectors exception branch (34-35)
    class _BrokenMagic:
        @staticmethod
        def Magic(mime=False):
            _ = mime
            raise RuntimeError("ctor fail")

    fail._magic = _BrokenMagic
    assert fail.create_detectors() is None


def test_binbloom_analysis_exception_path() -> None:
    class _Analyzer:
        default_capacity = 10
        default_error_rate = 0.01
        filepath = "/tmp/a.bin"

        def _init_result_structure(self, d):
            return d

        def _extract_functions(self):
            raise RuntimeError("boom")

    res = run_binbloom_analysis(
        analyzer=_Analyzer(),
        capacity=None,
        error_rate=None,
        bloom_available=True,
        log_debug=lambda _m: None,
        log_error=lambda _m: None,
    )
    assert res["error"] == "boom"


def test_crypto_overlay_pe_imports_registry_residuals(monkeypatch) -> None:
    crypto = CryptoAnalyzer(adapter=object())
    # line 190
    out = {}
    crypto._detect_via_strings(out)
    assert out == {}

    # lines 257-258
    class _BadBytes:
        def hex(self):
            return "zz"

    crypto._read_bytes = lambda _v, _s: _BadBytes()  # type: ignore[method-assign]
    assert crypto._calculate_section_entropy({"vaddr": 1, "size": 10}) == 0.0

    # lines 329,334,339
    assert crypto._get_imports() == []
    assert crypto._get_sections() == []
    assert crypto._get_strings() == []
    # line 350 fallback on object without read_bytes
    assert CryptoAnalyzer(adapter=object())._read_bytes(0, 1) == b""

    # overlay line 56: file_size > pe_end but no overlay
    ov = OverlayAnalyzer(adapter=SimpleNamespace(cmdj=lambda _c: {}))
    ov._get_file_size = lambda: 10  # type: ignore[method-assign]
    ov._get_valid_pe_end = lambda _fs: 10  # type: ignore[method-assign]
    r = ov.analyze()
    assert r["has_overlay"] is False

    # overlay lines 112-113 invalid pe_end conversion
    ov2 = OverlayAnalyzer(adapter=SimpleNamespace(cmdj=lambda _c: {}))
    ov2._calculate_pe_end = lambda: "x"  # type: ignore[method-assign]
    assert ov2._get_valid_pe_end(100) is None

    # overlay lines 186-188 hash exception handling
    res = ov._default_result()
    ov._cmdj = lambda _cmd, _d=None: [1, 2, 3, 4]  # type: ignore[method-assign]
    monkeypatch.setattr(
        "r2inspect.modules.overlay_analyzer.calculate_hashes_for_bytes",
        lambda _b: (_ for _ in ()).throw(RuntimeError("hash fail")),
    )
    ov._analyze_overlay_content(res, 0, 4)
    assert res["overlay_hashes"] == {}

    # overlay line 313 unknown type when patterns truthy but empty iteration
    class _TruthyEmpty:
        def __bool__(self):
            return True

        def __iter__(self):
            return iter(())

    assert ov._determine_overlay_type(_TruthyEmpty(), [1, 2, 3, 4]) == "unknown"

    # pe_imports lines 88-89
    adapter = SimpleNamespace(get_imports=lambda: [{"libname": "KERNEL32.dll", "name": ""}])
    logs: list[str] = []
    logger = SimpleNamespace(debug=lambda m: logs.append(m), error=lambda _m: None)
    assert calculate_imphash(adapter, logger) == ""
    assert any("No valid import strings" in m for m in logs)

    # analyzer_registry lines 635,639
    registry = AnalyzerRegistry(lazy_loading=False)

    def _callable(self, _ep, _obj):
        _ = self
        return 7

    def _derive(self, _ep, _obj):
        _ = self
        return "x"

    monkeypatch.setattr(
        "r2inspect.registry.entry_points.EntryPointLoader._register_entry_point_callable", _callable
    )
    monkeypatch.setattr(
        "r2inspect.registry.entry_points.EntryPointLoader._derive_entry_point_name", _derive
    )
    loader = EntryPointLoader(registry)
    assert loader._register_entry_point_callable(object(), lambda _r: None) == 7
    assert loader._derive_entry_point_name(object(), object()) == "x"

    # Avoid leaking env from service tests if run in different order
    os.environ.pop("R2INSPECT_VALIDATE_SCHEMAS", None)
