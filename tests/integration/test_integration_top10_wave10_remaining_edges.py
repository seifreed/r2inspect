"""Remaining edge coverage for wave10 top10 modules."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

from tests.helpers import env_vars

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


class _BadBytes:
    def hex(self) -> str:
        return "zz"


class _BadBytesCrypto(CryptoAnalyzer):
    """Crypto double whose _read_bytes yields un-hex-able data."""

    def _read_bytes(self, vaddr: int, size: int) -> bytes:
        return cast(bytes, _BadBytes())


class _NoOverlay(OverlayAnalyzer):
    """Overlay double: file_size == pe_end (no overlay) and a fixed cmdj."""

    def _get_file_size(self) -> int | None:
        return 10

    def _get_valid_pe_end(self, file_size: int) -> int | None:
        return 10

    def _cmdj(self, command: str, default: Any | None = None) -> Any:
        return [1, 2, 3, 4]


def test_similarity_scoring_helpers() -> None:
    assert jaccard_similarity(set(), set()) == 1.0
    assert jaccard_similarity({"a"}, set()) == 0.0
    assert jaccard_similarity({"a", "b"}, {"b", "c"}) == 1 / 3
    assert normalized_difference_similarity(10, 10) == 1.0
    assert normalized_difference_similarity(0, 10) == 0.0


def test_analysis_service_paths() -> None:
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

    with env_vars(R2INSPECT_VALIDATE_SCHEMAS="1"):
        svc.validate_results({"a": {"x": 1}, "b": "no-dict"})
    assert called["convert"] == 1

    with env_vars(R2INSPECT_VALIDATE_SCHEMAS="0"):
        assert AnalysisService._should_validate_schemas() is False
        prev_convert = called["convert"]
        svc.validate_results({"a": {"x": 1}})
        assert called["convert"] == prev_convert
    with env_vars(R2INSPECT_VALIDATE_SCHEMAS="yes"):
        assert AnalysisService._should_validate_schemas() is True
    assert AnalysisService.has_circuit_breaker_data({}) is False
    assert AnalysisService.has_circuit_breaker_data({"k": 1}) is True
    assert AnalysisService.has_circuit_breaker_data({"a": {"state": "open"}}) is True
    assert AnalysisService.has_circuit_breaker_data({"a": {"errors": 1}}) is True
    assert AnalysisService.has_circuit_breaker_data({"a": {"state": "closed", "count": 0}}) is False


def test_magic_adapter_paths() -> None:
    # win32 branch and create_detectors no-magic
    win = MagicAdapter(platform="win32")
    assert win.available is False
    assert win.create_detectors() is None

    class _MagicModule:
        @staticmethod
        def Magic(mime: bool = False) -> object:
            _ = mime
            return object()

    # import success: the importer seam returns a fake magic module
    ok = MagicAdapter(platform="darwin", importer=lambda: _MagicModule)
    assert ok.available is True
    assert ok.create_detectors() is not None

    # import failure: the importer seam raises
    def _import_fail() -> Any:
        raise RuntimeError("no magic")

    fail = MagicAdapter(platform="darwin", importer=_import_fail)
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


def test_crypto_overlay_pe_imports_registry_residuals() -> None:
    crypto = CryptoAnalyzer(adapter=object())
    out: dict[str, Any] = {}
    crypto._detect_via_strings(out)
    assert out == {}

    # un-hex-able section bytes -> entropy 0.0 (real path via subclass double)
    assert (
        _BadBytesCrypto(adapter=object())._calculate_section_entropy({"vaddr": 1, "size": 10})
        == 0.0
    )

    assert crypto._get_imports() == []
    assert crypto._get_sections() == []
    assert crypto._get_strings() == []
    # fallback on an adapter without read_bytes
    assert CryptoAnalyzer(adapter=object())._read_bytes(0, 1) == b""

    # file_size == pe_end -> no overlay
    ov = _NoOverlay(adapter=SimpleNamespace(cmdj=lambda _c: {}))
    r = ov.analyze()
    assert r["has_overlay"] is False

    # hash-exception handling via the calculate_hashes_fn DI seam
    res = ov._default_result()

    def _raise_hashes(_b: Any) -> Any:
        raise RuntimeError("hash fail")

    ov._analyze_overlay_content(res, 0, 4, calculate_hashes_fn=_raise_hashes)
    assert res["overlay_hashes"] == {}

    # patterns truthy but empty iteration -> unknown
    class _TruthyEmpty:
        def __bool__(self) -> bool:
            return True

        def __iter__(self) -> Any:
            return iter(())

    assert ov._determine_overlay_type(_TruthyEmpty(), [1, 2, 3, 4]) == "unknown"

    # pe_imports: empty import names -> "" + debug log
    adapter = SimpleNamespace(get_imports=lambda: [{"libname": "KERNEL32.dll", "name": ""}])
    logs: list[str] = []
    logger = SimpleNamespace(debug=lambda m: logs.append(m), error=lambda _m: None)
    assert calculate_imphash(adapter, logger) == ""
    assert any("No valid import strings" in m for m in logs)

    # EntryPointLoader real behaviour (no patching of the methods under test)
    registry = AnalyzerRegistry(lazy_loading=False)
    loader = EntryPointLoader(registry)
    ep = SimpleNamespace(name="sample-ep")

    assert loader._register_entry_point_callable(ep, lambda _r: None) == 1

    def _failing_obj(_r: Any) -> None:
        raise RuntimeError("callable failed")

    assert loader._register_entry_point_callable(ep, _failing_obj) == 0
    # object() is not a base analyzer -> falls back to str(ep.name)
    assert loader._derive_entry_point_name(ep, object()) == "sample-ep"
