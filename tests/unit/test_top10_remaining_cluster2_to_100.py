"""Targeted tests for remaining top-10 projected misses."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from r2inspect.cli import batch_processing
from r2inspect.cli import batch_workers
from r2inspect.config import Config
from r2inspect.modules.authenticode_analyzer import AuthenticodeAnalyzer
from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer
from r2inspect.modules.crypto_analyzer import CryptoAnalyzer
from r2inspect.modules import crypto_domain
from r2inspect.modules import domain_helpers
from r2inspect.modules.pe_analyzer import PEAnalyzer
from r2inspect.pipeline.stages_metadata import MetadataStage
from r2inspect.registry.analyzer_registry import AnalyzerRegistry
from r2inspect.infrastructure.memory import MemoryMonitor, MemoryLimits


def test_crypto_analyzer_entropy_invalid_hex_and_method_fallbacks() -> None:
    adapter = SimpleNamespace(read_bytes=lambda _v, _s: b"\xff")
    analyzer = CryptoAnalyzer(adapter=adapter)
    analyzer._read_bytes = lambda _v, _s: b"\xff"  # type: ignore[method-assign]
    assert analyzer._calculate_section_entropy({"vaddr": 0x1000, "size": 1}) == 0.0

    analyzer_no_methods = CryptoAnalyzer(adapter=SimpleNamespace())
    assert analyzer_no_methods._get_imports() == []
    assert analyzer_no_methods._get_sections() == []
    assert analyzer_no_methods._get_strings() == []
    assert analyzer_no_methods._read_bytes(0x1000, 16) == b""


def test_bindiff_analyzer_remaining_branches(monkeypatch) -> None:
    analyzer = BinDiffAnalyzer(adapter=SimpleNamespace(), filepath="dummy.bin")

    monkeypatch.setattr(analyzer, "analyze", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    compare = analyzer.compare_with({"comparison_ready": True, "filename": "b"})
    assert compare["similarity_score"] == 0.0

    called = {"aaa": False}
    monkeypatch.setattr(
        "r2inspect.modules.bindiff_analyzer.cmd_helper",
        lambda *_args, **_kwargs: called.__setitem__("aaa", True) or "",
    )
    adapter = SimpleNamespace(get_functions=lambda: [])
    analyzer2 = BinDiffAnalyzer(adapter=adapter, filepath="dummy.bin")
    analyzer2._extract_function_features()
    assert called["aaa"] is True

    adapter3 = SimpleNamespace(
        analyze_all=lambda: None,
        get_functions=lambda: [{"offset": 0x1000, "name": "f1", "size": 1}],
        get_cfg=lambda _addr: "invalid",
    )
    analyzer3 = BinDiffAnalyzer(adapter=adapter3, filepath="dummy.bin")
    features = analyzer3._extract_function_features()
    assert features["cfg_features"] == []

    called_entropy = {"used": False}
    monkeypatch.setattr(
        "r2inspect.modules.bindiff_analyzer.cmd_helper",
        lambda *_args, **_kwargs: called_entropy.__setitem__("used", True) or "0.1 0.2",
    )
    analyzer4 = BinDiffAnalyzer(adapter=SimpleNamespace(), filepath="dummy.bin")
    analyzer4._extract_byte_features()
    assert called_entropy["used"] is True


def test_batch_workers_remaining_branches(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("os.getenv", lambda _k, _d=None: "")
    assert batch_workers._cap_threads_for_execution(4) == 4

    class _Limiter:
        def acquire(self, timeout: float = 30.0) -> bool:
            return True

        def release_success(self) -> None:
            return None

        def release_error(self, _e: str) -> None:
            return None

    monkeypatch.setattr(
        "r2inspect.cli.batch_workers.create_inspector",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("forced")),
    )
    _, _, error = batch_workers.process_single_file(
        file_path=tmp_path / "a.bin",
        batch_path=tmp_path,
        config_obj=Config(),
        options={},
        output_json=False,
        output_path=tmp_path,
        rate_limiter=_Limiter(),
    )
    assert error == "forced"

    monkeypatch.setattr(
        "r2inspect.cli.batch_workers.process_single_file",
        lambda *args, **kwargs: (args[0], None, None),
    )
    all_results: dict[str, dict[str, Any]] = {}
    failed: list[tuple[str, str]] = []
    batch_workers.process_files_parallel(
        files_to_process=[tmp_path / "x.bin"],
        all_results=all_results,
        failed_files=failed,
        output_path=tmp_path,
        batch_path=tmp_path,
        config_obj=Config(),
        options={},
        output_json=False,
        threads=1,
        rate_limiter=_Limiter(),
    )
    assert failed and failed[0][1] == "Empty results"


def test_memory_monitor_and_metadata_remaining_branches(monkeypatch) -> None:
    monitor = MemoryMonitor(MemoryLimits())
    monitor.check_interval = 0.0
    monitor.critical_callback = lambda _stats: (_ for _ in ()).throw(RuntimeError("critical"))
    monitor._handle_critical_memory({"process_memory_mb": 100.0, "process_usage_percent": 0.9})

    gc_calls = {"n": 0}
    monkeypatch.setattr("gc.collect", lambda: gc_calls.__setitem__("n", gc_calls["n"] + 1) or 0)
    monitor._trigger_gc(aggressive=True)
    assert gc_calls["n"] >= 3
    assert (
        monitor.validate_section_size(int((monitor.limits.section_size_limit_mb + 1) * 1024 * 1024))
        is False
    )
    assert monitor.limit_collection_size([1, 2, 3], 10) == [1, 2, 3]
    monitor.set_callbacks(lambda _s: None, lambda _s: None)
    assert monitor.warning_callback is not None and monitor.critical_callback is not None

    stage = MetadataStage(
        registry=AnalyzerRegistry(),
        adapter=SimpleNamespace(),
        config=SimpleNamespace(),
        filename="dummy.bin",
        options={},
    )
    ctx = {"results": {}}
    assert stage._run_analyzer_method(ctx, "missing", "m", "x") is None

    class _BadRegistry:
        @staticmethod
        def get_analyzer_class(_name: str) -> Any:
            return int

    stage2 = MetadataStage(
        registry=_BadRegistry(),  # type: ignore[arg-type]
        adapter=SimpleNamespace(),
        config=SimpleNamespace(),
        filename="dummy.bin",
        options={},
    )
    out = stage2._run_analyzer_method({"results": {}}, "x", "missing_method", "x")
    assert out == {"x": []}


def test_pe_analyzer_domain_helpers_crypto_domain_and_authenticode(monkeypatch) -> None:
    analyzer = PEAnalyzer(adapter=SimpleNamespace())
    assert analyzer.get_category() == "format"
    assert "PE" in analyzer.get_description()
    assert analyzer.supports_format("PE32+")

    monkeypatch.setattr(
        "r2inspect.modules.pe_analyzer._get_version_info", lambda _a, _l: {"v": "1"}
    )
    monkeypatch.setattr("r2inspect.modules.pe_analyzer._determine_pe_format", lambda _b, _h: "PE32")
    assert analyzer.get_version_info() == {"v": "1"}
    assert analyzer._determine_pe_format({}, None) == "PE32"

    assert domain_helpers.shannon_entropy(b"") == 0.0
    assert domain_helpers.entropy_from_ints([]) == 0.0
    assert domain_helpers.clamp_score(200) == 100
    assert domain_helpers.count_suspicious_imports([{"name": "X"}], {"X"}) == 1
    assert domain_helpers.normalize_section_name(None) == ""

    old_noise = crypto_domain.NOISE_PATTERNS
    old_crypto = crypto_domain.CRYPTO_PATTERNS
    try:
        crypto_domain.NOISE_PATTERNS = ["("]
        assert crypto_domain._is_candidate_string("abc") is False
        crypto_domain.CRYPTO_PATTERNS = {"Bad": ["("]}
        assert crypto_domain._matches_any_pattern("abc", ["("]) is False
        result = crypto_domain.consolidate_detections(
            {
                "AES": [
                    {"confidence": 0.5, "evidence_type": "a"},
                    {"confidence": 0.6, "evidence_type": "b"},
                ]
            }
        )
        assert result[0]["confidence"] == 0.8
    finally:
        crypto_domain.NOISE_PATTERNS = old_noise
        crypto_domain.CRYPTO_PATTERNS = old_crypto

    auth = AuthenticodeAnalyzer(adapter=SimpleNamespace())
    assert auth._extract_cn_entry([0x55, 0x04, 0x03, 0x00, 2, 999, 999], 0, 0) is None

    class _BadSig(dict):
        def get(self, *_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError("bad")

    assert auth._verify_signature_integrity(_BadSig()) is False


def test_batch_processing_magic_resolution_branches(monkeypatch) -> None:
    old_magic = batch_processing.magic
    try:
        batch_processing.magic = batch_processing._MAGIC_UNINITIALIZED
        monkeypatch.setattr(batch_processing.sys, "platform", "win32")
        assert batch_processing._resolve_magic_module() is None

        batch_processing.magic = batch_processing._MAGIC_UNINITIALIZED
        monkeypatch.setattr(batch_processing.sys, "platform", "linux")
        real_import = __import__

        def _fake_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "magic":
                raise ImportError("missing")
            return real_import(name, globals, locals, fromlist, level)

        monkeypatch.setattr("builtins.__import__", _fake_import)
        assert batch_processing._resolve_magic_module() is None

        batch_processing.magic = batch_processing._MAGIC_UNINITIALIZED
        assert batch_processing._init_magic() is None
    finally:
        batch_processing.magic = old_magic
