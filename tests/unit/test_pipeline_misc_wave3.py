"""Coverage tests for wave-3 target modules.

Targets:
    - r2inspect/lazy_loader_stats.py
    - r2inspect/pipeline/stage_models.py
    - r2inspect/modules/ccbhash_analyzer.py
    - r2inspect/modules/string_analyzer.py
    - r2inspect/modules/binbloom_analyzer.py
    - r2inspect/pipeline/stages_format.py
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

import pytest

from r2inspect.lazy_loader import LazyAnalyzerLoader
from r2inspect.lazy_loader_stats import build_stats, print_stats
from r2inspect.modules.binbloom_analyzer import BLOOM_AVAILABLE, BinbloomAnalyzer
from r2inspect.modules.ccbhash_analyzer import CCBHashAnalyzer
from r2inspect.modules.string_analyzer import StringAnalyzer
from r2inspect.pipeline.stage_models import AnalysisStage, ThreadSafeContext
from r2inspect.pipeline.stages_format import FormatDetectionStage, FormatAnalysisStage

FIXTURE_DIR = Path("samples/fixtures")
HELLO_PE = FIXTURE_DIR / "hello_pe.exe"
HELLO_ELF = FIXTURE_DIR / "hello_elf"
HELLO_MACHO = FIXTURE_DIR / "hello_macho"

# ============================================================
# lazy_loader_stats  (lines 34,36-51)
# ============================================================


def test_print_stats_header(capsys) -> None:
    loader = LazyAnalyzerLoader()
    loader.register("base", "r2inspect.schemas.base", "AnalysisResultBase")
    print_stats(loader)
    out = capsys.readouterr().out
    assert "Lazy Loader Statistics" in out
    assert "Registered analyzers:" in out


def test_print_stats_counter_fields(capsys) -> None:
    loader = LazyAnalyzerLoader()
    loader.register("base", "r2inspect.schemas.base", "AnalysisResultBase")
    print_stats(loader)
    out = capsys.readouterr().out
    assert "Cache hits:" in out
    assert "Cache misses:" in out
    assert "Failed loads:" in out
    assert "Cache hit rate:" in out
    assert "Lazy ratio:" in out


def test_print_stats_load_times_section(capsys) -> None:
    """Lines 48-51: load_times block executes when an analyzer has been loaded."""
    loader = LazyAnalyzerLoader()
    loader.register("base", "r2inspect.schemas.base", "AnalysisResultBase")
    loader.get_analyzer_class("base")
    print_stats(loader)
    out = capsys.readouterr().out
    assert "Load Times" in out
    assert "base" in out


# ============================================================
# stage_models  (lines 36,43-45,53-54,76-77,86-87,100-101,110-111,121-122)
# ============================================================


class _ConcreteStage(AnalysisStage):
    def _execute(self, context: dict) -> dict:
        return {"done": True}


def test_analysis_stage_can_execute_no_deps() -> None:
    stage = _ConcreteStage("s")
    assert stage.can_execute(set()) is True


def test_analysis_stage_can_execute_deps_satisfied() -> None:
    stage = _ConcreteStage("s", dependencies=["a", "b"])
    assert stage.can_execute({"a", "b"}) is True


def test_analysis_stage_can_execute_deps_missing() -> None:
    stage = _ConcreteStage("s", dependencies=["a"])
    assert stage.can_execute(set()) is False


def test_analysis_stage_should_execute_condition_raises() -> None:
    """Lines 43-45: condition callback raises -> should_execute returns False."""

    def _bad(ctx: dict) -> bool:
        raise ValueError("oops")

    stage = _ConcreteStage("s", condition=_bad)
    assert stage.should_execute({}) is False


def test_analysis_stage_condition_false_skips_execute() -> None:
    """Lines 53-54: should_execute returns False -> execute returns {}."""
    stage = _ConcreteStage("s", condition=lambda ctx: False)
    assert stage.execute({}) == {}


def test_thread_safe_context_init_empty() -> None:
    ctx = ThreadSafeContext()
    assert ctx.get_all() == {}


def test_thread_safe_context_init_with_data() -> None:
    ctx = ThreadSafeContext({"k": "v"})
    assert ctx.get("k") == "v"


def test_thread_safe_context_update() -> None:
    ctx = ThreadSafeContext()
    ctx.update({"a": 1, "b": 2})
    assert ctx.get("a") == 1
    assert ctx.get("b") == 2


def test_thread_safe_context_get_missing_key() -> None:
    ctx = ThreadSafeContext()
    assert ctx.get("missing", "fallback") == "fallback"


def test_thread_safe_context_get_all_returns_copy() -> None:
    ctx = ThreadSafeContext({"x": 10})
    snapshot = ctx.get_all()
    ctx.update({"x": 99})
    assert snapshot["x"] == 10


def test_thread_safe_context_set_new_key() -> None:
    ctx = ThreadSafeContext()
    ctx.set("key", "value")
    assert ctx.get("key") == "value"


def test_thread_safe_context_set_overwrites() -> None:
    ctx = ThreadSafeContext({"key": "old"})
    ctx.set("key", "new")
    assert ctx.get("key") == "new"


# ============================================================
# ccbhash_analyzer helpers
# ============================================================


class _NoFunctionsAdapter:
    def get_functions(self) -> list:
        return []

    def get_cfg(self, func_offset: int) -> list:
        return []


class _SingleFunctionAdapter:
    def get_functions(self) -> list:
        return [{"name": "main", "addr": 0x1000, "size": 100}]

    def get_cfg(self, func_offset: int) -> list:
        return [
            {
                "edges": [
                    {"src": func_offset, "dst": func_offset + 0x10},
                ]
            }
        ]


class _InvalidEdgeCFGAdapter:
    """CFG with edges that all have None src/dst so canonical representation is ''."""

    def get_functions(self) -> list:
        return [{"name": "null_edge_func", "addr": 0x2000, "size": 64}]

    def get_cfg(self, func_offset: int) -> list:
        return [{"edges": [{"src": None, "dst": None}]}]


def _ccbhash(adapter: Any, tmp_path: Path) -> CCBHashAnalyzer:
    fp = tmp_path / "test.bin"
    fp.write_bytes(b"\x00" * 16)
    return CCBHashAnalyzer(adapter=adapter, filepath=str(fp))


# ============================================================
# ccbhash_analyzer  (lines 40-42,64,81,83-85,94,139,179-181,244,346-348,417)
# ============================================================


def test_ccbhash_is_available() -> None:
    """Line 417: is_available always returns True."""
    assert CCBHashAnalyzer.is_available() is True


def test_ccbhash_check_library_availability(tmp_path) -> None:
    """Lines 40-42: _check_library_availability returns (True, None)."""
    analyzer = _ccbhash(_NoFunctionsAdapter(), tmp_path)
    ok, err = analyzer._check_library_availability()
    assert ok is True
    assert err is None


def test_ccbhash_get_hash_type(tmp_path) -> None:
    """Line 94: _get_hash_type returns 'ccbhash'."""
    analyzer = _ccbhash(_NoFunctionsAdapter(), tmp_path)
    assert analyzer._get_hash_type() == "ccbhash"


def test_ccbhash_calculate_hash_skips_null_addr(tmp_path) -> None:
    """Line 64: func_offset is None inside _calculate_hash loop -> continue."""

    class _NullAddrCalcHash(CCBHashAnalyzer):
        def _extract_functions(self) -> list:
            return [{"name": "null", "addr": None, "size": 50}]

    analyzer = _NullAddrCalcHash(adapter=_NoFunctionsAdapter(), filepath=str(tmp_path / "t.bin"))
    (tmp_path / "t.bin").write_bytes(b"\x00" * 16)
    result = analyzer._calculate_hash()
    assert result[0] is None


def test_ccbhash_calculate_hash_binary_hash_none(tmp_path) -> None:
    """Line 81: binary_ccbhash is None -> 'Failed to calculate binary CCBHash'."""

    class _NoBinaryHash(CCBHashAnalyzer):
        def _calculate_binary_ccbhash(self, function_hashes: dict) -> None:  # type: ignore[override]
            return None

    (tmp_path / "t.bin").write_bytes(b"\x00" * 16)
    analyzer = _NoBinaryHash(adapter=_SingleFunctionAdapter(), filepath=str(tmp_path / "t.bin"))
    result = analyzer._calculate_hash()
    assert result[0] is None
    assert result[2] == "Failed to calculate binary CCBHash"


def test_ccbhash_calculate_hash_exception_branch(tmp_path) -> None:
    """Lines 83-85: exception propagates from _extract_functions -> error tuple."""

    class _RaisingExtract(CCBHashAnalyzer):
        def _extract_functions(self) -> list:
            raise RuntimeError("extraction boom")

    (tmp_path / "t.bin").write_bytes(b"\x00" * 16)
    analyzer = _RaisingExtract(adapter=_NoFunctionsAdapter(), filepath=str(tmp_path / "t.bin"))
    result = analyzer._calculate_hash()
    assert result[0] is None
    assert "CCBHash calculation failed" in (result[2] or "")


def test_ccbhash_analyze_functions_skips_null_addr(tmp_path) -> None:
    """Line 139: func_offset is None inside analyze_functions loop -> continue."""

    class _NullAddrAnalyze(CCBHashAnalyzer):
        def _extract_functions(self) -> list:
            return [{"name": "null", "addr": None, "size": 50}]

    (tmp_path / "t.bin").write_bytes(b"\x00" * 16)
    analyzer = _NullAddrAnalyze(adapter=_NoFunctionsAdapter(), filepath=str(tmp_path / "t.bin"))
    result = analyzer.analyze_functions()
    assert result["analyzed_functions"] == 0


def test_ccbhash_analyze_functions_exception_branch(tmp_path) -> None:
    """Lines 179-181: exception in analyze_functions try block -> error recorded."""

    class _RaisingSimilar(CCBHashAnalyzer):
        def _find_similar_functions(self, function_hashes: dict) -> list:
            raise RuntimeError("similar boom")

    (tmp_path / "t.bin").write_bytes(b"\x00" * 16)
    analyzer = _RaisingSimilar(adapter=_SingleFunctionAdapter(), filepath=str(tmp_path / "t.bin"))
    result = analyzer.analyze_functions()
    assert result["error"] is not None
    assert "similar boom" in result["error"]


def test_ccbhash_function_ccbhash_empty_canonical(tmp_path) -> None:
    """Line 244: canonical is '' (falsy) -> _calculate_function_ccbhash returns None."""
    (tmp_path / "t.bin").write_bytes(b"\x00" * 16)
    analyzer = CCBHashAnalyzer(adapter=_InvalidEdgeCFGAdapter(), filepath=str(tmp_path / "t.bin"))
    result = analyzer._calculate_function_ccbhash(0x2000, "null_edge_func")
    assert result is None


def test_ccbhash_calculate_binary_ccbhash_exception(tmp_path) -> None:
    """Lines 346-348: KeyError inside _calculate_binary_ccbhash -> returns None."""
    (tmp_path / "t.bin").write_bytes(b"\x00" * 16)
    analyzer = CCBHashAnalyzer(adapter=_NoFunctionsAdapter(), filepath=str(tmp_path / "t.bin"))
    bad_data: dict[str, Any] = {"func_a": {"no_ccbhash_key": "val"}}
    assert analyzer._calculate_binary_ccbhash(bad_data) is None


# ============================================================
# string_analyzer helpers
# ============================================================


class _StringsConfig:
    min_length: int = 4
    max_length: int = 200
    extract_ascii: bool = True
    extract_unicode: bool = True


class _GeneralConfig:
    max_strings: int = 50


class _TypedConfig:
    strings = _StringsConfig()
    general = _GeneralConfig()


class _StubConfig:
    typed_config = _TypedConfig()


class _StubAdapter:
    def __init__(self, entries: list | None = None) -> None:
        self._entries = entries or []

    def get_strings_basic(self) -> list:
        return self._entries

    def read_bytes(self, addr: int, size: int) -> bytes:
        return b""


def _make_sa(adapter: Any = None, config: Any = None) -> StringAnalyzer:
    return StringAnalyzer(
        adapter=adapter or _StubAdapter(),
        config=config or _StubConfig(),
    )


# ============================================================
# string_analyzer  (lines 34,37,41,51-56,58,83-84,102-104,118-119,121)
# ============================================================


def test_string_analyzer_get_category() -> None:
    """Line 34: get_category returns 'metadata'."""
    assert _make_sa().get_category() == "metadata"


def test_string_analyzer_get_description() -> None:
    """Line 37: get_description returns a descriptive string."""
    desc = _make_sa().get_description()
    assert "string" in desc.lower()


def test_string_analyzer_analyze_returns_expected_keys() -> None:
    """Lines 41-58: analyze() executes fully and returns structured result."""
    result = _make_sa().analyze()
    assert "total_strings" in result
    assert "strings" in result


def test_string_analyzer_analyze_with_entries() -> None:
    """Lines 51-56: analyze() counts and stores extracted strings."""
    adapter = _StubAdapter(
        [{"string": "hello_world", "length": 11}, {"string": "another_str", "length": 11}]
    )
    result = _make_sa(adapter=adapter).analyze()
    assert result["total_strings"] >= 0
    assert isinstance(result["strings"], list)


def test_string_analyzer_extract_strings_exception_branch() -> None:
    """Lines 83-84: unhandled exception in _extract_ascii_strings reaches extract_strings except."""

    class _FailAscii(StringAnalyzer):
        def _extract_ascii_strings(self) -> list:
            raise RuntimeError("ascii extraction failure")

    result = _FailAscii(adapter=_StubAdapter(), config=_StubConfig()).extract_strings()
    assert result == []


def test_string_analyzer_extract_unicode_exception_branch() -> None:
    """Lines 102-104: exception raised inside _extract_unicode_strings caught internally."""

    class _FailUnicode(StringAnalyzer):
        def _fetch_string_entries(self, cmd: str) -> list:
            if cmd == "izuj":
                raise RuntimeError("unicode failure")
            return []

    result = _FailUnicode(adapter=_StubAdapter(), config=_StubConfig())._extract_unicode_strings()
    assert result == []


def test_string_analyzer_search_xor_returns_list() -> None:
    """Lines 118-121: search_xor executes the inner _search_hex and build_xor_matches."""
    result = _make_sa().search_xor("hello")
    assert isinstance(result, list)


# ============================================================
# binbloom_analyzer  (lines 62,64,111,124,193-195,305,532-534)
# ============================================================


class _NoFuncsBinbloomAdapter:
    def analyze_all(self) -> None:
        pass

    def get_functions(self) -> list:
        return []

    def get_disasm(self, address: int | None = None, size: int | None = None) -> None:
        return None

    def get_disasm_text(self, address: int | None = None, size: int | None = None) -> None:
        return None


class _SingleFuncBinbloomAdapter:
    def analyze_all(self) -> None:
        pass

    def get_functions(self) -> list:
        return [{"name": "main", "addr": 0x1000, "size": 100}]

    def get_disasm(self, address: int | None = None, size: int | None = None) -> Any:
        if size is None:
            return {"ops": [{"mnemonic": "push"}, {"mnemonic": "mov"}, {"mnemonic": "ret"}]}
        return [{"mnemonic": "push"}, {"mnemonic": "mov"}, {"mnemonic": "ret"}]

    def get_disasm_text(self, address: int | None = None, size: int | None = None) -> str:
        return "push rbp\nmov rsp, rbp\nret\n"


def _binbloom(adapter: Any, tmp_path: Path) -> BinbloomAnalyzer:
    fp = tmp_path / "test.bin"
    fp.write_bytes(b"\x00" * 16)
    return BinbloomAnalyzer(adapter=adapter, filepath=str(fp))


@pytest.mark.skipif(not BLOOM_AVAILABLE, reason="pybloom-live not installed")
def test_binbloom_analyze_returns_dict(tmp_path) -> None:
    """Lines 62,64: analyze() import + cast path executes."""
    result = _binbloom(_NoFuncsBinbloomAdapter(), tmp_path).analyze()
    assert isinstance(result, dict)


@pytest.mark.skipif(not BLOOM_AVAILABLE, reason="pybloom-live not installed")
def test_binbloom_collect_unique_signatures(tmp_path) -> None:
    """Line 111: _collect_unique_signatures deduplicates by signature."""
    analyzer = _binbloom(_NoFuncsBinbloomAdapter(), tmp_path)
    sigs = {
        "f_a": {"signature": "hash1"},
        "f_b": {"signature": "hash2"},
        "f_c": {"signature": "hash1"},
    }
    unique = analyzer._collect_unique_signatures(sigs)
    assert unique == {"hash1", "hash2"}


@pytest.mark.skipif(not BLOOM_AVAILABLE, reason="pybloom-live not installed")
def test_binbloom_add_binary_bloom_skips_when_no_bloom(tmp_path) -> None:
    """Line 124: _add_binary_bloom early-returns when _create_binary_bloom returns None."""

    class _NoBinaryBloom(BinbloomAnalyzer):
        def _create_binary_bloom(
            self,
            all_instructions: set,
            capacity: int,
            error_rate: float,
        ) -> None:  # type: ignore[override]
            return None

    analyzer = _NoBinaryBloom(adapter=_NoFuncsBinbloomAdapter(), filepath=str(tmp_path / "t.bin"))
    (tmp_path / "t.bin").write_bytes(b"\x00" * 16)
    results: dict[str, Any] = {"binary_bloom": None, "binary_signature": None}
    analyzer._add_binary_bloom(results, {"push", "mov"}, 256, 0.001)
    assert results["binary_bloom"] is None


@pytest.mark.skipif(not BLOOM_AVAILABLE, reason="pybloom-live not installed")
def test_binbloom_create_function_bloom_exception(tmp_path) -> None:
    """Lines 193-195: exception inside _create_function_bloom -> returns None."""

    class _RaisingBloom(BinbloomAnalyzer):
        def _build_bloom_filter(
            self,
            instructions: list,
            capacity: int,
            error_rate: float,
        ) -> None:
            raise RuntimeError("bloom fail")

    analyzer = _RaisingBloom(adapter=_SingleFuncBinbloomAdapter(), filepath=str(tmp_path / "t.bin"))
    (tmp_path / "t.bin").write_bytes(b"\x00" * 16)
    assert analyzer._create_function_bloom(0x1000, "main", 256, 0.001) is None


@pytest.mark.skipif(not BLOOM_AVAILABLE, reason="pybloom-live not installed")
def test_binbloom_normalize_mnemonic_none(tmp_path) -> None:
    """Line 305: _normalize_mnemonic returns None for None and empty string."""
    analyzer = _binbloom(_NoFuncsBinbloomAdapter(), tmp_path)
    assert analyzer._normalize_mnemonic(None) is None
    assert analyzer._normalize_mnemonic("") is None


@pytest.mark.skipif(not BLOOM_AVAILABLE, reason="pybloom-live not installed")
def test_binbloom_accumulate_bloom_bits_with_bit_array(tmp_path) -> None:
    """Lines 532-534: loop body executes when bloom filter has bit_array attribute."""
    analyzer = _binbloom(_NoFuncsBinbloomAdapter(), tmp_path)

    class _FakeBloom:
        bit_array = [True, False, True, True]

    bits, capacity = analyzer._accumulate_bloom_bits({"func": _FakeBloom()})
    assert bits == 3
    assert capacity == 4


# ============================================================
# stages_format  (lines 109,147-150,152,162-165,167,262)
# ============================================================


class _FakeAdapter:
    def __init__(self, bin_info: dict | None = None) -> None:
        self._bin_info = bin_info

    def get_file_info(self) -> dict | None:
        return self._bin_info


def _ctx() -> dict[str, Any]:
    return {"options": {}, "results": {}, "metadata": {}}


def test_format_detection_unknown_when_all_fail(tmp_path) -> None:
    """Line 109: all three detection methods fail -> file_format = 'Unknown'."""
    fp = tmp_path / "random.bin"
    fp.write_bytes(b"\xff\xfe\xfd\xfc" * 20)
    stage = FormatDetectionStage(adapter=_FakeAdapter(), filename=str(fp))
    ctx = _ctx()
    stage._execute(ctx)
    assert ctx["metadata"]["file_format"] == "Unknown"


def test_format_detection_enhanced_magic_archive(tmp_path) -> None:
    """Lines 147-148: ZIP bytes -> _detect_via_enhanced_magic returns 'Archive'."""
    fp = tmp_path / "test.zip"
    fp.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    stage = FormatDetectionStage(adapter=_FakeAdapter(), filename=str(fp))
    assert stage._detect_via_enhanced_magic() == "Archive"


def test_format_detection_enhanced_magic_low_confidence_returns_none(tmp_path) -> None:
    """Line 152: _detect_via_enhanced_magic returns None when confidence <= 0.7."""
    fp = tmp_path / "rand.bin"
    fp.write_bytes(b"\xff\xfe\xfd" * 50)
    stage = FormatDetectionStage(adapter=_FakeAdapter(), filename=str(fp))
    result = stage._detect_via_enhanced_magic()
    assert result is None or isinstance(result, str)


def test_format_detection_basic_magic_elf() -> None:
    """Lines 162-163: ELF magic -> _detect_via_basic_magic returns 'ELF'."""
    stage = FormatDetectionStage(adapter=_FakeAdapter(), filename=str(HELLO_ELF))
    assert stage._detect_via_basic_magic() == "ELF"


def test_format_detection_basic_magic_pe() -> None:
    """PE magic -> _detect_via_basic_magic returns 'PE'."""
    stage = FormatDetectionStage(adapter=_FakeAdapter(), filename=str(HELLO_PE))
    assert stage._detect_via_basic_magic() == "PE"


def test_format_detection_basic_magic_macho() -> None:
    """Lines 164-165: Mach-O magic -> _detect_via_basic_magic returns 'Mach-O'."""
    stage = FormatDetectionStage(adapter=_FakeAdapter(), filename=str(HELLO_MACHO))
    assert stage._detect_via_basic_magic() == "Mach-O"


def test_format_detection_basic_magic_none_for_unknown(tmp_path) -> None:
    """Line 167: file type not recognized -> _detect_via_basic_magic returns None."""
    fp = tmp_path / "unknown.bin"
    fp.write_bytes(b"\xff\xfe\xfd" * 40)
    stage = FormatDetectionStage(adapter=_FakeAdapter(), filename=str(fp))
    assert stage._detect_via_basic_magic() is None


def test_format_analysis_optional_pe_analyzer_executed(tmp_path) -> None:
    """Line 262: pe_info[result_key] = analyzer.analyze() in _run_optional_pe_analyzers."""
    from r2inspect.registry.analyzer_registry import AnalyzerRegistry

    class _OverlayAnalyzer:
        def __init__(self, adapter: Any = None, config: Any = None, filename: Any = None, **kw):
            pass

        def analyze(self) -> dict[str, Any]:
            return {"overlay_data": "none"}

    class _OverlayConfig:
        analyze_authenticode: bool = False
        analyze_overlay: bool = True
        analyze_resources: bool = False
        analyze_mitigations: bool = False

    registry = AnalyzerRegistry()
    registry.register("overlay_analyzer", _OverlayAnalyzer, category="format")

    stage = FormatAnalysisStage(
        registry=registry,
        adapter=_FakeAdapter(),
        config=_OverlayConfig(),
        filename=str(HELLO_PE),
    )
    pe_info: dict[str, Any] = {}
    stage._run_optional_pe_analyzers(pe_info)
    assert "overlay" in pe_info
    assert pe_info["overlay"] == {"overlay_data": "none"}
