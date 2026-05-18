"""Remaining edge coverage for wave9 top10 modules."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

from r2inspect.modules.ccbhash_analyzer import CCBHashAnalyzer
from r2inspect.pipeline import stages_format as sf
from r2inspect.registry import default_registry as default_registry_module
from r2inspect.registry.analyzer_registry import AnalyzerRegistry
from r2inspect.cli.output_csv import CsvOutputFormatter


class _Adapter:
    def get_file_info(self) -> dict[str, Any]:
        return {}

    def get_cfg(self, _offset: int) -> list[dict[str, Any]]:
        return [{"edges": [{"src": 1, "dst": 2}]}]


class _CCBHashBinaryFails(CCBHashAnalyzer):
    def _extract_functions(self) -> list[dict[str, Any]]:
        return [{"name": "f0", "addr": None}, {"name": "f1", "addr": 1}]

    def _calculate_function_ccbhash(self, func_offset: int, func_name: str) -> str | None:
        return "h1"

    def _calculate_binary_ccbhash(
        self, function_hashes: dict[str, dict[str, Any]]
    ) -> str | None:
        return None


class _CCBHashExtractRaises(CCBHashAnalyzer):
    def _extract_functions(self) -> list[dict[str, Any]]:
        raise RuntimeError("boom")


class _CCBHashSimilarRaises(CCBHashAnalyzer):
    def _extract_functions(self) -> list[dict[str, Any]]:
        return [{"name": "f0", "addr": None}, {"name": "f1", "addr": 1}]

    def _calculate_function_ccbhash(self, func_offset: int, func_name: str) -> str | None:
        return "h1"

    def _find_similar_functions(
        self, function_hashes: dict[str, dict[str, Any]]
    ) -> list[dict[str, Any]]:
        raise RuntimeError("oops")


class _CCBHashNoCanonical(CCBHashAnalyzer):
    @staticmethod
    def _build_canonical_representation(cfg: dict[str, Any], func_offset: int) -> str | None:
        return None


class _BadData(dict):
    def __bool__(self) -> bool:
        return True

    def values(self) -> Any:
        raise RuntimeError("bad values")


class _Desc:
    def __init__(self, text: str) -> None:
        self.text = text

    def from_file(self, _path: str) -> str:
        return self.text


class _AllNoneDetect(sf.FormatDetectionStage):
    def _detect_via_r2(self) -> str | None:
        return None

    def _detect_via_enhanced_magic(self) -> str | None:
        return None

    def _detect_via_basic_magic(self) -> str | None:
        return None


def test_ccbhash_remaining_paths() -> None:
    # available_fn -> False drives the defensive unavailable branch
    assert CCBHashAnalyzer(
        adapter=_Adapter(), filepath="/tmp/a.bin"
    )._check_library_availability(available_fn=lambda: False) == (
        False,
        "CCBHash analysis is not available",
    )

    # None addr skipped, binary hash fails -> explicit error tuple
    assert _CCBHashBinaryFails(adapter=_Adapter(), filepath="/tmp/a.bin")._calculate_hash() == (
        None,
        None,
        "Failed to calculate binary CCBHash",
    )

    # exception inside _calculate_hash
    _hash, _method, err = _CCBHashExtractRaises(
        adapter=_Adapter(), filepath="/tmp/a.bin"
    )._calculate_hash()
    assert _hash is None and _method is None and err is not None and "failed" in err.lower()

    # _find_similar_functions raises -> analyze_functions surfaces the error
    out = _CCBHashSimilarRaises(adapter=_Adapter(), filepath="/tmp/a.bin").analyze_functions()
    assert out["error"] == "oops"

    # canonical representation None -> real _calculate_function_ccbhash returns None
    assert (
        _CCBHashNoCanonical(adapter=_Adapter(), filepath="/tmp/a.bin")._calculate_function_ccbhash(
            1, "f"
        )
        is None
    )

    # real _calculate_binary_ccbhash with data whose .values() raises -> None
    bad = _BadData({"x": {"ccbhash": "aa"}})
    assert (
        CCBHashAnalyzer(adapter=_Adapter(), filepath="/tmp/a.bin")._calculate_binary_ccbhash(bad)
        is None
    )


def _no_detectors() -> SimpleNamespace:
    return SimpleNamespace(get_detectors=lambda: None)


def test_stages_format_remaining_paths(tmp_path: Path) -> None:
    # non-str path falls through the resolver's except and is returned as-is
    assert sf._resolved_path(cast(str, 1)) == 1

    file_path = tmp_path / "a.bin"
    file_path.write_bytes(b"x")
    # FileInfoStage: no magic detectors (provider yields None) -> mime/type None.
    # hashing via the hash_calculator DI seam.
    stage = sf.FileInfoStage(
        adapter=_Adapter(),
        filename=str(file_path),
        hash_calculator=lambda _p: {"md5": "x", "sha256": "y"},
        magic_detector_provider=_no_detectors(),
    )
    context: dict[str, Any] = {"results": {}}
    result = stage._execute(context)
    assert result["file_info"]["mime_type"] is None and result["file_info"]["file_type"] is None

    # all three detect_* return None -> "Unknown" (subclass double)
    detect = _AllNoneDetect(adapter=_Adapter(), filename=str(file_path))
    context = {"results": {}, "metadata": {}}
    out = detect._execute(context)
    assert out["format_detection"]["file_format"] == "Unknown"

    # 158-163, 178-183 — file-type detection via the file_type_detector DI
    # seam (the module-global detect_file_type was removed in the refactor).
    def _fmt_stage(detector: object) -> sf.FormatDetectionStage:
        return sf.FormatDetectionStage(
            adapter=_Adapter(), filename=str(file_path), file_type_detector=detector
        )

    assert (
        _fmt_stage(lambda _p: {"confidence": 0.2, "file_format": "PE32"})
        ._detect_via_enhanced_magic()
        == "PE"
    )
    assert (
        _fmt_stage(
            lambda _p: {"confidence": 0.2, "file_format": "NOPE"}
        )._detect_via_enhanced_magic()
        is None
    )
    assert (
        _fmt_stage(lambda _p: {"confidence": 0.9, "file_format": "ZIP"})
        ._detect_via_enhanced_magic()
        == "Archive"
    )
    assert (
        _fmt_stage(lambda _p: {"confidence": 0.9, "file_format": "PDF"})
        ._detect_via_enhanced_magic()
        == "Document"
    )
    assert (
        _fmt_stage(
            lambda _p: {"confidence": 0.9, "file_format": "RANDOMFMT"}
        )._detect_via_enhanced_magic()
        is None
    )
    # _detect_via_basic_magic driven by the magic_detector_provider DI seam
    def _basic_stage(detectors: object) -> sf.FormatDetectionStage:
        return sf.FormatDetectionStage(
            adapter=_Adapter(),
            filename=str(file_path),
            magic_detector_provider=SimpleNamespace(get_detectors=lambda: detectors),
        )

    # no detectors -> header-byte fallback on b"x" -> None
    assert _basic_stage(None)._detect_via_basic_magic() is None
    assert _basic_stage((None, _Desc("elf binary")))._detect_via_basic_magic() == "ELF"
    assert _basic_stage((None, _Desc("mach-o binary")))._detect_via_basic_magic() == "Mach-O"
    assert _basic_stage((None, _Desc("random type")))._detect_via_basic_magic() is None

    # 293 in _run_optional_pe_analyzers
    reg = SimpleNamespace(get_analyzer_class=lambda _name: None)
    cfg = SimpleNamespace(
        analyze_authenticode=True,
        analyze_overlay=True,
        analyze_resources=True,
        analyze_mitigations=True,
    )
    fas = sf.FormatAnalysisStage(
        registry=reg, adapter=_Adapter(), config=cfg, filename=str(file_path)
    )
    pe_info = {}
    fas._run_optional_pe_analyzers(pe_info)
    assert pe_info == {}


def test_default_registry_entry_points_exception() -> None:
    # Entry-point loading problems must not break registry creation: the
    # built-in analyzers are registered before load_entry_points and the
    # registry is returned regardless. Drive the real entry_points_fn DI
    # seam (no patching) with a provider that raises.
    def _raising_entry_points() -> object:
        raise RuntimeError("ep fail")

    reg = default_registry_module.create_default_registry(
        entry_points_fn=_raising_entry_points
    )
    assert isinstance(reg, AnalyzerRegistry)
    assert len(reg.list_analyzers()) > 0


def test_output_csv_clean_file_type_exception() -> None:
    reporter = CsvOutputFormatter(results={})

    def _raise_sub(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("boom")

    # The regex_sub seam raises -> defensive except returns the input unchanged.
    assert reporter._clean_file_type("PE32, 5 sections", regex_sub=_raise_sub) == "PE32, 5 sections"
