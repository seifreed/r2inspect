"""Remaining edge coverage for wave9 top10 modules."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from r2inspect.modules.ccbhash_analyzer import CCBHashAnalyzer
from r2inspect.pipeline import stages_format as sf
from r2inspect.registry import default_registry as default_registry_module
from r2inspect.cli.output_csv import CsvOutputFormatter


class _Adapter:
    def get_file_info(self):
        return {}

    def get_cfg(self, _offset):
        return [{"edges": [{"src": 1, "dst": 2}]}]


def test_ccbhash_remaining_paths(monkeypatch) -> None:
    analyzer = CCBHashAnalyzer(adapter=_Adapter(), filepath="/tmp/a.bin")
    orig_calc_func = analyzer._calculate_function_ccbhash
    orig_calc_binary = analyzer._calculate_binary_ccbhash

    # line 42
    monkeypatch.setattr(CCBHashAnalyzer, "is_available", staticmethod(lambda: False))
    assert analyzer._check_library_availability() == (False, "CCBHash analysis is not available")

    # line 64 and 81: skip None addr, binary hash fails
    analyzer._extract_functions = lambda: [{"name": "f0", "addr": None}, {"name": "f1", "addr": 1}]  # type: ignore[method-assign]
    analyzer._calculate_function_ccbhash = lambda _off, _name: "h1"  # type: ignore[method-assign]
    analyzer._calculate_binary_ccbhash = lambda _fh: None  # type: ignore[method-assign]
    assert analyzer._calculate_hash() == (None, None, "Failed to calculate binary CCBHash")

    # lines 84-85: exception in _calculate_hash
    analyzer._extract_functions = lambda: (_ for _ in ()).throw(RuntimeError("boom"))  # type: ignore[method-assign]
    _hash, _method, err = analyzer._calculate_hash()
    assert _hash is None and _method is None and err is not None and "failed" in err.lower()

    # line 139 and 179-181 in analyze_functions
    analyzer._extract_functions = lambda: [{"name": "f0", "addr": None}, {"name": "f1", "addr": 1}]  # type: ignore[method-assign]
    analyzer._calculate_function_ccbhash = lambda _off, _name: "h1"  # type: ignore[method-assign]
    analyzer._find_similar_functions = lambda _fh: (_ for _ in ()).throw(RuntimeError("oops"))  # type: ignore[method-assign]
    out = analyzer.analyze_functions()
    assert out["error"] == "oops"

    # line 244
    analyzer._calculate_function_ccbhash = orig_calc_func  # type: ignore[method-assign]
    analyzer.adapter = _Adapter()
    analyzer.adapter.get_cfg = lambda _off: [{"edges": [{"src": 1, "dst": 2}]}]  # type: ignore[method-assign]
    monkeypatch.setattr(
        CCBHashAnalyzer, "_build_canonical_representation", staticmethod(lambda _cfg, _off: None)
    )
    assert analyzer._calculate_function_ccbhash(1, "f") is None

    # lines 346-348
    analyzer._calculate_binary_ccbhash = orig_calc_binary  # type: ignore[method-assign]

    class _BadData(dict):
        def __bool__(self):
            return True

        def values(self):
            raise RuntimeError("bad values")

    bad = _BadData({"x": {"ccbhash": "aa"}})
    assert analyzer._calculate_binary_ccbhash(bad) is None


def test_stages_format_remaining_paths(monkeypatch, tmp_path: Path) -> None:
    # 39-40
    assert sf._resolved_path(1) == 1  # type: ignore[arg-type]

    # 69-70 in FileInfoStage when no magic detectors
    monkeypatch.setattr(sf, "_magic_initialized", True)
    monkeypatch.setattr(sf, "_magic_detectors", None)
    monkeypatch.setattr(sf, "calculate_hashes", lambda _p: {"md5": "x", "sha256": "y"})
    file_path = tmp_path / "a.bin"
    file_path.write_bytes(b"x")
    stage = sf.FileInfoStage(adapter=_Adapter(), filename=str(file_path))
    context = {"results": {}}
    result = stage._execute(context)
    assert result["file_info"]["mime_type"] is None and result["file_info"]["file_type"] is None

    # 127 + 129
    detect = sf.FormatDetectionStage(adapter=_Adapter(), filename=str(file_path))
    monkeypatch.setattr(detect, "_detect_via_r2", lambda: None)
    monkeypatch.setattr(detect, "_detect_via_enhanced_magic", lambda: None)
    monkeypatch.setattr(detect, "_detect_via_basic_magic", lambda: None)
    context = {"results": {}, "metadata": {}}
    out = detect._execute(context)
    assert out["format_detection"]["file_format"] == "Unknown"

    # 158-163, 178-183
    detect2 = sf.FormatDetectionStage(adapter=_Adapter(), filename=str(file_path))
    monkeypatch.setattr(
        sf, "detect_file_type", lambda _p: {"confidence": 0.2, "file_format": "PE32"}
    )
    assert detect2._detect_via_enhanced_magic() == "PE"
    monkeypatch.setattr(
        sf, "detect_file_type", lambda _p: {"confidence": 0.2, "file_format": "NOPE"}
    )
    assert detect2._detect_via_enhanced_magic() is None
    monkeypatch.setattr(
        sf, "detect_file_type", lambda _p: {"confidence": 0.9, "file_format": "ZIP"}
    )
    assert detect2._detect_via_enhanced_magic() == "Archive"
    monkeypatch.setattr(
        sf, "detect_file_type", lambda _p: {"confidence": 0.9, "file_format": "PDF"}
    )
    assert detect2._detect_via_enhanced_magic() == "Document"
    monkeypatch.setattr(
        sf, "detect_file_type", lambda _p: {"confidence": 0.9, "file_format": "RANDOMFMT"}
    )
    assert detect2._detect_via_enhanced_magic() is None

    # 187 and 193-198
    monkeypatch.setattr(sf, "_magic_initialized", True)
    monkeypatch.setattr(sf, "_magic_detectors", None)
    assert detect2._detect_via_basic_magic() is None

    class _Desc:
        def __init__(self, text):
            self.text = text

        def from_file(self, _path):
            return self.text

    monkeypatch.setattr(sf, "_magic_detectors", (None, _Desc("elf binary")))
    assert detect2._detect_via_basic_magic() == "ELF"
    monkeypatch.setattr(sf, "_magic_detectors", (None, _Desc("mach-o binary")))
    assert detect2._detect_via_basic_magic() == "Mach-O"
    monkeypatch.setattr(sf, "_magic_detectors", (None, _Desc("random type")))
    assert detect2._detect_via_basic_magic() is None

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


def test_default_registry_entry_points_exception(monkeypatch) -> None:
    class _R:
        def __init__(self):
            self._items = []

        def register(self, **kwargs):
            self._items.append(kwargs)

        def load_entry_points(self):
            raise RuntimeError("ep fail")

    monkeypatch.setattr(default_registry_module, "AnalyzerRegistry", _R)
    reg = default_registry_module.create_default_registry()
    assert isinstance(reg, _R)


def test_output_csv_clean_file_type_exception(monkeypatch) -> None:
    reporter = CsvOutputFormatter(results={})
    real_import = __import__

    def fake_import(name, *args, **kwargs):
        if name == "re":
            raise RuntimeError("boom")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", fake_import)
    assert reporter._clean_file_type("PE32, 5 sections") == "PE32, 5 sections"
