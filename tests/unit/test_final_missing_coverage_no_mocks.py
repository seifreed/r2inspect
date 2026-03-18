from __future__ import annotations

import builtins
import importlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from r2inspect.adapters.magic_adapter import MagicAdapter
from r2inspect.modules.impfuzzy_analyzer import IMPFUZZY_AVAILABLE, ImpfuzzyAnalyzer
from r2inspect.modules.resource_analyzer import ResourceAnalyzer
from r2inspect.modules.simhash_analyzer import SIMHASH_AVAILABLE, SimHashAnalyzer
from r2inspect.pipeline import stages_format
from r2inspect.registry.analyzer_registry import AnalyzerRegistry
from r2inspect.registry.entry_points import EntryPointLoader


def test_magic_adapter_windows_branch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.platform", "win32")
    adapter = MagicAdapter()
    assert adapter.available is False


def test_magic_adapter_create_detectors_exception() -> None:
    class _BadMagic:
        class Magic:
            def __init__(self, **_: object) -> None:
                raise RuntimeError("boom")

    adapter = MagicAdapter()
    adapter._magic = _BadMagic
    assert adapter.create_detectors() is None


def test_batch_processing_magic_resolution_fallbacks(monkeypatch: pytest.MonkeyPatch) -> None:
    batch = importlib.import_module("r2inspect.cli.batch_processing")

    batch.magic = batch._MAGIC_UNINITIALIZED
    monkeypatch.setattr(batch.sys, "platform", "win32")
    assert batch._resolve_magic_module() is None

    batch.magic = batch._MAGIC_UNINITIALIZED
    monkeypatch.setattr(batch.sys, "platform", "linux")
    original_import = builtins.__import__

    def _raising_import(name: str, *args: object, **kwargs: object):
        if name == "magic":
            raise ImportError("no magic")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _raising_import)
    assert batch._resolve_magic_module() is None

    batch.magic = batch._MAGIC_UNINITIALIZED
    assert batch._init_magic() is None


def test_stages_format_magic_none_and_macho_branch(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x00" * 64)

    class _Adapter:
        def get_file_info(self) -> dict[str, object]:
            return {}

    stage = stages_format.FileInfoStage(_Adapter(), str(sample))
    stages_format._magic_initialized = True
    stages_format._magic_detectors = None
    result = stage._execute({"results": {}})
    assert result["file_info"]["mime_type"] is None
    assert result["file_info"]["file_type"] is None

    class _Desc:
        def from_file(self, _: str) -> str:
            return "Mach-O 64-bit executable"

    stages_format._magic_initialized = True
    stages_format._magic_detectors = (object(), _Desc())
    fd = stages_format.FormatDetectionStage(_Adapter(), str(sample))
    assert fd._detect_via_basic_magic() == "Mach-O"


def test_impfuzzy_exception_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    analyzer = ImpfuzzyAnalyzer(adapter=None, filepath="/tmp/nonexistent")

    class _BadDict(dict):
        def get(self, key: object, default: object = None) -> object:  # type: ignore[override]
            raise RuntimeError("bad")

    assert analyzer._process_imports([_BadDict()]) == []

    class _BadSSDeep:
        @staticmethod
        def compare(_: str, __: str) -> int:
            raise RuntimeError("compare failed")

    monkeypatch.setattr("r2inspect.modules.impfuzzy_analyzer.get_ssdeep", lambda: _BadSSDeep())
    monkeypatch.setattr("r2inspect.modules.impfuzzy_analyzer.IMPFUZZY_AVAILABLE", True)
    assert ImpfuzzyAnalyzer.compare_hashes("a", "b") is None


def test_resource_analyzer_exception_branches() -> None:
    class _RA(ResourceAnalyzer):
        def __init__(self) -> None:
            super().__init__(adapter=None)

    class _VersionCrashRA(_RA):
        def _parse_version_info(self, offset: int, size: int) -> dict[str, object] | None:
            raise RuntimeError("version parse failed")

    result: dict[str, object] = {}
    _VersionCrashRA()._extract_version_info(
        result, [{"type_name": "RT_VERSION", "offset": 1, "size": 128}]
    )
    assert "version_info" not in result

    class _ParseCrashRA(_RA):
        def _read_version_info_data(self, offset: int, size: int) -> list[int] | None:
            return [0] * 128

        def _find_vs_signature(self, data: list[int]) -> int:
            raise RuntimeError("signature fail")

    assert _ParseCrashRA()._parse_version_info(1, 128) is None

    class _ManifestCrashRA(_RA):
        def _read_resource_as_string(self, offset: int, size: int) -> str | None:
            raise RuntimeError("manifest fail")

    manifest_result: dict[str, object] = {}
    _ManifestCrashRA()._extract_manifest(
        manifest_result, [{"type_name": "RT_MANIFEST", "offset": 10, "size": 20}]
    )
    assert "manifest" not in manifest_result

    class _StringCrashRA(_RA):
        def _read_resource_as_string(self, offset: int, size: int) -> str | None:
            raise RuntimeError("string fail")

    strings_result: dict[str, object] = {}
    _StringCrashRA()._extract_strings(
        strings_result, [{"type_name": "RT_STRING", "offset": 10, "size": 20}]
    )
    assert strings_result.get("strings") == []


def test_registry_entry_point_loader_helpers() -> None:
    registry = AnalyzerRegistry()
    ep = SimpleNamespace(name="dummy_ep")

    def obj(r):
        return None

    loader = EntryPointLoader(registry)
    assert loader._register_entry_point_callable(ep, obj) in {0, 1}
    assert isinstance(loader._derive_entry_point_name(ep, obj), str)


@pytest.mark.skipif(not SIMHASH_AVAILABLE, reason="simhash not installed")
def test_simhash_calculate_similarity_with_int_hash_value() -> None:
    class _Analyzer(SimHashAnalyzer):
        def analyze(self) -> dict[str, object]:
            return {"available": True, "hash_value": 123456}

    analyzer = _Analyzer(adapter=None, filepath="/tmp/nonexistent")
    result = analyzer.calculate_similarity(123456, hash_type="combined")
    assert result.get("hash_type") == "combined"
