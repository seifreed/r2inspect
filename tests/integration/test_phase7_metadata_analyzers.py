from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.config import Config
from r2inspect.modules.export_analyzer import ExportAnalyzer
from r2inspect.modules.function_analyzer import FunctionAnalyzer
from r2inspect.modules.import_analyzer import ImportAnalyzer
from r2inspect.modules.resource_analyzer import ResourceAnalyzer
from r2inspect.modules.section_analyzer import SectionAnalyzer
from r2inspect.modules.string_analyzer import StringAnalyzer

pytestmark = pytest.mark.requires_r2

PE_FIXTURE = "samples/fixtures/hello_pe.exe"
ELF_FIXTURE = "samples/fixtures/hello_elf"
BAD_PE_FIXTURE = "samples/fixtures/edge_bad_pe.bin"
TINY_FIXTURE = "samples/fixtures/edge_tiny.bin"


def _config(tmp_path: Path) -> Config:
    return Config(str(tmp_path / "r2inspect_phase7.json"))


def _open_adapter(path: str) -> tuple[Any, R2PipeAdapter]:
    r2 = r2pipe.open(path)
    return r2, R2PipeAdapter(r2)


def test_import_analyzer_handles_empty_and_ordinal_only(tmp_path: Path) -> None:
    r2, adapter = _open_adapter(PE_FIXTURE)
    try:
        analyzer = ImportAnalyzer(adapter, _config(tmp_path))
        result = analyzer.analyze()
    finally:
        r2.quit()

    assert result["available"] is True
    assert "imports" in result
    assert "dlls" in result
    if result["imports"]:
        for entry in result["imports"]:
            assert "name" in entry
            assert "ordinal" in entry
            if entry.get("name") in {"", "unknown"}:
                assert entry.get("ordinal", 0) > 0

    r2, adapter = _open_adapter(BAD_PE_FIXTURE)
    try:
        analyzer = ImportAnalyzer(adapter, _config(tmp_path))
        empty_result = analyzer.analyze()
    finally:
        r2.quit()

    assert empty_result["available"] is True
    assert empty_result["total_imports"] == 0
    assert empty_result["total_dlls"] == 0
    assert empty_result["imports"] == []
    assert empty_result["dlls"] == []


def test_export_analyzer_defaults_and_stats(tmp_path: Path) -> None:
    r2, adapter = _open_adapter(ELF_FIXTURE)
    try:
        analyzer = ExportAnalyzer(adapter, _config(tmp_path))
        result = analyzer.analyze()
    finally:
        r2.quit()

    assert result["available"] is True
    assert result["total_exports"] == len(result["exports"])
    assert "export_names" in result["statistics"]
    assert result["statistics"]["total_exports"] == len(result["exports"])
    if result["exports"]:
        export_entry = result["exports"][0]
        assert isinstance(export_entry.get("address"), str)
        assert export_entry["address"].startswith("0x")
        assert isinstance(export_entry.get("characteristics"), dict)


def test_section_analyzer_permissions_and_entropy(tmp_path: Path) -> None:
    r2, adapter = _open_adapter(PE_FIXTURE)
    try:
        analyzer = SectionAnalyzer(adapter, _config(tmp_path))
        result = analyzer.analyze()
    finally:
        r2.quit()

    assert result["available"] is True
    assert result["sections"]

    for section in result["sections"]:
        flags = str(section.get("flags", ""))
        if "x" in flags:
            assert section["is_executable"] is True
        if "w" in flags:
            assert section["is_writable"] is True
        if "r" in flags:
            assert section["is_readable"] is True
        entropy = section.get("entropy", 0.0)
        assert 0.0 <= entropy <= 8.0


def test_function_analyzer_basic_and_empty() -> None:
    r2, adapter = _open_adapter(ELF_FIXTURE)
    try:
        analyzer = FunctionAnalyzer(adapter)
        result = analyzer.analyze_functions()
    finally:
        r2.quit()

    assert result["total_functions"] > 0
    assert result["machoc_hashes"]
    assert result["functions_analyzed"] <= result["total_functions"]
    for hash_value in result["machoc_hashes"].values():
        assert isinstance(hash_value, str)
        assert len(hash_value) == 64

    r2, adapter = _open_adapter(TINY_FIXTURE)
    try:
        analyzer = FunctionAnalyzer(adapter)
        empty_result = analyzer.analyze_functions()
    finally:
        r2.quit()

    assert empty_result["total_functions"] == 0
    assert empty_result["machoc_hashes"] == {}
    assert empty_result["error"] == "No functions detected"


def test_string_analyzer_min_length_and_decode_errors(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.set("strings", "min_length", 8)
    config.set("strings", "max_length", 64)

    r2, adapter = _open_adapter(PE_FIXTURE)
    try:
        analyzer = StringAnalyzer(adapter, config)
        result = analyzer.analyze()
    finally:
        r2.quit()

    assert result["available"] is True
    for string_value in result["strings"]:
        assert 8 <= len(string_value) <= 64

    r2, adapter = _open_adapter(PE_FIXTURE)
    try:
        analyzer = StringAnalyzer(adapter, config)
        assert analyzer._decode_base64("!!not-base64!!") is None
        assert analyzer._decode_hex("zzzz") is None
    finally:
        r2.quit()


def test_resource_analyzer_malformed_and_binary_extraction() -> None:
    r2, adapter = _open_adapter(BAD_PE_FIXTURE)
    try:
        analyzer = ResourceAnalyzer(adapter)
        result = analyzer.analyze()
    finally:
        r2.quit()

    assert result["has_resources"] is False
    assert result.get("resources", []) == []

    r2, adapter = _open_adapter(PE_FIXTURE)
    try:
        analyzer = ResourceAnalyzer(adapter)
        resource_info = {"offset": 0x100, "size": 64, "entropy": 0.0, "hashes": {}}
        analyzer._analyze_resource_data(resource_info)
    finally:
        r2.quit()

    assert resource_info["entropy"] >= 0.0
    if resource_info["hashes"]:
        assert "md5" in resource_info["hashes"]
        assert "sha1" in resource_info["hashes"]
        assert "sha256" in resource_info["hashes"]
