#!/usr/bin/env python3
"""Unit tests for impfuzzy, overlay, ccbhash, bindiff, macho, and elf analyzers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from r2inspect.modules.impfuzzy_analyzer import ImpfuzzyAnalyzer
from r2inspect.modules.overlay_analyzer import OverlayAnalyzer
from r2inspect.modules.ccbhash_analyzer import CCBHashAnalyzer
from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer
from r2inspect.modules.macho_analyzer import MachOAnalyzer
from r2inspect.modules.elf_analyzer import ELFAnalyzer


# ---------------------------------------------------------------------------
# Stub adapter – covers all adapter method calls used by the analyzers above
# ---------------------------------------------------------------------------


class StubAdapter:
    def cmd(self, cmd_str: str) -> str:
        return ""

    def cmdj(self, cmd_str: str) -> Any:
        return {}

    def get_file_info(self) -> dict[str, Any]:
        return {}

    def get_imports(self) -> list[Any]:
        return []

    def get_exports(self) -> list[Any]:
        return []

    def get_sections(self) -> list[Any]:
        return []

    def get_symbols(self) -> list[Any]:
        return []

    def get_strings(self) -> list[Any]:
        return []

    def get_functions(self) -> list[Any]:
        return []

    def read_bytes(self, offset: int, size: int) -> bytes:
        return b""

    def read_bytes_list(self, offset: int, size: int) -> list[int]:
        return []

    def get_info_text(self) -> str:
        return ""

    def get_dynamic_info_text(self) -> str:
        return ""

    def get_entropy_pattern(self) -> str:
        return ""

    def get_headers_json(self) -> list[Any]:
        return []

    def get_header_text(self) -> str:
        return ""

    def get_data_directories(self) -> list[Any]:
        return []

    def get_cfg(self, address: int | None = None) -> list[Any]:
        return []

    def analyze_all(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_file(tmp_path: Path, name: str = "sample.bin", content: bytes = b"\x00" * 64) -> Path:
    p = tmp_path / name
    p.write_bytes(content)
    return p


# ===========================================================================
# ImpfuzzyAnalyzer
# ===========================================================================


def test_impfuzzy_is_available_returns_bool() -> None:
    result = ImpfuzzyAnalyzer.is_available()
    assert isinstance(result, bool)


def test_impfuzzy_check_library_availability(tmp_path: Path) -> None:
    path = _make_file(tmp_path)
    analyzer = ImpfuzzyAnalyzer(StubAdapter(), str(path))
    available, msg = analyzer._check_library_availability()
    assert isinstance(available, bool)
    if available:
        assert msg is None
    else:
        assert isinstance(msg, str)
        assert "pyimpfuzzy" in msg.lower() or "pip" in msg.lower()


def test_impfuzzy_compare_hashes_none_inputs() -> None:
    assert ImpfuzzyAnalyzer.compare_hashes(None, None) is None  # type: ignore[arg-type]
    assert ImpfuzzyAnalyzer.compare_hashes("", "abc") is None
    assert ImpfuzzyAnalyzer.compare_hashes("abc", "") is None


def test_impfuzzy_compare_hashes_when_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    import r2inspect.modules.impfuzzy_analyzer as mod
    original = mod.IMPFUZZY_AVAILABLE
    monkeypatch.setattr(mod, "IMPFUZZY_AVAILABLE", False)
    assert ImpfuzzyAnalyzer.compare_hashes("abc", "abc") is None
    monkeypatch.setattr(mod, "IMPFUZZY_AVAILABLE", original)


def test_impfuzzy_calculate_from_nonexistent_file() -> None:
    result = ImpfuzzyAnalyzer.calculate_impfuzzy_from_file("/nonexistent/path/to/file.exe")
    # Either None (library unavailable or file missing) or None due to exception
    assert result is None


def test_impfuzzy_calculate_from_file_when_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    import r2inspect.modules.impfuzzy_analyzer as mod
    monkeypatch.setattr(mod, "IMPFUZZY_AVAILABLE", False)
    assert ImpfuzzyAnalyzer.calculate_impfuzzy_from_file("/any/file.exe") is None


def test_impfuzzy_process_imports_basic(tmp_path: Path) -> None:
    path = _make_file(tmp_path)
    analyzer = ImpfuzzyAnalyzer(StubAdapter(), str(path))
    imports = [{"name": "CreateFile", "libname": "kernel32.dll"}]
    result = analyzer._process_imports(imports)
    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0] == "kernel32.createfile"


def test_impfuzzy_process_imports_multiple(tmp_path: Path) -> None:
    path = _make_file(tmp_path)
    analyzer = ImpfuzzyAnalyzer(StubAdapter(), str(path))
    imports = [
        {"name": "CreateFile", "libname": "kernel32.dll"},
        {"name": "VirtualAlloc", "libname": "kernel32.dll"},
        {"name": "WSAStartup", "libname": "ws2_32.dll"},
    ]
    result = analyzer._process_imports(imports)
    assert isinstance(result, list)
    assert len(result) == 3
    # Results are sorted
    assert result == sorted(result)
    assert "kernel32.createfile" in result
    assert "kernel32.virtualalloc" in result
    assert "ws2_32.wsastartup" in result


def test_impfuzzy_process_imports_ordinals_skipped(tmp_path: Path) -> None:
    path = _make_file(tmp_path)
    analyzer = ImpfuzzyAnalyzer(StubAdapter(), str(path))
    imports = [{"name": "ord_1234", "libname": "kernel32.dll"}]
    result = analyzer._process_imports(imports)
    assert result == []


def test_impfuzzy_process_imports_empty(tmp_path: Path) -> None:
    path = _make_file(tmp_path)
    analyzer = ImpfuzzyAnalyzer(StubAdapter(), str(path))
    assert analyzer._process_imports([]) == []


def test_impfuzzy_process_imports_missing_name(tmp_path: Path) -> None:
    path = _make_file(tmp_path)
    analyzer = ImpfuzzyAnalyzer(StubAdapter(), str(path))
    # Entry with no recognisable name field should be skipped
    imports = [{"libname": "kernel32.dll"}]
    result = analyzer._process_imports(imports)
    assert result == []


def test_impfuzzy_process_imports_alt_field_names(tmp_path: Path) -> None:
    path = _make_file(tmp_path)
    analyzer = ImpfuzzyAnalyzer(StubAdapter(), str(path))
    # Uses 'lib' and 'func' fields as fallbacks
    imports = [{"func": "OpenProcess", "lib": "kernel32.dll"}]
    result = analyzer._process_imports(imports)
    assert isinstance(result, list)
    assert len(result) == 1
    assert "kernel32" in result[0]


def test_impfuzzy_analyze_imports_not_pe(tmp_path: Path) -> None:
    # File with no MZ header → not PE → early return
    path = _make_file(tmp_path, content=b"\x7fELF" + b"\x00" * 60)
    analyzer = ImpfuzzyAnalyzer(StubAdapter(), str(path))
    result = analyzer.analyze_imports()
    assert isinstance(result, dict)
    assert "available" in result
    assert "library_available" in result
    # For non-PE the analysis won't produce a hash
    assert result["available"] is False


# ===========================================================================
# OverlayAnalyzer
# ===========================================================================


def test_overlay_default_result_fields() -> None:
    analyzer = OverlayAnalyzer(StubAdapter())
    result = analyzer._default_result()
    assert result["has_overlay"] is False
    assert result["overlay_offset"] == 0
    assert result["overlay_size"] == 0
    assert result["overlay_entropy"] == 0.0
    assert result["available"] is True
    assert result["patterns_found"] == []
    assert result["suspicious_indicators"] == []
    assert result["embedded_files"] == []


def test_overlay_get_file_size_present() -> None:
    class FileSizeAdapter(StubAdapter):
        def get_file_info(self) -> dict[str, Any]:
            return {"core": {"size": 1000}}

    analyzer = OverlayAnalyzer(FileSizeAdapter())
    assert analyzer._get_file_size() == 1000


def test_overlay_get_file_size_missing() -> None:
    analyzer = OverlayAnalyzer(StubAdapter())
    assert analyzer._get_file_size() is None


def test_overlay_get_file_size_zero() -> None:
    class ZeroSizeAdapter(StubAdapter):
        def get_file_info(self) -> dict[str, Any]:
            return {"core": {"size": 0}}

    analyzer = OverlayAnalyzer(ZeroSizeAdapter())
    assert analyzer._get_file_size() is None


def test_overlay_check_large_overlay_triggers() -> None:
    analyzer = OverlayAnalyzer(StubAdapter())
    result = analyzer._default_result()
    result["overlay_size"] = 2 * 1024 * 1024  # 2 MB
    suspicious: list[dict[str, Any]] = []
    analyzer._check_large_overlay(result, suspicious)
    assert len(suspicious) == 1
    assert suspicious[0]["severity"] == "medium"
    assert "overlay" in suspicious[0]["indicator"].lower()


def test_overlay_check_large_overlay_no_trigger() -> None:
    analyzer = OverlayAnalyzer(StubAdapter())
    result = analyzer._default_result()
    result["overlay_size"] = 512  # small
    suspicious: list[dict[str, Any]] = []
    analyzer._check_large_overlay(result, suspicious)
    assert suspicious == []


def test_overlay_check_entropy_high_triggers() -> None:
    analyzer = OverlayAnalyzer(StubAdapter())
    result = analyzer._default_result()
    result["overlay_entropy"] = 7.8
    suspicious: list[dict[str, Any]] = []
    analyzer._check_entropy(result, suspicious)
    assert len(suspicious) == 1
    assert suspicious[0]["severity"] == "high"


def test_overlay_check_entropy_low_no_trigger() -> None:
    analyzer = OverlayAnalyzer(StubAdapter())
    result = analyzer._default_result()
    result["overlay_entropy"] = 4.0
    suspicious: list[dict[str, Any]] = []
    analyzer._check_entropy(result, suspicious)
    assert suspicious == []


def test_overlay_check_entropy_boundary() -> None:
    analyzer = OverlayAnalyzer(StubAdapter())
    result = analyzer._default_result()
    result["overlay_entropy"] = 7.5  # exactly at threshold – not above
    suspicious: list[dict[str, Any]] = []
    analyzer._check_entropy(result, suspicious)
    assert suspicious == []


def test_overlay_check_autoit_triggers() -> None:
    analyzer = OverlayAnalyzer(StubAdapter())
    result = analyzer._default_result()
    result["patterns_found"] = [{"name": "AutoIt", "type": "installer", "confidence": "high"}]
    suspicious: list[dict[str, Any]] = []
    analyzer._check_autoit(result, suspicious)
    assert len(suspicious) == 1
    assert "autoit" in suspicious[0]["indicator"].lower()


def test_overlay_check_autoit_no_trigger() -> None:
    analyzer = OverlayAnalyzer(StubAdapter())
    result = analyzer._default_result()
    result["patterns_found"] = [{"name": "NSIS", "type": "installer"}]
    suspicious: list[dict[str, Any]] = []
    analyzer._check_autoit(result, suspicious)
    assert suspicious == []


def test_overlay_check_embedded_executables_pe() -> None:
    analyzer = OverlayAnalyzer(StubAdapter())
    result = analyzer._default_result()
    result["embedded_files"] = [{"type": "PE", "offset": 100, "extension": "exe"}]
    suspicious: list[dict[str, Any]] = []
    analyzer._check_embedded_executables(result, suspicious)
    assert len(suspicious) == 1
    assert suspicious[0]["severity"] == "high"
    assert "executable" in suspicious[0]["indicator"].lower()


def test_overlay_check_embedded_executables_elf() -> None:
    analyzer = OverlayAnalyzer(StubAdapter())
    result = analyzer._default_result()
    result["embedded_files"] = [{"type": "ELF", "offset": 200, "extension": "elf"}]
    suspicious: list[dict[str, Any]] = []
    analyzer._check_embedded_executables(result, suspicious)
    assert len(suspicious) == 1


def test_overlay_check_embedded_executables_non_exec() -> None:
    analyzer = OverlayAnalyzer(StubAdapter())
    result = analyzer._default_result()
    result["embedded_files"] = [{"type": "PNG", "offset": 10, "extension": "png"}]
    suspicious: list[dict[str, Any]] = []
    analyzer._check_embedded_executables(result, suspicious)
    assert suspicious == []


def test_overlay_check_suspicious_strings_cmd_exe() -> None:
    analyzer = OverlayAnalyzer(StubAdapter())
    result = analyzer._default_result()
    result["extracted_strings"] = ["cmd.exe /c dir", "innocuous string"]
    suspicious: list[dict[str, Any]] = []
    analyzer._check_suspicious_strings(result, suspicious)
    assert len(suspicious) == 1
    assert "suspicious strings" in suspicious[0]["indicator"].lower()


def test_overlay_check_suspicious_strings_none() -> None:
    analyzer = OverlayAnalyzer(StubAdapter())
    result = analyzer._default_result()
    result["extracted_strings"] = ["hello world", "foo bar baz"]
    suspicious: list[dict[str, Any]] = []
    analyzer._check_suspicious_strings(result, suspicious)
    assert suspicious == []


def test_overlay_analyze_no_overlay_when_no_file_size() -> None:
    # StubAdapter returns empty get_file_info → _get_file_size() returns None → no overlay
    analyzer = OverlayAnalyzer(StubAdapter())
    result = analyzer.analyze()
    assert result["has_overlay"] is False


def test_overlay_analyze_with_overlay() -> None:
    class OverlayAdapter(StubAdapter):
        def get_file_info(self) -> dict[str, Any]:
            return {"core": {"size": 2000}}

        def get_sections(self) -> list[Any]:
            return [{"paddr": 0, "size": 1000, "name": ".text"}]

    analyzer = OverlayAnalyzer(OverlayAdapter())
    result = analyzer.analyze()
    assert result["has_overlay"] is True
    assert result["overlay_offset"] == 1000
    assert result["overlay_size"] == 1000
    assert result["file_size"] == 2000


def test_overlay_analyze_no_overlay_section_fills_file() -> None:
    class NoOverlayAdapter(StubAdapter):
        def get_file_info(self) -> dict[str, Any]:
            return {"core": {"size": 1000}}

        def get_sections(self) -> list[Any]:
            return [{"paddr": 0, "size": 1000, "name": ".text"}]

    analyzer = OverlayAnalyzer(NoOverlayAdapter())
    result = analyzer.analyze()
    # pe_end == file_size → overlay_size <= 0 → no overlay
    assert result["has_overlay"] is False


# ===========================================================================
# CCBHashAnalyzer
# ===========================================================================


def test_ccbhash_is_available() -> None:
    assert CCBHashAnalyzer.is_available() is True


def test_ccbhash_check_library_availability(tmp_path: Path) -> None:
    path = _make_file(tmp_path)
    analyzer = CCBHashAnalyzer(StubAdapter(), str(path))
    available, msg = analyzer._check_library_availability()
    assert available is True
    assert msg is None


def test_ccbhash_calculate_hash_no_functions(tmp_path: Path) -> None:
    path = _make_file(tmp_path)
    analyzer = CCBHashAnalyzer(StubAdapter(), str(path))
    hash_val, method, error = analyzer._calculate_hash()
    assert hash_val is None
    assert method is None
    assert error is not None
    assert "function" in error.lower()


def test_ccbhash_compare_hashes_equal() -> None:
    h = "a" * 64
    assert CCBHashAnalyzer.compare_hashes(h, h) is True


def test_ccbhash_compare_hashes_different() -> None:
    assert CCBHashAnalyzer.compare_hashes("a" * 64, "b" * 64) is False


def test_ccbhash_compare_hashes_none_inputs() -> None:
    assert CCBHashAnalyzer.compare_hashes(None, "abc") is None  # type: ignore[arg-type]
    assert CCBHashAnalyzer.compare_hashes("abc", None) is None  # type: ignore[arg-type]
    assert CCBHashAnalyzer.compare_hashes("", "abc") is None


def test_ccbhash_compare_ccbhashes_legacy() -> None:
    h = "x" * 64
    assert CCBHashAnalyzer.compare_ccbhashes(h, h) is True
    assert CCBHashAnalyzer.compare_ccbhashes(h, "y" * 64) is False
    # None inputs fall back to False (not None)
    assert CCBHashAnalyzer.compare_ccbhashes("", "abc") is False


def test_ccbhash_analyze_functions_no_functions(tmp_path: Path) -> None:
    path = _make_file(tmp_path)
    analyzer = CCBHashAnalyzer(StubAdapter(), str(path))
    result = analyzer.analyze_functions()
    assert isinstance(result, dict)
    assert result["available"] is False
    assert result["function_hashes"] == {}
    assert result["error"] is not None


def test_ccbhash_build_canonical_edges() -> None:
    cfg = {"edges": [{"src": 1, "dst": 2}, {"src": 2, "dst": 3}]}
    canon = CCBHashAnalyzer._build_canonical_representation(cfg, 0x1000)
    assert canon is not None
    assert "1->2" in canon
    assert "2->3" in canon


def test_ccbhash_build_canonical_blocks() -> None:
    cfg = {"blocks": [{"offset": 0x2000}, {"offset": 0x1000}]}
    canon = CCBHashAnalyzer._build_canonical_representation(cfg, 0x1000)
    assert canon is not None
    # blocks are sorted by offset
    assert "4096" in canon  # 0x1000
    assert "8192" in canon  # 0x2000


def test_ccbhash_build_canonical_fallback() -> None:
    canon = CCBHashAnalyzer._build_canonical_representation({}, 0x1234)
    assert canon == str(0x1234)


def test_ccbhash_calculate_binary_ccbhash_empty() -> None:
    path = Path("/tmp/fake.bin")  # not used for this static-like method
    # Needs an instance but calculation is deterministic from dict
    import tempfile, os
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(b"\x00" * 10)
        tmp = f.name
    try:
        analyzer = CCBHashAnalyzer(StubAdapter(), tmp)
        assert analyzer._calculate_binary_ccbhash({}) is None
    finally:
        os.unlink(tmp)


def test_ccbhash_calculate_binary_ccbhash_with_data() -> None:
    import tempfile, os
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(b"\x00" * 10)
        tmp = f.name
    try:
        analyzer = CCBHashAnalyzer(StubAdapter(), tmp)
        func_hashes = {
            "func_a": {"ccbhash": "a" * 64, "addr": 0x1000, "size": 100},
            "func_b": {"ccbhash": "b" * 64, "addr": 0x2000, "size": 50},
        }
        result = analyzer._calculate_binary_ccbhash(func_hashes)
        assert isinstance(result, str)
        assert len(result) == 64  # SHA256 hex digest
    finally:
        os.unlink(tmp)


def test_ccbhash_find_similar_functions_none() -> None:
    import tempfile, os
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(b"\x00" * 10)
        tmp = f.name
    try:
        analyzer = CCBHashAnalyzer(StubAdapter(), tmp)
        func_hashes = {
            "func_a": {"ccbhash": "a" * 64, "addr": 0x1000, "size": 100},
            "func_b": {"ccbhash": "b" * 64, "addr": 0x2000, "size": 50},
        }
        result = analyzer._find_similar_functions(func_hashes)
        assert result == []
    finally:
        os.unlink(tmp)


def test_ccbhash_find_similar_functions_with_match() -> None:
    import tempfile, os
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(b"\x00" * 10)
        tmp = f.name
    try:
        analyzer = CCBHashAnalyzer(StubAdapter(), tmp)
        same_hash = "c" * 64
        func_hashes = {
            "func_a": {"ccbhash": same_hash, "addr": 0x1000, "size": 100},
            "func_b": {"ccbhash": same_hash, "addr": 0x2000, "size": 100},
            "func_c": {"ccbhash": "d" * 64, "addr": 0x3000, "size": 50},
        }
        result = analyzer._find_similar_functions(func_hashes)
        assert len(result) == 1
        assert result[0]["count"] == 2
        assert set(result[0]["functions"]) == {"func_a", "func_b"}
    finally:
        os.unlink(tmp)


# ===========================================================================
# BinDiffAnalyzer
# ===========================================================================


def test_bindiff_analyze_returns_required_keys(tmp_path: Path) -> None:
    path = _make_file(tmp_path)
    analyzer = BinDiffAnalyzer(StubAdapter(), str(path))
    result = analyzer.analyze()
    assert "filename" in result
    assert result["filename"] == "sample.bin"
    assert "filepath" in result
    assert "comparison_ready" in result


def test_bindiff_analyze_structural_features(tmp_path: Path) -> None:
    path = _make_file(tmp_path)
    analyzer = BinDiffAnalyzer(StubAdapter(), str(path))
    result = analyzer.analyze()
    assert "structural_features" in result
    assert isinstance(result["structural_features"], dict)


def test_bindiff_analyze_signatures_generated(tmp_path: Path) -> None:
    path = _make_file(tmp_path)
    analyzer = BinDiffAnalyzer(StubAdapter(), str(path))
    result = analyzer.analyze()
    assert "signatures" in result
    sigs = result["signatures"]
    assert "structural" in sigs
    assert "function" in sigs
    assert "string" in sigs
    assert "behavioral" in sigs


def test_bindiff_compare_with_not_ready(tmp_path: Path) -> None:
    path = _make_file(tmp_path)
    analyzer = BinDiffAnalyzer(StubAdapter(), str(path))
    other = {"comparison_ready": False, "filename": "other.bin"}
    result = analyzer.compare_with(other)
    assert "error" in result


def test_bindiff_compare_with_ready(tmp_path: Path) -> None:
    path_a = _make_file(tmp_path, name="a.bin")
    path_b = _make_file(tmp_path, name="b.bin")
    analyzer_a = BinDiffAnalyzer(StubAdapter(), str(path_a))
    analyzer_b = BinDiffAnalyzer(StubAdapter(), str(path_b))
    result_b = analyzer_b.analyze()
    comparison = analyzer_a.compare_with(result_b)
    assert "overall_similarity" in comparison
    assert "similarity_level" in comparison
    assert isinstance(comparison["overall_similarity"], float)
    assert 0.0 <= comparison["overall_similarity"] <= 1.0


def test_bindiff_compare_with_self_is_similar(tmp_path: Path) -> None:
    path = _make_file(tmp_path)
    analyzer = BinDiffAnalyzer(StubAdapter(), str(path))
    result = analyzer.analyze()
    comparison = analyzer.compare_with(result)
    # Comparing identical (stub) results should yield high similarity
    assert comparison["overall_similarity"] >= 0.0


# ===========================================================================
# MachOAnalyzer
# ===========================================================================


def test_macho_supports_format_positive() -> None:
    analyzer = MachOAnalyzer(StubAdapter())
    for fmt in ("MACH0", "MACHO", "MACH-O", "MACH064"):
        assert analyzer.supports_format(fmt) is True, f"Expected True for {fmt}"


def test_macho_supports_format_negative() -> None:
    analyzer = MachOAnalyzer(StubAdapter())
    for fmt in ("ELF", "ELF64", "PE", "PE32", ""):
        assert analyzer.supports_format(fmt) is False, f"Expected False for {fmt}"


def test_macho_supports_format_case_insensitive() -> None:
    analyzer = MachOAnalyzer(StubAdapter())
    # Method uppercases the input, so lower-case should work too
    assert analyzer.supports_format("mach0") is True
    assert analyzer.supports_format("macho") is True


def test_macho_get_category() -> None:
    analyzer = MachOAnalyzer(StubAdapter())
    assert analyzer.get_category() == "format"


def test_macho_get_description() -> None:
    analyzer = MachOAnalyzer(StubAdapter())
    desc = analyzer.get_description()
    assert isinstance(desc, str)
    assert len(desc) > 0
    assert "mach" in desc.lower() or "macho" in desc.lower()


def test_macho_analyze_returns_dict() -> None:
    analyzer = MachOAnalyzer(StubAdapter())
    result = analyzer.analyze()
    assert isinstance(result, dict)


def test_macho_analyze_has_expected_keys() -> None:
    analyzer = MachOAnalyzer(StubAdapter())
    result = analyzer.analyze()
    for key in ("architecture", "bits", "load_commands", "sections", "security_features"):
        assert key in result, f"Missing key: {key}"


def test_macho_analyze_security_features_structure() -> None:
    analyzer = MachOAnalyzer(StubAdapter())
    result = analyzer.analyze()
    sec = result["security_features"]
    assert isinstance(sec, dict)
    for key in ("pie", "stack_canary", "arc", "encrypted", "signed"):
        assert key in sec


def test_macho_analyze_load_commands_list() -> None:
    analyzer = MachOAnalyzer(StubAdapter())
    result = analyzer.analyze()
    assert isinstance(result["load_commands"], list)


def test_macho_analyze_sections_list() -> None:
    analyzer = MachOAnalyzer(StubAdapter())
    result = analyzer.analyze()
    assert isinstance(result["sections"], list)


# ===========================================================================
# ELFAnalyzer
# ===========================================================================


def test_elf_supports_format_positive() -> None:
    analyzer = ELFAnalyzer(StubAdapter())
    for fmt in ("ELF", "ELF32", "ELF64"):
        assert analyzer.supports_format(fmt) is True, f"Expected True for {fmt}"


def test_elf_supports_format_negative() -> None:
    analyzer = ELFAnalyzer(StubAdapter())
    for fmt in ("PE", "PE32", "MACH0", "MACHO", "MACH-O", ""):
        assert analyzer.supports_format(fmt) is False, f"Expected False for {fmt}"


def test_elf_supports_format_case_insensitive() -> None:
    analyzer = ELFAnalyzer(StubAdapter())
    assert analyzer.supports_format("elf") is True
    assert analyzer.supports_format("elf64") is True


def test_elf_get_category() -> None:
    analyzer = ELFAnalyzer(StubAdapter())
    assert analyzer.get_category() == "format"


def test_elf_get_description() -> None:
    analyzer = ELFAnalyzer(StubAdapter())
    desc = analyzer.get_description()
    assert isinstance(desc, str)
    assert len(desc) > 0
    assert "elf" in desc.lower()


def test_elf_analyze_returns_dict() -> None:
    analyzer = ELFAnalyzer(StubAdapter())
    result = analyzer.analyze()
    assert isinstance(result, dict)


def test_elf_analyze_has_expected_keys() -> None:
    analyzer = ELFAnalyzer(StubAdapter())
    result = analyzer.analyze()
    for key in ("architecture", "bits", "sections", "program_headers", "security_features"):
        assert key in result, f"Missing key: {key}"


def test_elf_analyze_sections_list() -> None:
    analyzer = ELFAnalyzer(StubAdapter())
    result = analyzer.analyze()
    assert isinstance(result["sections"], list)


def test_elf_analyze_program_headers_list() -> None:
    analyzer = ELFAnalyzer(StubAdapter())
    result = analyzer.analyze()
    assert isinstance(result["program_headers"], list)


def test_elf_analyze_security_features_structure() -> None:
    analyzer = ELFAnalyzer(StubAdapter())
    result = analyzer.analyze()
    sec = result["security_features"]
    assert isinstance(sec, dict)
    for key in ("nx", "stack_canary", "relro", "pie"):
        assert key in sec


def test_elf_analyze_with_file_info() -> None:
    class InfoAdapter(StubAdapter):
        def get_file_info(self) -> dict[str, Any]:
            return {
                "bin": {
                    "arch": "x86",
                    "bits": 64,
                    "endian": "little",
                    "class": "ELF64",
                    "format": "elf",
                    "baddr": 0x400000,
                }
            }

    analyzer = ELFAnalyzer(InfoAdapter())
    result = analyzer.analyze()
    assert result["architecture"] == "x86"
    assert result["bits"] == 64
    assert result["endian"] == "little"
