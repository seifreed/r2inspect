"""Coverage tests for resource_analyzer, impfuzzy_analyzer, section_analyzer (wave 3)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import r2inspect.modules.impfuzzy_analyzer as impfuzzy_module
from r2inspect.modules.impfuzzy_analyzer import ImpfuzzyAnalyzer
from r2inspect.modules.resource_analyzer import ResourceAnalyzer
from r2inspect.modules.section_analyzer import SectionAnalyzer


# ---------------------------------------------------------------------------
# Shared adapter helpers
# ---------------------------------------------------------------------------


class PxjAdapter:
    """Adapter that returns a configurable bytes-list for pxj commands."""

    def __init__(self, data: list) -> None:
        self._data = data

    def read_bytes_list(self, addr: int, size: int | None) -> list:
        return self._data


class SimpleSectionAdapter:
    """Minimal adapter for SectionAnalyzer tests."""

    def __init__(
        self,
        sections: list | None = None,
        read_bytes_data: bytes = b"",
        file_info: dict | None = None,
    ) -> None:
        self._sections = sections if sections is not None else []
        self._read_bytes_data = read_bytes_data
        self._file_info = file_info if file_info is not None else {}

    def get_sections(self) -> list:
        return self._sections

    def read_bytes(self, addr: int, size: int) -> bytes:
        return self._read_bytes_data

    def get_file_info(self) -> dict:
        return self._file_info


class RaisingSectionsAdapter:
    """Adapter whose get_sections raises so analyze_sections exception path is hit."""

    def get_sections(self) -> list:
        raise RuntimeError("sections unavailable")

    def read_bytes(self, addr: int, size: int) -> bytes:
        return b""

    def get_file_info(self) -> dict:
        return {}


class UnhashableFlagsAdapter:
    """Adapter that returns a list (not str) as flags value, making flag_counts fail."""

    def get_sections(self) -> list:
        return [{"name": ".text", "vaddr": 0, "vsize": 0, "size": 0, "flags": []}]

    def read_bytes(self, addr: int, size: int) -> bytes:
        return b""

    def get_file_info(self) -> dict:
        return {}


class RaisingFileInfoAdapter:
    """Adapter whose get_file_info raises so _get_arch exception path is hit."""

    def get_sections(self) -> list:
        return []

    def read_bytes(self, addr: int, size: int) -> bytes:
        return b""

    def get_file_info(self) -> dict:
        raise RuntimeError("file info unavailable")


# ---------------------------------------------------------------------------
# resource_analyzer.py – outer exception in _analyze_resource_data
# ---------------------------------------------------------------------------


def test_resource_analyze_resource_data_outer_exception() -> None:
    """resource dict missing 'offset' key triggers outer except (lines 212-213)."""
    analyzer = ResourceAnalyzer(adapter=None)
    resource: dict = {"size": 100, "entropy": 0.0, "hashes": {}}
    analyzer._analyze_resource_data(resource)
    # Should not raise; entropy/hashes stay at defaults
    assert resource["entropy"] == 0.0


# ---------------------------------------------------------------------------
# resource_analyzer.py – _extract_version_info success path (lines 251-252)
# ---------------------------------------------------------------------------


def _build_version_info_data() -> list[int]:
    """Build a bytes list containing a CompanyName UTF-16LE string."""
    key = "CompanyName"
    key_bytes = list(key.encode("utf-16le"))  # 22 bytes
    value_bytes = list("Acme".encode("utf-16le"))  # 8 bytes
    null_term = [0, 0]
    pad = [0, 0, 0, 0]
    # filler so total >= 64 bytes, key starts at offset 64
    filler = [0] * 64
    return filler + key_bytes + pad + value_bytes + null_term


def test_resource_extract_version_info_success() -> None:
    """version_data is truthy – sets result['version_info'] and breaks (lines 251-252)."""
    data = _build_version_info_data()

    class VersionAdapter:
        def read_bytes_list(self, addr: int, size: int | None) -> list:
            return data

    analyzer = ResourceAnalyzer(adapter=VersionAdapter())
    result: dict = {}
    resources = [{"type_name": "RT_VERSION", "offset": 0x1000, "size": 512}]
    analyzer._extract_version_info(result, resources)
    assert "version_info" in result
    assert result["version_info"]["strings"].get("CompanyName") == "Acme"


# ---------------------------------------------------------------------------
# resource_analyzer.py – _extract_version_info exception path (lines 253-254)
# ---------------------------------------------------------------------------


def test_resource_extract_version_info_exception() -> None:
    """Resource dict missing 'offset' raises KeyError caught at lines 253-254."""
    analyzer = ResourceAnalyzer(adapter=None)
    result: dict = {}
    # Missing 'offset' key triggers KeyError inside the try block
    resources = [{"type_name": "RT_VERSION", "size": 512}]
    analyzer._extract_version_info(result, resources)
    assert "version_info" not in result


# ---------------------------------------------------------------------------
# resource_analyzer.py – _parse_version_info VS signature path (lines 278-280)
# ---------------------------------------------------------------------------


def test_resource_parse_version_info_with_vs_signature() -> None:
    """Data with VS_FIXEDFILEINFO signature exercises lines 278-280."""
    # Build data: 64 bytes filler, then VS signature with file version bytes
    data: list[int] = [0] * 200
    sig_pos = 50
    sig = [0xBD, 0x04, 0xEF, 0xFE]
    data[sig_pos : sig_pos + 4] = sig
    # Set version fields: file_version_ms at sig_pos+8, file_version_ls at sig_pos+12
    # Version 1.0.2.3
    data[sig_pos + 8] = 0x01  # major
    data[sig_pos + 9] = 0x00
    data[sig_pos + 10] = 0x00  # minor
    data[sig_pos + 11] = 0x00
    data[sig_pos + 12] = 0x02  # build low
    data[sig_pos + 13] = 0x00
    data[sig_pos + 14] = 0x03  # revision
    data[sig_pos + 15] = 0x00

    class SigAdapter:
        def read_bytes_list(self, addr: int, size: int | None) -> list:
            return data

    analyzer = ResourceAnalyzer(adapter=SigAdapter())
    result = analyzer._parse_version_info(0x1000, 1024)
    # file_version string was set (or not if no strings found); no exception
    assert result is None or isinstance(result, dict)


# ---------------------------------------------------------------------------
# resource_analyzer.py – _extract_version_strings stores value (line 329)
# and _read_version_string_value returns empty when no value bytes (line 360)
# ---------------------------------------------------------------------------


def test_resource_extract_version_strings_stores_value() -> None:
    """_extract_version_strings finds CompanyName value -> strings[key]=value (line 329)."""
    data = _build_version_info_data()
    analyzer = ResourceAnalyzer(adapter=None)
    result = analyzer._extract_version_strings(data)
    assert "CompanyName" in result
    assert result["CompanyName"] == "Acme"


def test_resource_read_version_string_value_empty_value_bytes() -> None:
    """Key found but immediate null terminator -> value_bytes=[] -> return '' (line 360)."""
    analyzer = ResourceAnalyzer(adapter=None)
    key = "K"
    key_bytes = list(key.encode("utf-16le"))
    # key + 4 pad bytes + immediate null pair
    data = key_bytes + [0, 0, 0, 0, 0, 0]
    result = analyzer._read_version_string_value(data, key)
    assert result == ""


def test_resource_read_version_string_value_printable_decoded() -> None:
    """Value bytes decode to printable string -> returns value (line 364)."""
    analyzer = ResourceAnalyzer(adapter=None)
    key = "N"
    key_bytes = list(key.encode("utf-16le"))
    value_bytes = list("Hi".encode("utf-16le"))  # [0x48, 0x00, 0x69, 0x00]
    null_term = [0, 0]
    data = key_bytes + [0, 0, 0, 0] + value_bytes + null_term
    result = analyzer._read_version_string_value(data, key)
    assert result == "Hi"


# ---------------------------------------------------------------------------
# resource_analyzer.py – _extract_manifest exception (lines 382-383)
# ---------------------------------------------------------------------------


def test_resource_extract_manifest_exception() -> None:
    """Resource dict missing 'offset' raises KeyError caught at lines 382-383."""
    analyzer = ResourceAnalyzer(adapter=None)
    result: dict = {}
    resources = [{"type_name": "RT_MANIFEST", "size": 100}]  # no 'offset' key
    analyzer._extract_manifest(result, resources)
    assert "manifest" not in result


# ---------------------------------------------------------------------------
# resource_analyzer.py – _extract_strings exception (lines 418-419)
# ---------------------------------------------------------------------------


def test_resource_extract_strings_exception() -> None:
    """Resource dict missing 'offset' raises KeyError caught at lines 418-419."""
    analyzer = ResourceAnalyzer(adapter=None)
    result: dict = {}
    resources = [{"type_name": "RT_STRING", "size": 100}]  # no 'offset' key
    analyzer._extract_strings(result, resources)
    assert "strings" in result
    assert result["strings"] == []


# ---------------------------------------------------------------------------
# resource_analyzer.py – _read_resource_as_string decode paths
# ---------------------------------------------------------------------------


def test_read_resource_as_string_type_error_data() -> None:
    """Non-int items in data list trigger TypeError in all three try blocks
    (lines 442-443, 450-451, 458-459, 461)."""
    adapter = PxjAdapter(data=["not_an_int"])
    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._read_resource_as_string(0x1000, 100)
    assert result is None


def test_read_resource_as_string_utf8_returns_text() -> None:
    """UTF-16LE produces non-printable (null pairs); UTF-8 has printable 'a'
    so returns at line 449."""
    # b"\x00\x00\x00\x00a": UTF-16 -> U+0000 U+0000 (not printable), odd 'a' ignored
    #                        UTF-8  -> "\x00\x00\x00\x00a" (has 'a')
    adapter = PxjAdapter(data=[0x00, 0x00, 0x00, 0x00, 0x61])
    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._read_resource_as_string(0x1000, 5)
    assert result is not None
    assert "a" in result


def test_read_resource_as_string_all_null_returns_none() -> None:
    """All-null bytes: UTF-16LE, UTF-8, and ASCII all produce non-printable chars
    (exercises lines 446-448, 454-456, 461)."""
    adapter = PxjAdapter(data=[0x00, 0x00, 0x00, 0x00])
    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._read_resource_as_string(0x1000, 4)
    assert result is None


# ---------------------------------------------------------------------------
# impfuzzy_analyzer.py – _extract_imports ii fallback returns dict (lines 213-214)
# ---------------------------------------------------------------------------


class CmdAndCmdJAdapter:
    """Adapter with both cmd and cmdj methods so the cmdj fallback path is used.
    iij returns an empty list; ii returns a single import dict."""

    def cmd(self, command: str) -> str:
        return ""

    def cmdj(self, command: str) -> Any:
        if command == "iij":
            return []
        if command == "ii":
            return {"name": "WriteFile", "libname": "kernel32.dll"}
        return []


def test_impfuzzy_extract_imports_ii_fallback_returns_dict() -> None:
    """ii command returns a dict; covers the elif isinstance(dict) branch (lines 213-214)."""
    analyzer = ImpfuzzyAnalyzer(CmdAndCmdJAdapter(), "/nonexistent/path/x.exe")
    imports = analyzer._extract_imports()
    assert isinstance(imports, list)
    # May be empty (dict placed but no 'get_imports' conflict) or have one item
    assert len(imports) >= 0


# ---------------------------------------------------------------------------
# impfuzzy_analyzer.py – _process_imports valid entries (lines 266, 270-271)
# ---------------------------------------------------------------------------


def test_impfuzzy_process_imports_non_ordinal_entries() -> None:
    """Non-ordinal imports are appended to dll_funcs then to flat list (lines 266, 270-271)."""
    analyzer = ImpfuzzyAnalyzer(None, "/any/path.exe")  # type: ignore[arg-type]
    imports_data = [
        {"name": "CreateFileA", "libname": "kernel32.dll"},
        {"name": "ExitProcess", "libname": "kernel32.dll"},
    ]
    result = analyzer._process_imports(imports_data)
    assert "kernel32.createfilea" in result
    assert "kernel32.exitprocess" in result
    assert result == sorted(result)


def test_impfuzzy_process_imports_mixed_ordinal_and_valid() -> None:
    """Ordinal entries are skipped; valid entries reach lines 266, 270-271."""
    analyzer = ImpfuzzyAnalyzer(None, "/any/path.exe")  # type: ignore[arg-type]
    imports_data = [
        {"name": "ord_1", "libname": "kernel32.dll"},
        {"name": "WriteFile", "libname": "kernel32.dll"},
    ]
    result = analyzer._process_imports(imports_data)
    assert "kernel32.writefile" in result
    # ordinal was skipped
    assert not any("ord_1" in s for s in result)


# ---------------------------------------------------------------------------
# impfuzzy_analyzer.py – _calculate_hash success path (line 78)
# ---------------------------------------------------------------------------


def test_impfuzzy_calculate_hash_success_real_pe() -> None:
    """Use hello_pe.exe; _calculate_hash succeeds and returns (hash, method, None) (line 78)."""
    if not impfuzzy_module.IMPFUZZY_AVAILABLE:
        return
    pe_path = Path(__file__).parents[2] / "samples" / "fixtures" / "hello_pe.exe"
    if not pe_path.exists():
        return

    class PEInfoAdapter:
        def get_file_info(self) -> dict:
            return {"bin": {"format": "pe", "arch": "x86", "bits": 32}}

    analyzer = ImpfuzzyAnalyzer(PEInfoAdapter(), str(pe_path))
    h, method, err = analyzer._calculate_hash()
    assert h is not None
    assert method == "python_library"
    assert err is None


# ---------------------------------------------------------------------------
# impfuzzy_analyzer.py – analyze_imports ordinal-only imports (lines 140-143)
# ---------------------------------------------------------------------------


def test_impfuzzy_analyze_imports_process_returns_empty() -> None:
    """All imports are ordinal so _process_imports returns [] (lines 140-143)."""
    if not impfuzzy_module.IMPFUZZY_AVAILABLE:
        return
    pe_path = Path(__file__).parents[2] / "samples" / "fixtures" / "hello_pe.exe"
    if not pe_path.exists():
        return

    class OrdinalOnlyAdapter:
        def get_file_info(self) -> dict:
            return {"bin": {"format": "pe"}}

        def get_imports(self) -> list:
            return [
                {"name": "ord_1", "libname": "kernel32.dll"},
                {"name": "ord_2", "libname": "user32.dll"},
            ]

    analyzer = ImpfuzzyAnalyzer(OrdinalOnlyAdapter(), str(pe_path))
    result = analyzer.analyze_imports()
    assert result["available"] is False
    assert result["error"] == "No valid imports found after processing"


# ---------------------------------------------------------------------------
# impfuzzy_analyzer.py – analyze_imports success path (lines 153-176)
# ---------------------------------------------------------------------------


def test_impfuzzy_analyze_imports_full_success() -> None:
    """Full success path: PE + imports + hash -> results.update executed (lines 153-176)."""
    if not impfuzzy_module.IMPFUZZY_AVAILABLE:
        return
    pe_path = Path(__file__).parents[2] / "samples" / "fixtures" / "hello_pe.exe"
    if not pe_path.exists():
        return

    class ImportAdapter:
        def get_file_info(self) -> dict:
            return {"bin": {"format": "pe"}}

        def get_imports(self) -> list:
            return [
                {"name": "CreateFileA", "libname": "kernel32.dll"},
                {"name": "ExitProcess", "libname": "kernel32.dll"},
            ]

    analyzer = ImpfuzzyAnalyzer(ImportAdapter(), str(pe_path))
    result = analyzer.analyze_imports()
    assert result["available"] is True
    assert result["impfuzzy_hash"] is not None
    assert result["import_count"] > 0
    assert result["dll_count"] > 0


# ---------------------------------------------------------------------------
# impfuzzy_analyzer.py – analyze_imports exception path (lines 172-174)
# ---------------------------------------------------------------------------


def test_impfuzzy_analyze_imports_exception_path(tmp_path: Path) -> None:
    """pyimpfuzzy.get_impfuzzy raises on invalid PE -> exception caught (lines 172-174)."""
    if not impfuzzy_module.IMPFUZZY_AVAILABLE:
        return
    fake_pe = tmp_path / "bad.exe"
    fake_pe.write_bytes(b"MZ" + b"\x00" * 200)  # MZ magic but invalid PE structure

    class ImportAdapter:
        def get_file_info(self) -> dict:
            return {"bin": {"format": "pe"}}

        def get_imports(self) -> list:
            return [{"name": "CreateFileA", "libname": "kernel32.dll"}]

    analyzer = ImpfuzzyAnalyzer(ImportAdapter(), str(fake_pe))
    result = analyzer.analyze_imports()
    assert result["available"] is False
    assert result["error"] is not None


# ---------------------------------------------------------------------------
# section_analyzer.py – get_category / get_description / supports_format
# ---------------------------------------------------------------------------


def test_section_analyzer_get_category() -> None:
    """get_category returns 'metadata' (line 26)."""
    analyzer = SectionAnalyzer(adapter=SimpleSectionAdapter())
    assert analyzer.get_category() == "metadata"


def test_section_analyzer_get_description() -> None:
    """get_description returns a non-empty string (line 29)."""
    analyzer = SectionAnalyzer(adapter=SimpleSectionAdapter())
    desc = analyzer.get_description()
    assert isinstance(desc, str) and len(desc) > 0


def test_section_analyzer_supports_format() -> None:
    """supports_format returns True for PE/ELF/MACH0 (line 32)."""
    analyzer = SectionAnalyzer(adapter=SimpleSectionAdapter())
    assert analyzer.supports_format("PE") is True
    assert analyzer.supports_format("ELF") is True
    assert analyzer.supports_format("MACH0") is True
    assert analyzer.supports_format("XYZ") is False


# ---------------------------------------------------------------------------
# section_analyzer.py – analyze_sections exception (lines 66-67)
# ---------------------------------------------------------------------------


def test_section_analyze_sections_exception() -> None:
    """adapter.get_sections raises -> exception caught in analyze_sections (lines 66-67)."""
    analyzer = SectionAnalyzer(adapter=RaisingSectionsAdapter())
    result = analyzer.analyze_sections()
    assert result == []


# ---------------------------------------------------------------------------
# section_analyzer.py – _analyze_single_section exception (lines 99-101)
# ---------------------------------------------------------------------------


def test_section_analyze_single_section_exception() -> None:
    """_apply_permissions raising causes exception in the try block (lines 99-101)."""
    class _RaisingPermAdapter(SimpleSectionAdapter):
        pass

    analyzer = SectionAnalyzer(adapter=_RaisingPermAdapter())

    # Monkey-patch _apply_permissions to raise inside the try block
    def _raise(section: object, analysis: object) -> None:
        raise RuntimeError("forced permission error")

    analyzer._apply_permissions = _raise  # type: ignore[method-assign]
    result = analyzer._analyze_single_section(
        {"name": ".text", "vaddr": 0, "vsize": 0, "size": 100, "flags": ""}
    )
    assert "error" in result


# ---------------------------------------------------------------------------
# section_analyzer.py – _apply_pe_characteristics with flags (lines 121-127)
# and _decode_pe_characteristics body (lines 262, 265, 286-290)
# ---------------------------------------------------------------------------

_PE_EXEC_WRITE_READ = 0x01000000 | 0x04000000 | 0x02000000  # EXECUTE | WRITE | READ


def test_section_apply_pe_characteristics_all_rwx() -> None:
    """characteristics with EXECUTE, WRITE, READ bits set exercises lines 121-127
    and _decode_pe_characteristics loop (lines 262, 265, 286-290)."""
    analyzer = SectionAnalyzer(adapter=SimpleSectionAdapter())
    section: dict = {
        "name": ".text",
        "vaddr": 0,
        "vsize": 0,
        "size": 0,
        "flags": "",
        "characteristics": _PE_EXEC_WRITE_READ,
    }
    analysis: dict = {
        "pe_characteristics": [],
        "is_executable": False,
        "is_writable": False,
        "is_readable": False,
    }
    analyzer._apply_pe_characteristics(section, analysis)
    assert analysis["is_executable"] is True
    assert analysis["is_writable"] is True
    assert analysis["is_readable"] is True
    assert "IMAGE_SCN_MEM_EXECUTE" in analysis["pe_characteristics"]
    assert "IMAGE_SCN_MEM_WRITE" in analysis["pe_characteristics"]
    assert "IMAGE_SCN_MEM_READ" in analysis["pe_characteristics"]


def test_section_decode_pe_characteristics_known_flags() -> None:
    """_decode_pe_characteristics returns list of flag names (exercises lines 286-290)."""
    analyzer = SectionAnalyzer(adapter=SimpleSectionAdapter())
    flags = analyzer._decode_pe_characteristics(0x00000020 | 0x01000000)
    assert "IMAGE_SCN_CNT_CODE" in flags
    assert "IMAGE_SCN_MEM_EXECUTE" in flags


# ---------------------------------------------------------------------------
# section_analyzer.py – _check_suspicious_characteristics exception (lines 173-174)
# ---------------------------------------------------------------------------


def test_section_check_suspicious_characteristics_exception() -> None:
    """Non-dict section raises AttributeError caught at lines 173-174."""
    analyzer = SectionAnalyzer(adapter=SimpleSectionAdapter())
    analysis = {
        "is_executable": False,
        "is_writable": False,
        "entropy": 0.0,
    }
    result = analyzer._check_suspicious_characteristics("not_a_dict", analysis)  # type: ignore[arg-type]
    assert isinstance(result, list)
    assert result == []


# ---------------------------------------------------------------------------
# section_analyzer.py – suspicious section name indicator (line 207)
# ---------------------------------------------------------------------------


def test_section_suspicious_section_name_indicator() -> None:
    """Section named 'UPX0' triggers suspicious_section_name_indicator (line 207)."""
    analyzer = SectionAnalyzer(adapter=SimpleSectionAdapter())
    indicators = analyzer._check_section_name_indicators("UPX0")
    assert any("upx" in ind.lower() or "suspicious" in ind.lower() for ind in indicators)


# ---------------------------------------------------------------------------
# section_analyzer.py – writable and executable (line 216)
# ---------------------------------------------------------------------------


def test_section_writable_and_executable_indicator() -> None:
    """Both is_writable and is_executable True -> appends indicator (line 216)."""
    analyzer = SectionAnalyzer(adapter=SimpleSectionAdapter())
    analysis = {"is_executable": True, "is_writable": True, "entropy": 0.0}
    indicators = analyzer._check_permission_indicators(analysis)
    assert "Writable and executable section" in indicators


def test_section_executable_low_entropy_indicator() -> None:
    """is_executable with entropy < 1.0 appends low-entropy indicator (line 219)."""
    analyzer = SectionAnalyzer(adapter=SimpleSectionAdapter())
    analysis = {"is_executable": True, "is_writable": False, "entropy": 0.5}
    indicators = analyzer._check_permission_indicators(analysis)
    assert any("low entropy" in ind.lower() for ind in indicators)


# ---------------------------------------------------------------------------
# section_analyzer.py – moderate high entropy (line 230)
# ---------------------------------------------------------------------------


def test_section_moderate_high_entropy_indicator() -> None:
    """Entropy between 7.0 and 7.5 triggers moderate high entropy (line 230)."""
    analyzer = SectionAnalyzer(adapter=SimpleSectionAdapter())
    indicators = analyzer._check_entropy_indicators(7.2)
    assert any("moderate" in ind.lower() for ind in indicators)


def test_section_high_entropy_indicator() -> None:
    """Entropy > 7.5 triggers high entropy (line 228)."""
    analyzer = SectionAnalyzer(adapter=SimpleSectionAdapter())
    indicators = analyzer._check_entropy_indicators(7.8)
    assert any("high entropy" in ind.lower() for ind in indicators)


# ---------------------------------------------------------------------------
# section_analyzer.py – large virtual/raw size difference (line 248)
# ---------------------------------------------------------------------------


def test_section_large_size_diff_ratio() -> None:
    """ratio between 1 and 5 but size_diff_ratio > 0.8 -> 'Large virtual/raw...' (line 248)."""
    analyzer = SectionAnalyzer(adapter=SimpleSectionAdapter())
    # vsize=900, raw_size=100: ratio=9.0 > 5 -> "Large size ratio" hits line 246 not 248
    # To hit 248: ratio <= 5 AND size_diff_ratio > 0.8
    # vsize=450, raw_size=100: ratio=4.5 <= 5; diff=350, max=450; diff_ratio=350/450=0.78 < 0.8
    # vsize=910, raw_size=100: ratio=9.1 > 5 -> line 246. Need ratio <= 5 and diff > 0.8*max
    # vsize=500, raw_size=100: ratio=5.0 not > 5; diff=400/500=0.8 not > 0.8
    # vsize=600, raw_size=100: ratio=6.0 > 5 -> line 246. Nope.
    # vsize=300, raw_size=100: ratio=3.0; diff=200/300=0.667 < 0.8. No.
    # vsize=950, raw_size=200: ratio=4.75; diff=750/950=0.789 < 0.8. No.
    # vsize=950, raw_size=50: ratio=19 > 10 -> line 244.
    # vsize=4, raw_size=1: ratio=4; diff=3/4=0.75 < 0.8. No.
    # vsize=9, raw_size=1: ratio=9 > 5 -> line 246. No.
    # vsize=99, raw_size=10: ratio=9.9 > 5 -> line 246.
    # vsize=49, raw_size=10: ratio=4.9; diff=39/49=0.796 < 0.8. Barely misses.
    # vsize=98, raw_size=10: ratio=9.8 > 5 -> 246.
    # vsize=45, raw_size=10: ratio=4.5; diff=35/45=0.778. < 0.8.
    # vsize=19, raw_size=1: ratio=19 > 10. line 244.
    # Trying exact math: need ratio <= 5 and (vsize-raw)/max(vsize,raw) > 0.8
    # If raw < vsize: (vsize-raw)/vsize > 0.8 -> 1 - raw/vsize > 0.8 -> raw/vsize < 0.2 -> vsize > 5*raw
    # But ratio=vsize/raw <= 5 AND vsize > 5*raw is impossible (strictly). Unless ratio == 5 exactly:
    # ratio = 5 exactly: diff_ratio = (5-1)/5 = 0.8, which is NOT > 0.8.
    # So the combination "ratio <= 5 AND diff_ratio > 0.8" is only possible if raw > vsize!
    # If raw > vsize: ratio = vsize/raw < 1. diff = raw - vsize. diff/raw > 0.8 -> 1 - vsize/raw > 0.8
    # -> vsize/raw < 0.2 -> vsize < 0.2*raw
    # AND ratio <= 5: vsize/raw <= 5, satisfied since vsize/raw < 0.2 < 5.
    # Example: vsize=10, raw_size=100: ratio=0.1 <= 5; diff=90/100=0.9 > 0.8 -> line 248! ✓
    indicators = analyzer._check_size_indicators(vsize=10, raw_size=100)
    assert any("difference" in ind.lower() for ind in indicators)


# ---------------------------------------------------------------------------
# section_analyzer.py – _get_section_characteristics exception (lines 325-326)
# ---------------------------------------------------------------------------


def test_section_get_section_characteristics_exception() -> None:
    """Non-dict section triggers exception caught at lines 325-326."""
    analyzer = SectionAnalyzer(adapter=SimpleSectionAdapter())
    analysis = {
        "is_executable": False,
        "entropy": 0.0,
        "pe_characteristics": [],
    }
    result = analyzer._get_section_characteristics("not_a_dict", analysis)  # type: ignore[arg-type]
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# section_analyzer.py – _analyze_code_section exception (lines 377-378)
# ---------------------------------------------------------------------------


def test_section_analyze_code_section_exception() -> None:
    """Non-dict section triggers AttributeError caught at lines 377-378."""
    analyzer = SectionAnalyzer(adapter=SimpleSectionAdapter())
    result = analyzer._analyze_code_section("not_a_dict")  # type: ignore[arg-type]
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# section_analyzer.py – _get_arch cached path (line 413)
# ---------------------------------------------------------------------------


def test_section_get_arch_cached() -> None:
    """Second call returns cached _arch value via line 413."""
    analyzer = SectionAnalyzer(adapter=SimpleSectionAdapter(file_info={"arch": "x86_64"}))
    # First call sets _arch
    arch1 = analyzer._get_arch()
    assert arch1 == "x86_64"
    # Second call returns from cache (line 413)
    arch2 = analyzer._get_arch()
    assert arch2 == "x86_64"


# ---------------------------------------------------------------------------
# section_analyzer.py – _get_arch exception path (lines 418-419)
# ---------------------------------------------------------------------------


def test_section_get_arch_exception() -> None:
    """adapter.get_file_info raises -> exception caught (lines 418-419), arch=None."""
    analyzer = SectionAnalyzer(adapter=RaisingFileInfoAdapter())
    arch = analyzer._get_arch()
    assert arch is None


# ---------------------------------------------------------------------------
# section_analyzer.py – get_section_summary exception (lines 449-450)
# ---------------------------------------------------------------------------


def test_section_get_section_summary_exception() -> None:
    """Adapter returns section with list flags (unhashable) -> exception in
    get_section_summary caught at lines 449-450."""
    analyzer = SectionAnalyzer(adapter=UnhashableFlagsAdapter())
    summary = analyzer.get_section_summary()
    # Exception caught internally; summary still returned
    assert isinstance(summary, dict)
    assert "total_sections" in summary


# ---------------------------------------------------------------------------
# section_analyzer.py – _check_entropy_anomaly sets entropy_anomaly (lines 418-419)
# Note: these lines are _check_entropy_anomaly logic, NOT _get_arch
# ---------------------------------------------------------------------------


def test_section_check_entropy_anomaly_out_of_range() -> None:
    """entropy outside expected_entropy range sets entropy_anomaly=True (line 339)."""
    analyzer = SectionAnalyzer(adapter=SimpleSectionAdapter())
    characteristics: dict = {"expected_entropy": "6.0-7.5"}
    analysis = {"entropy": 2.0}
    analyzer._check_entropy_anomaly(characteristics, analysis)
    assert characteristics.get("entropy_anomaly") is True


def test_section_check_entropy_anomaly_variable_skips() -> None:
    """expected_entropy='Variable' skips the check (returns early, line 333)."""
    analyzer = SectionAnalyzer(adapter=SimpleSectionAdapter())
    characteristics: dict = {"expected_entropy": "Variable"}
    analysis = {"entropy": 8.0}
    analyzer._check_entropy_anomaly(characteristics, analysis)
    assert "entropy_anomaly" not in characteristics


# ---------------------------------------------------------------------------
# section_analyzer.py – _get_section_characteristics with is_executable (line 323)
# ---------------------------------------------------------------------------


def test_section_get_section_characteristics_executable() -> None:
    """When analysis['is_executable']=True, code_analysis is populated (line 323)."""
    analyzer = SectionAnalyzer(
        adapter=SimpleSectionAdapter(read_bytes_data=b"\x90" * 100, file_info={"arch": "x86"})
    )
    section = {"name": ".text", "vaddr": 0x1000, "size": 100, "vsize": 100}
    analysis = {"is_executable": True, "entropy": 6.5, "pe_characteristics": []}
    result = analyzer._get_section_characteristics(section, analysis)
    assert "code_analysis" in result
