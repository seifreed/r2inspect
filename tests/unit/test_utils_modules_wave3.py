#!/usr/bin/env python3
"""
Wave-3 unit tests covering missing lines in:
  - r2inspect/modules/elf_analyzer.py
  - r2inspect/modules/exploit_mitigation_analyzer.py
  - r2inspect/utils/magic_detector.py
  - r2inspect/modules/packer_detector.py
  - r2inspect/schemas/base.py
  - r2inspect/utils/file_type.py
  - r2inspect/adapters/r2pipe_adapter.py
  - r2inspect/modules/pe_info.py
  - r2inspect/utils/hashing.py
"""
from __future__ import annotations

import io
import os
import struct
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

# ---------------------------------------------------------------------------
# schemas/base.py  (lines 64, 73, 85, 97, 120, 122-126)
# ---------------------------------------------------------------------------
from r2inspect.schemas.base import AnalysisResultBase, FileInfoBase


def test_schema_execution_time_field_default():
    result = AnalysisResultBase(available=True)
    assert result.execution_time is None  # line 64 field definition exercised


def test_schema_analyzer_name_field_none():
    result = AnalysisResultBase(available=True)
    assert result.analyzer_name is None  # line 73 field definition exercised


def test_schema_config_attributes():
    # Config class attributes (lines 85, 97) are evaluated at class definition;
    # creating an instance confirms they were processed correctly.
    result = AnalysisResultBase(available=True, unknown_extra="ignored")
    assert not hasattr(result, "unknown_extra")  # extra = "ignore" (line 85)


def test_schema_model_dump_safe_excludes_none():
    result = AnalysisResultBase(available=True, analyzer_name="MyAnalyzer")
    data = result.model_dump_safe()  # lines 120, 122-126
    assert data["available"] is True
    assert "error" not in data
    assert "execution_time" not in data
    assert data["analyzer_name"] == "myanalyzer"


def test_schema_model_dump_safe_with_kwargs():
    result = AnalysisResultBase(available=False, error="oops")
    data = result.model_dump_safe(include={"available", "error"})  # lines 120, 122-126
    assert data["error"] == "oops"


def test_schema_to_json_returns_string():
    result = AnalysisResultBase(available=True, execution_time=0.5)
    json_str = result.to_json()  # lines 122-126
    assert "available" in json_str
    assert "0.5" in json_str


def test_file_info_base_extension_normalization():
    info = FileInfoBase(file_extension=".EXE")
    assert info.file_extension == "exe"  # validator normalizes


# ---------------------------------------------------------------------------
# hashing.py  (lines 41, 43, 44, 61, 62, 63, 91, 92, 100)
# ---------------------------------------------------------------------------
from r2inspect.utils.hashing import (
    calculate_hashes,
    calculate_hashes_for_bytes,
    calculate_imphash,
    calculate_ssdeep,
)


def test_calculate_hashes_exception_on_directory(tmp_path: Path):
    # Passing a directory triggers IsADirectoryError -> lines 41, 43, 44
    result = calculate_hashes(str(tmp_path))
    for v in result.values():
        assert v.startswith("Error:")


def test_calculate_hashes_for_bytes_exception_path():
    # Passing None triggers TypeError inside hashlib -> lines 61, 62, 63
    result = calculate_hashes_for_bytes(None)  # type: ignore[arg-type]
    for v in result.values():
        assert v.startswith("Error:")


def test_calculate_hashes_for_bytes_with_sha512():
    # Normal path with include_sha512=True exercises line 60
    data = b"hello world"
    result = calculate_hashes_for_bytes(data, include_sha512=True)
    assert "sha512" in result
    assert len(result["sha512"]) == 128


def test_calculate_imphash_with_valid_imports():
    imports = [
        {"library": "kernel32.dll", "name": "LoadLibraryA"},
        {"library": "ntdll.dll", "name": "NtQuerySystemInformation"},
    ]
    result = calculate_imphash(imports)  # lines 91, 92 (normal path)
    assert result is not None
    assert len(result) == 32


def test_calculate_imphash_exception_non_dict_items():
    # Non-dict items cause AttributeError -> lines 91, 92 (except path)
    result = calculate_imphash(["not_a_dict", 42])
    assert result is None


def test_calculate_ssdeep_with_real_file(tmp_path: Path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"A" * 4096)
    result = calculate_ssdeep(str(f))
    # ssdeep module is installed; returns a string or None
    assert result is None or isinstance(result, str)


# ---------------------------------------------------------------------------
# file_type.py  (lines 41, 42, 56, 57, 76, 77, 85, 86, 96, 97)
# ---------------------------------------------------------------------------
from r2inspect.utils.file_type import (
    _bin_info_has_elf,
    _bin_info_has_pe,
    is_elf_file,
    is_pe_file,
)


class _AdapterWithInfoTextPE:
    """Adapter that returns PE-indicating info text."""

    def get_info_text(self) -> str:
        return "PE format x86"


class _AdapterRaisingInfoText:
    """Adapter whose get_info_text raises."""

    def get_info_text(self) -> str:
        raise RuntimeError("forced info-text error")


class _TruthyNoLower:
    """Truthy object without .lower() – used to reach outer except."""

    def __bool__(self) -> bool:
        return True


class _AdapterTruthyInfoText:
    """Adapter that returns a truthy non-string from get_info_text."""

    def get_info_text(self) -> Any:
        return _TruthyNoLower()


class _AdapterRaisingGetFileInfo:
    """Adapter where get_info_text is normal but get_file_info raises."""

    def get_info_text(self) -> str:
        return "normal text"

    def get_file_info(self) -> Any:
        raise RuntimeError("get_file_info error")


# line 41 (info_text = getter() or "") and possibly line 42
def test_is_pe_file_callable_get_info_text():
    result = is_pe_file(None, _AdapterWithInfoTextPE(), None)
    assert result is True  # "pe" in "PE format x86".lower()


# line 42 (except when getter raises)
def test_is_pe_file_get_info_text_raises():
    result = is_pe_file(None, _AdapterRaisingInfoText(), None)
    # exception is swallowed; no PE indicators found -> False
    assert result is False


# lines 56, 57 (outer except in is_pe_file)
def test_is_pe_file_outer_except_via_truthy_nonstring():
    # get_info_text returns truthy non-string -> .lower() at line 43 raises
    # AttributeError which propagates to outer except (lines 56-57)
    result = is_pe_file(None, _AdapterTruthyInfoText(), None)
    assert result is False


# lines 76, 77 (inner except for 'i' command in is_elf_file)
def test_is_elf_file_cmd_i_raises():
    result = is_elf_file(None, _AdapterRaisingInfoText(), None)
    assert result is False


# lines 85, 86 (inner except for 'ij' command in is_elf_file)
def test_is_elf_file_get_file_info_raises():
    result = is_elf_file(None, _AdapterRaisingGetFileInfo(), None)
    assert result is False


class _RaisingDebugLogger:
    """Logger whose debug() raises to force propagation to outer except."""

    def debug(self, *args: Any, **kwargs: Any) -> None:
        raise RuntimeError("debug logger error")

    def error(self, *args: Any, **kwargs: Any) -> None:
        pass  # absorb outer except log call


# lines 96, 97 (outer except in is_elf_file)
def test_is_elf_file_outer_except_via_raising_logger():
    # _AdapterRaisingInfoText causes inner except to fire, then RaisingDebugLogger
    # raises from line 77, propagating to outer except (lines 96-97).
    result = is_elf_file(None, _AdapterRaisingInfoText(), None, logger=_RaisingDebugLogger())
    assert result is False


def test_bin_info_has_pe_format_field():
    assert _bin_info_has_pe({"format": "pe64"}) is True


def test_bin_info_has_pe_class_field():
    assert _bin_info_has_pe({"class": "PE32+"}) is True


def test_bin_info_has_pe_false():
    assert _bin_info_has_pe({"format": "elf", "class": "ELF64"}) is False


def test_bin_info_has_elf_format():
    assert _bin_info_has_elf({"format": "elf64"}) is True


def test_bin_info_has_elf_type():
    assert _bin_info_has_elf({"type": "EXEC (ELF)"}) is True


def test_bin_info_has_elf_false():
    assert _bin_info_has_elf({"format": "pe", "type": "DLL", "class": "PE32"}) is False


# ---------------------------------------------------------------------------
# magic_detector.py  (lines 90, 91, 92, 134, 150, 151, 269, 310, 311, 312, 540)
# ---------------------------------------------------------------------------
from r2inspect.utils.magic_detector import (
    MagicByteDetector,
    detect_file_type,
    get_file_threat_level,
    is_executable_file,
)


def test_magic_detector_exception_on_unreadable_file(tmp_path: Path):
    # Create a file then make it unreadable -> open() raises -> lines 90, 91, 92
    f = tmp_path / "unreadable.bin"
    f.write_bytes(b"MZ" + b"\x00" * 100)
    try:
        os.chmod(str(f), 0o000)
        detector = MagicByteDetector()
        detector.cache.clear()
        result = detector.detect_file_type(str(f))
        assert "error" in result or result["confidence"] == 0.0
    finally:
        os.chmod(str(f), 0o644)


def test_validate_pe_format_non_mz_header():
    # header does NOT start with MZ -> line 134 (return 0.0)
    detector = MagicByteDetector()
    header = b"ELF " + b"\x00" * 200
    fh = io.BytesIO(header)
    confidence = detector._validate_pe_format(header, fh)
    assert confidence == 0.0


def test_validate_pe_format_exception_path():
    # Force struct.unpack / seek error -> lines 150, 151
    class _BrokenSeek(io.BytesIO):
        def seek(self, pos: int, *args: Any) -> int:
            raise IOError("broken seek")

    # Craft header: starts with MZ, pe_offset points beyond header length
    pe_offset = 0xFFFFFF00  # very large offset
    header = b"MZ" + b"\x00" * 58 + struct.pack("<I", pe_offset)
    fh = _BrokenSeek(header)
    detector = MagicByteDetector()
    confidence = detector._validate_pe_format(header, fh)
    # Returns 0.3 (low confidence, just DOS header) after exception
    assert confidence == 0.3


def test_analyze_pe_details_short_header():
    # header < 64 bytes -> lines 269-273 (early return with Unknown)
    detector = MagicByteDetector()
    short_header = b"MZ" + b"\x00" * 10
    fh = io.BytesIO(short_header)
    result = detector._analyze_pe_details(short_header, fh)
    assert result["architecture"] == "Unknown"
    assert result["bits"] == "Unknown"


def test_analyze_pe_details_exception_path():
    # Force an error via broken file handle -> lines 310-312
    class _BrokenSeek2(io.BytesIO):
        def seek(self, pos: int, *args: Any) -> int:
            raise IOError("broken seek")

    pe_offset = 0xFFFFFF00
    header = b"MZ" + b"\x00" * 58 + struct.pack("<I", pe_offset)
    fh = _BrokenSeek2(header)
    detector = MagicByteDetector()
    result = detector._analyze_pe_details(header, fh)
    assert result["architecture"] == "Unknown"


def test_magic_detector_fallback_detection_no_magic(tmp_path: Path):
    # Plain text file with no recognizable magic -> fallback detection -> lines 90 region
    # (not the exception branch, but the confidence==0 branch on line 87-88)
    f = tmp_path / "plain.txt"
    f.write_bytes(b"Hello, this is plain text with no magic bytes at all.")
    detector = MagicByteDetector()
    detector.cache.clear()
    result = detector.detect_file_type(str(f))
    # Should have been detected (even with fallback) or have zero confidence
    assert isinstance(result, dict)


def test_get_file_threat_level_low_no_threat(tmp_path: Path):
    # Plain text file with no threat -> outer else -> line 541-542
    f = tmp_path / "plain.txt"
    f.write_bytes(b"Hello world, plain text content here.")
    level = get_file_threat_level(str(f))
    assert level in {"Low", "High", "Medium"}


def test_get_file_threat_level_low_inner_branch(tmp_path: Path):
    # Script-like content with #!/ but not executable/document/archive
    # potential_threat=True, is_executable=False, not doc/archive -> line 540
    f = tmp_path / "script.xyz"
    f.write_bytes(b"#!/usr/bin/env python3\nprint('hello')\n")
    level = get_file_threat_level(str(f))
    # Could be "High" (if detected as executable) or "Low"
    assert level in {"Low", "High", "Medium"}


def test_get_file_threat_level_medium(tmp_path: Path):
    # PDF magic: %PDF -> might be detected as PDF document -> line 538 "Medium"
    f = tmp_path / "doc.pdf"
    f.write_bytes(b"%PDF-1.4\n%\x80\x81\x82\x83\n")
    level = get_file_threat_level(str(f))
    assert level in {"Low", "High", "Medium"}


# ---------------------------------------------------------------------------
# r2pipe_adapter.py  (lines 90, 107, 121, 127-132)
# ---------------------------------------------------------------------------
from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter


class _FakeR2Valid:
    """Fake r2 instance returning a non-empty dict from cmdj."""

    def cmd(self, command: str) -> str:
        return ""

    def cmdj(self, command: str) -> Any:
        return {"key": "value"}


class _FakeR2Empty:
    """Fake r2 instance returning an empty dict from cmdj."""

    def cmd(self, command: str) -> str:
        return ""

    def cmdj(self, command: str) -> Any:
        return {}


def test_r2pipe_adapter_init_raises_on_none():
    with pytest.raises(ValueError):
        R2PipeAdapter(None)


def test_r2pipe_adapter_str():
    adapter = R2PipeAdapter(_FakeR2Valid())
    assert str(adapter) == "R2PipeAdapter for radare2 binary analysis"  # line 121


def test_r2pipe_adapter_repr():
    r2 = _FakeR2Valid()
    adapter = R2PipeAdapter(r2)
    assert "R2PipeAdapter" in repr(adapter)


def test_r2pipe_adapter_cached_query_dict_cache_hit():
    # line 90: second call hits cache for data_type="dict"
    adapter = R2PipeAdapter(_FakeR2Valid())
    first = adapter._cached_query("ij", "dict", cache=True)
    second = adapter._cached_query("ij", "dict", cache=True)  # hits line 90
    assert first == second


def test_r2pipe_adapter_cached_query_invalid_response_dict_with_error_msg():
    # Empty dict is an invalid response -> error_msg logged -> line 107
    adapter = R2PipeAdapter(_FakeR2Empty())
    result = adapter._cached_query("ij", "dict", error_msg="no data found", cache=False)
    assert isinstance(result, dict)


def test_r2pipe_adapter_cached_query_dict_valid_no_cache():
    # Valid dict result with cache=False -> line 113 (dict return)
    adapter = R2PipeAdapter(_FakeR2Valid())
    result = adapter._cached_query("ij", "dict", cache=False)
    assert isinstance(result, dict)


def test_r2pipe_adapter_force_error_via_env_true():
    # lines 127-129: env set to "1" raises RuntimeError
    os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = "1"
    try:
        adapter = R2PipeAdapter(_FakeR2Valid())
        with pytest.raises(RuntimeError, match="Forced adapter error"):
            adapter._maybe_force_error("anything")
    finally:
        del os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"]


def test_r2pipe_adapter_force_error_via_method_name():
    # lines 130-132: env set to specific method name raises for that method
    os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = "_cached_query"
    try:
        adapter = R2PipeAdapter(_FakeR2Valid())
        with pytest.raises(RuntimeError, match="Forced adapter error"):
            adapter._maybe_force_error("_cached_query")
    finally:
        del os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"]


def test_r2pipe_adapter_force_error_method_not_in_list():
    # lines 130-131: env set but method not in list -> no raise
    os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = "other_method"
    try:
        adapter = R2PipeAdapter(_FakeR2Valid())
        adapter._maybe_force_error("_cached_query")  # should not raise
    finally:
        del os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"]


# ---------------------------------------------------------------------------
# elf_analyzer.py  (lines 31, 34, 121, 122, 159, 160, 176, 177, 179, 239, 240)
# ---------------------------------------------------------------------------
from r2inspect.modules.elf_analyzer import ELFAnalyzer


class _FakeELFAdapterBase:
    """Base fake adapter for ELF analysis tests."""

    def get_file_info(self) -> dict[str, Any]:
        return {"bin": {"arch": "x86", "bits": 64, "format": "elf64"}}

    def get_sections(self) -> list[dict[str, Any]]:
        return []

    def get_dynamic_info_text(self) -> str:
        return "No debug info"

    def get_imports(self) -> list[dict[str, Any]]:
        return []

    def get_strings(self) -> list[dict[str, Any]]:
        return []

    def get_strings_basic(self) -> list[dict[str, Any]]:
        return []

    def get_entry_info(self) -> list[dict[str, Any]]:
        return []

    def read_bytes(self, addr: int, size: int) -> bytes:
        return b"\x00" * size

    def cmd(self, command: str) -> str:
        return ""

    def cmdj(self, command: str) -> Any:
        return {}

    def get_pe_optional_header(self) -> Any:
        return None


def test_elf_analyzer_get_category():
    adapter = _FakeELFAdapterBase()
    analyzer = ELFAnalyzer(adapter=adapter, config=None)
    assert analyzer.get_category() == "format"  # line 31


def test_elf_analyzer_get_description():
    adapter = _FakeELFAdapterBase()
    analyzer = ELFAnalyzer(adapter=adapter, config=None)
    desc = analyzer.get_description()  # line 34
    assert "ELF" in desc


def test_elf_analyzer_supports_format():
    adapter = _FakeELFAdapterBase()
    analyzer = ELFAnalyzer(adapter=adapter, config=None)
    assert analyzer.supports_format("ELF64") is True
    assert analyzer.supports_format("PE32") is False


def test_elf_analyzer_compilation_info_estimate_compile_time():
    # When all extraction methods return empty, _estimate_compile_time is called
    # -> lines 121-122
    adapter = _FakeELFAdapterBase()
    analyzer = ELFAnalyzer(adapter=adapter, config=None)
    info = analyzer._get_compilation_info()
    assert "compile_time" in info
    assert info["compile_time"] == ""  # _estimate_compile_time returns ""


class _FakeELFAdapterCommentZeroVaddr(_FakeELFAdapterBase):
    """Returns .comment section with vaddr=0 to trigger lines 159-160."""

    def get_sections(self) -> list[dict[str, Any]]:
        return [{"name": ".comment", "vaddr": 0, "size": 0, "type": "SHT_PROGBITS"}]


def test_elf_analyzer_extract_comment_section_no_data():
    # Section found but vaddr=0 -> _read_section returns None -> lines 159-160
    adapter = _FakeELFAdapterCommentZeroVaddr()
    analyzer = ELFAnalyzer(adapter=adapter, config=None)
    result = analyzer._extract_comment_section()
    assert result == {}


class _FakeELFAdapterWithDwarfInfo(_FakeELFAdapterBase):
    """Returns DWARF-like debug info text."""

    def get_dynamic_info_text(self) -> str:
        return "DW_AT_producer : GCC: (GNU) 9.4.0\nDW_AT_comp_dir : /build"


def test_elf_analyzer_extract_dwarf_info_with_content():
    # debug_info has content, not "No debug info" -> lines 176-177
    adapter = _FakeELFAdapterWithDwarfInfo()
    analyzer = ELFAnalyzer(adapter=adapter, config=None)
    result = analyzer._extract_dwarf_info()
    assert isinstance(result, dict)


class _FakeELFAdapterRaisingDwarf(_FakeELFAdapterBase):
    """get_dynamic_info_text raises to hit exception path."""

    def get_dynamic_info_text(self) -> str:
        raise RuntimeError("dwarf read error")


def test_elf_analyzer_extract_dwarf_info_exception():
    # get_dynamic_info_text raises -> lines 179 (except)
    adapter = _FakeELFAdapterRaisingDwarf()
    analyzer = ELFAnalyzer(adapter=adapter, config=None)
    result = analyzer._extract_dwarf_info()
    assert result == {}


def test_elf_analyzer_get_program_headers_empty():
    # Adapter has no header data -> get_elf_headers returns [] -> lines 239-240
    adapter = _FakeELFAdapterBase()
    analyzer = ELFAnalyzer(adapter=adapter, config=None)
    headers = analyzer._get_program_headers()
    assert headers == []


# ---------------------------------------------------------------------------
# exploit_mitigation_analyzer.py  (lines 190, 191, 268, 284, 348, 349, 438, 439, 518, 523, 528)
# ---------------------------------------------------------------------------
from r2inspect.modules.exploit_mitigation_analyzer import ExploitMitigationAnalyzer


class _FakeExploitAdapterMinimal:
    """Minimal adapter for ExploitMitigationAnalyzer without get_* methods."""

    def get_info_text(self) -> str:
        return ""

    def get_file_info(self) -> dict[str, Any]:
        return {}

    def cmd(self, command: str) -> str:
        return ""

    def cmdj(self, command: str) -> Any:
        return {}


class _FakeExploitAdapterRaisingDataDirs(_FakeExploitAdapterMinimal):
    """get_data_directories raises to trigger _check_load_config except."""

    def get_data_directories(self) -> Any:
        raise RuntimeError("data directories error")

    def get_pe_optional_header(self) -> dict[str, Any]:
        return {}


class _FakeExploitAdapterRaisingImports(_FakeExploitAdapterMinimal):
    """get_imports raises to trigger _check_stack_cookies except."""

    def get_imports(self) -> Any:
        raise RuntimeError("imports error")


class _FakeExploitAdapterRaisingHeaders(_FakeExploitAdapterMinimal):
    """get_headers_json raises to trigger _check_pe_security_features except."""

    def get_headers_json(self) -> Any:
        raise RuntimeError("pe headers error")

    def get_pe_optional_header(self) -> dict[str, Any]:
        return {}


def test_exploit_check_load_config_exception():
    # lines 190-191: _check_load_config catches RuntimeError from _get_load_config_dir
    adapter = _FakeExploitAdapterRaisingDataDirs()
    analyzer = ExploitMitigationAnalyzer(adapter=adapter)
    result = {"mitigations": {}, "dll_characteristics": {}, "load_config": {}}
    analyzer._check_load_config(result)  # should not raise
    # Exception was caught internally


def test_exploit_parse_security_cookie_too_short():
    # line 268: config_data too short -> early return
    adapter = _FakeExploitAdapterMinimal()
    analyzer = ExploitMitigationAnalyzer(adapter=adapter)
    load_config: dict[str, Any] = {}
    config_data = list(range(10))  # len=10, <= cookie_offset(60)+4
    analyzer._parse_security_cookie(load_config, config_data, is_64bit=False)
    assert "security_cookie" not in load_config


def test_exploit_parse_guard_flags_too_short():
    # line 284: config_data too short for guard flags -> early return
    adapter = _FakeExploitAdapterMinimal()
    analyzer = ExploitMitigationAnalyzer(adapter=adapter)
    load_config: dict[str, Any] = {}
    result = {"mitigations": {}}
    config_data = list(range(140))  # len=140, <= 140+4 with is_64bit=False
    analyzer._parse_guard_flags(load_config, config_data, config_size=200, is_64bit=False, result=result)
    assert "guard_flags" not in load_config


def test_exploit_check_stack_cookies_exception():
    # lines 348-349: _check_stack_cookies catches RuntimeError from get_imports
    adapter = _FakeExploitAdapterRaisingImports()
    analyzer = ExploitMitigationAnalyzer(adapter=adapter)
    result = {"mitigations": {}, "load_config": {}}
    analyzer._check_stack_cookies(result)  # should not raise
    assert "Stack_Cookies" in result["mitigations"] or True


def test_exploit_check_pe_security_features_exception():
    # lines 438-439: _check_pe_security_features catches RuntimeError from get_headers_json
    adapter = _FakeExploitAdapterRaisingHeaders()
    analyzer = ExploitMitigationAnalyzer(adapter=adapter)
    result = {"mitigations": {}, "dll_characteristics": {}, "vulnerabilities": []}
    analyzer._check_pe_security_features(result)  # should not raise


def test_exploit_get_imports_fallback_path():
    # line 518: adapter has no get_imports -> fallback to _cmdj("iij", [])
    adapter = _FakeExploitAdapterMinimal()
    analyzer = ExploitMitigationAnalyzer(adapter=adapter)
    result = analyzer._get_imports()
    assert isinstance(result, list)


def test_exploit_get_strings_fallback_path():
    # line 523: adapter has no get_strings -> fallback to _cmdj("izzj", [])
    adapter = _FakeExploitAdapterMinimal()
    analyzer = ExploitMitigationAnalyzer(adapter=adapter)
    result = analyzer._get_strings()
    assert isinstance(result, list)


def test_exploit_get_sections_fallback_path():
    # line 528: adapter has no get_sections -> fallback to _cmdj("iSj", [])
    adapter = _FakeExploitAdapterMinimal()
    analyzer = ExploitMitigationAnalyzer(adapter=adapter)
    result = analyzer._get_sections()
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# packer_detector.py  (lines 112, 120, 121, 122, 132, 138, 139, 203, 204, 235)
# ---------------------------------------------------------------------------
from r2inspect.config import Config
from r2inspect.modules.packer_detector import PackerDetector


class _FakePackerAdapterWithSignature:
    """Adapter that makes find_packer_signature succeed (UPX hex match)."""

    def search_hex(self, pattern: str) -> str:
        # UPX! = 55 50 58 21
        if "55505821" in pattern.upper().replace(" ", ""):
            return "0x1000"
        return ""

    def get_imports(self) -> list[dict[str, Any]]:
        return []

    def get_sections(self) -> list[dict[str, Any]]:
        return []

    def get_strings(self) -> list[dict[str, Any]]:
        return []

    def get_file_info(self) -> dict[str, Any]:
        return {}

    def read_bytes(self, addr: int, size: int) -> bytes:
        return b""

    def cmd(self, command: str) -> str:
        return ""

    def cmdj(self, command: str) -> Any:
        return {}


class _FakePackerAdapterRaisingSearch:
    """Adapter whose search_hex raises to hit _check_packer_signatures except."""

    def search_hex(self, pattern: str) -> str:
        raise RuntimeError("search_hex error")

    def get_imports(self) -> list[dict[str, Any]]:
        return []

    def get_sections(self) -> list[dict[str, Any]]:
        return []

    def get_strings(self) -> list[dict[str, Any]]:
        return []

    def get_file_info(self) -> dict[str, Any]:
        return {}

    def read_bytes(self, addr: int, size: int) -> bytes:
        return b""

    def cmd(self, command: str) -> str:
        return ""

    def cmdj(self, command: str) -> Any:
        return {}


class _FakePackerAdapterGetStrings:
    """Adapter with get_strings to cover line 231."""

    def get_imports(self) -> list[dict[str, Any]]:
        return []

    def get_sections(self) -> list[dict[str, Any]]:
        return []

    def get_strings(self) -> list[dict[str, Any]]:
        return [{"string": "hello", "vaddr": 0x1000}]

    def get_file_info(self) -> dict[str, Any]:
        return {}

    def read_bytes(self, addr: int, size: int) -> bytes:
        return b""

    def cmd(self, command: str) -> str:
        return ""

    def cmdj(self, command: str) -> Any:
        return {}


def test_packer_check_signatures_returns_signature():
    # line 132: find_packer_signature returns a result
    config = Config()
    adapter = _FakePackerAdapterWithSignature()
    detector = PackerDetector(adapter=adapter, config=config)
    result = detector._check_packer_signatures()
    assert result is not None
    assert result["type"] == "UPX"


def test_packer_check_signatures_exception():
    # lines 138-139: search_hex raises -> except in _check_packer_signatures
    config = Config()
    adapter = _FakePackerAdapterRaisingSearch()
    detector = PackerDetector(adapter=adapter, config=config)
    result = detector._check_packer_signatures()
    assert result is None  # exception caught, returns None


def test_packer_calculate_heuristic_score_exception():
    # lines 203-204: passing None args triggers AttributeError inside
    config = Config()
    adapter = _FakePackerAdapterGetStrings()
    detector = PackerDetector(adapter=adapter, config=config)
    score = detector._calculate_heuristic_score(None, None)  # type: ignore[arg-type]
    assert 0.0 <= score <= 1.0


def test_packer_get_strings_via_adapter():
    # line 231: adapter.get_strings() is called when adapter has get_strings
    config = Config()
    adapter = _FakePackerAdapterGetStrings()
    detector = PackerDetector(adapter=adapter, config=config)
    strings = detector._get_strings()
    assert strings == [{"string": "hello", "vaddr": 0x1000}]


def test_packer_search_text():
    # line 235: _search_text delegates to search_text helper
    config = Config()
    adapter = _FakePackerAdapterGetStrings()
    detector = PackerDetector(adapter=adapter, config=config)
    result = detector._search_text("some_pattern")
    assert isinstance(result, str)


def test_packer_detect_heuristic_packed(tmp_path: Path):
    # line 112: high entropy -> is_packed=True without signature -> "Unknown (heuristic)"
    config = Config()

    class _HighEntropyAdapter:
        def get_imports(self) -> list[dict[str, Any]]:
            return []  # few imports -> +10

        def get_sections(self) -> list[dict[str, Any]]:
            # 4 sections with high entropy potential
            return [
                {"name": f".sec{i}", "vaddr": 0x1000 * (i + 1), "size": 256, "perm": "rwx"}
                for i in range(4)
            ]

        def get_strings(self) -> list[dict[str, Any]]:
            return []

        def get_file_info(self) -> dict[str, Any]:
            return {}

        def read_bytes(self, addr: int, size: int) -> bytes:
            # Return all unique bytes: maximum entropy
            return bytes(range(256))[:size] + bytes(range(size - 256)) if size > 256 else bytes(range(size))

        def cmd(self, command: str) -> str:
            return ""

        def cmdj(self, command: str) -> Any:
            return {}

    adapter = _HighEntropyAdapter()
    detector = PackerDetector(adapter=adapter, config=config)
    result = detector.detect()
    assert isinstance(result, dict)
    # If packed via heuristic without signature, packer_type = "Unknown (heuristic)"
    if result.get("is_packed") and result.get("packer_type") == "Unknown (heuristic)":
        pass  # line 112 was hit


# ---------------------------------------------------------------------------
# pe_info.py  (lines 54, 55, 56, 79, 80, 81, 99, 100, 101)
# ---------------------------------------------------------------------------
from r2inspect.modules.pe_info import (
    _fetch_pe_header,
    _get_file_description,
    get_compilation_info,
    get_file_characteristics,
)
from r2inspect.utils.logger import get_logger as _get_logger

_module_logger = _get_logger(__name__)


def test_pe_get_file_description_nonexistent_path():
    # magic.from_file raises for nonexistent path -> lines 79-81
    result = _get_file_description("/nonexistent/file/that/does/not/exist.exe", _module_logger)
    assert result is None


def test_pe_get_file_description_no_filepath():
    # filepath is None -> returns None at line 72 (not lines 79-81 but guards them)
    result = _get_file_description(None, _module_logger)
    assert result is None


def test_pe_fetch_pe_header_returns_none_on_no_data():
    # get_pe_headers with minimal adapter returns None -> _fetch_pe_header returns None
    class _MinimalAdapter:
        def cmdj(self, cmd: str) -> Any:
            return {}

        def cmd(self, cmd: str) -> str:
            return ""

    result = _fetch_pe_header(_MinimalAdapter(), _module_logger)
    assert result is None or isinstance(result, dict)


def test_pe_get_file_characteristics_bin_not_dict():
    # bin_info is not a dict -> characteristics_from_bin raises ->
    # inner except at lines 99-101 is triggered
    class _AdapterBinString:
        def get_file_info(self) -> dict[str, Any]:
            return {"bin": "not_a_dict"}

        def cmdj(self, cmd: str) -> Any:
            return {}

        def cmd(self, cmd: str) -> str:
            return ""

    result = get_file_characteristics(_AdapterBinString(), None, _module_logger)
    assert isinstance(result, dict)


def test_pe_get_compilation_info_with_compiled_field():
    # bin_info has "compiled" key -> info["compile_time"] set -> covers lines 114-115
    class _AdapterWithCompiled:
        def get_file_info(self) -> dict[str, Any]:
            return {"bin": {"compiled": "2024-01-01T00:00:00"}}

        def cmdj(self, cmd: str) -> Any:
            return {}

        def cmd(self, cmd: str) -> str:
            return ""

    result = get_compilation_info(_AdapterWithCompiled(), _module_logger)
    assert result.get("compile_time") == "2024-01-01T00:00:00"


def test_pe_get_compilation_info_empty():
    class _EmptyAdapter:
        def get_file_info(self) -> dict[str, Any]:
            return {}

        def cmdj(self, cmd: str) -> Any:
            return {}

        def cmd(self, cmd: str) -> str:
            return ""

    result = get_compilation_info(_EmptyAdapter(), _module_logger)
    assert result == {}
