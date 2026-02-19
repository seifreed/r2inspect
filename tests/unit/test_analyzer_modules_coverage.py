#!/usr/bin/env python3
"""Unit tests for section_analyzer, compiler_detector, packer_detector,
packer_helpers, and anti_analysis modules.

Stub adapters are plain classes – no mocks, no unittest.mock, no patch.
"""

from __future__ import annotations

from typing import Any

import pytest

from r2inspect.config import Config
from r2inspect.modules.anti_analysis import AntiAnalysisDetector
from r2inspect.modules.compiler_detector import CompilerDetector
from r2inspect.modules.packer_detector import PackerDetector
from r2inspect.modules.packer_helpers import (
    analyze_entropy,
    analyze_sections,
    count_imports,
    find_packer_signature,
    find_packer_string,
    overlay_info,
)
from r2inspect.modules.section_analyzer import SectionAnalyzer


# ---------------------------------------------------------------------------
# Stub adapters
# ---------------------------------------------------------------------------


class MinimalAdapter:
    """Stub that returns empty / safe defaults for every adapter method."""

    def get_sections(self) -> list[dict[str, Any]]:
        return []

    def get_imports(self) -> list[dict[str, Any]]:
        return []

    def get_strings(self) -> list[dict[str, Any]]:
        return []

    def get_strings_basic(self) -> list[dict[str, Any]]:
        return []

    def get_file_info(self) -> dict[str, Any]:
        return {}

    def get_symbols(self) -> list[dict[str, Any]]:
        return []

    def get_functions(self) -> list[dict[str, Any]]:
        return []

    def read_bytes(self, addr: int, size: int) -> bytes:
        return b""

    def search_text(self, pattern: str) -> str:
        return ""

    def search_hex(self, pattern: str) -> str:
        return ""


class PESectionsAdapter(MinimalAdapter):
    """Adapter that exposes typical PE sections."""

    def get_sections(self) -> list[dict[str, Any]]:
        return [
            {
                "name": ".text",
                "vaddr": 0x1000,
                "vsize": 0x2000,
                "size": 0x2000,
                "flags": "rx",
                "perm": "rx",
                "characteristics": 0x03000020,  # CNT_CODE | MEM_EXECUTE | MEM_READ
            },
            {
                "name": ".data",
                "vaddr": 0x3000,
                "vsize": 0x1000,
                "size": 0x1000,
                "flags": "rw",
                "perm": "rw",
                "characteristics": 0x06000040,  # INITIALIZED_DATA | MEM_READ | MEM_WRITE
            },
        ]

    def read_bytes(self, addr: int, size: int) -> bytes:
        # Return high-entropy-like bytes for the .text section, zeros elsewhere
        if addr == 0x1000:
            return bytes(range(256)) * (size // 256 + 1)
        return b"\x00" * size


class SuspiciousSectionsAdapter(MinimalAdapter):
    """Adapter with unusual section names and wx permissions."""

    def get_sections(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "upxsec",  # non-standard, triggers name indicator
                "vaddr": 0x1000,
                "vsize": 0x20000,
                "size": 0x100,  # tiny raw → suspicious size ratio
                "flags": "rwx",
                "perm": "rwx",
                "characteristics": 0,
            },
            {
                "name": ".vmp0",
                "vaddr": 0x21000,
                "vsize": 0x1000,
                "size": 0x1000,
                "flags": "rx",
                "perm": "rx",
                "characteristics": 0,
            },
        ]

    def read_bytes(self, addr: int, size: int) -> bytes:
        # Return repetitive data → entropy ~0
        return b"\xCC" * size

    def get_file_info(self) -> dict[str, Any]:
        return {"arch": "x86"}


class GCCStringsAdapter(MinimalAdapter):
    """Adapter that looks like a GCC-compiled binary."""

    def get_strings(self) -> list[dict[str, Any]]:
        return [
            {"string": "GCC: (GNU) 11.3.0"},
            {"string": "__gxx_personality_v0"},
            {"string": "__cxa_finalize"},
            {"string": "__stack_chk_fail"},
        ]

    def get_sections(self) -> list[dict[str, Any]]:
        return [
            {"name": ".text", "vaddr": 0x1000, "vsize": 0x1000, "size": 0x1000, "flags": "rx"},
            {"name": ".eh_frame", "vaddr": 0x2000, "vsize": 0x200, "size": 0x200, "flags": "r"},
            {"name": ".eh_frame_hdr", "vaddr": 0x2200, "vsize": 0x100, "size": 0x100, "flags": "r"},
            {
                "name": ".gcc_except_table",
                "vaddr": 0x2300,
                "vsize": 0x50,
                "size": 0x50,
                "flags": "r",
            },
        ]

    def get_imports(self) -> list[dict[str, Any]]:
        return [
            {"name": "libc.so.6", "libname": "libc.so.6"},
            {"name": "libgcc_s.so", "libname": "libgcc_s.so"},
        ]

    def get_file_info(self) -> dict[str, Any]:
        return {"bin": {"class": "ELF64"}, "core": {"file": "/tmp/test.elf"}}


class MSVCImportsAdapter(MinimalAdapter):
    """Adapter that looks like an MSVC-compiled binary."""

    def get_imports(self) -> list[dict[str, Any]]:
        return [
            {"name": "VCRUNTIME140.dll", "libname": "VCRUNTIME140.dll"},
            {"name": "VCRUNTIME140_1.dll", "libname": "VCRUNTIME140_1.dll"},
            {"name": "MSVCR140.dll", "libname": "MSVCR140.dll"},
            {"name": "__CxxFrameHandler3", "libname": "vcruntime140.dll"},
        ]

    def get_strings(self) -> list[dict[str, Any]]:
        return [
            {"string": "VCRUNTIME140.dll"},
            {"string": "__security_cookie"},
            {"string": "__security_check_cookie"},
        ]

    def get_sections(self) -> list[dict[str, Any]]:
        return [
            {"name": ".text", "vaddr": 0x1000, "vsize": 0x1000, "size": 0x1000, "flags": "rx"},
            {"name": ".rdata", "vaddr": 0x2000, "vsize": 0x500, "size": 0x500, "flags": "r"},
            {"name": ".idata", "vaddr": 0x2500, "vsize": 0x200, "size": 0x200, "flags": "r"},
        ]

    def get_file_info(self) -> dict[str, Any]:
        return {"bin": {"class": "PE32"}, "core": {"file": "/tmp/test.exe"}}


class UPXPackedAdapter(MinimalAdapter):
    """Adapter that has UPX packer indicators."""

    def get_sections(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "UPX0",
                "vaddr": 0x1000,
                "vsize": 0x10000,
                "size": 0x10,
                "flags": "rwx",
            },
            {
                "name": "UPX1",
                "vaddr": 0x11000,
                "vsize": 0x5000,
                "size": 0x4000,
                "flags": "rwx",
            },
        ]

    def get_strings(self) -> list[dict[str, Any]]:
        return [
            {"string": "$Info: This file is packed with the UPX executable packer"},
            {"string": "UPX!"},
        ]

    def get_imports(self) -> list[dict[str, Any]]:
        # Packed files typically have very few imports
        return [{"name": "LoadLibraryA", "libname": "kernel32.dll"}]

    def read_bytes(self, addr: int, size: int) -> bytes:
        # High-entropy compressed data
        return bytes(i % 256 for i in range(size))

    def search_hex(self, pattern: str) -> str:
        # UPX magic bytes present
        if "555058" in pattern.upper() or "555058" in pattern:
            return "0x00001000 hit0_0"
        return ""


class AntiDebugAdapter(MinimalAdapter):
    """Adapter that mimics a binary using anti-debug APIs."""

    def get_imports(self) -> list[dict[str, Any]]:
        return [
            {"name": "IsDebuggerPresent", "libname": "kernel32.dll", "plt": 0x4010},
            {"name": "CheckRemoteDebuggerPresent", "libname": "kernel32.dll", "plt": 0x4020},
            {"name": "GetTickCount", "libname": "kernel32.dll", "plt": 0x4030},
            {"name": "VirtualAllocEx", "libname": "kernel32.dll", "plt": 0x4040},
            {"name": "WriteProcessMemory", "libname": "kernel32.dll", "plt": 0x4050},
            {"name": "CreateRemoteThread", "libname": "kernel32.dll", "plt": 0x4060},
        ]

    def get_strings(self) -> list[dict[str, Any]]:
        return [
            {"string": "VMware"},
            {"string": "VBoxGuest"},
            {"string": "cuckoo"},
        ]

    def search_text(self, pattern: str) -> str:
        if pattern == "rdtsc":
            return "0x401000\n0x401500\n0x402000\n0x403000\n0x404000\n0x405000"
        if pattern == "cpuid":
            return "0x401100"
        if pattern == "fs:[0x30]":
            return "0x401200"
        if pattern == "cc":
            return "\n".join(f"0x40{i:04x}" for i in range(10))
        return ""


# ---------------------------------------------------------------------------
# SectionAnalyzer tests
# ---------------------------------------------------------------------------


def test_section_analyzer_empty_sections() -> None:
    adapter = MinimalAdapter()
    analyzer = SectionAnalyzer(adapter=adapter)
    result = analyzer.analyze()
    assert result["total_sections"] == 0
    assert result["sections"] == []
    assert "summary" in result


def test_section_analyzer_pe_sections() -> None:
    adapter = PESectionsAdapter()
    analyzer = SectionAnalyzer(adapter=adapter)
    result = analyzer.analyze()
    assert result["total_sections"] == 2
    names = {s["name"] for s in result["sections"]}
    assert ".text" in names
    assert ".data" in names


def test_section_analyzer_executable_flag() -> None:
    adapter = PESectionsAdapter()
    analyzer = SectionAnalyzer(adapter=adapter)
    sections = analyzer.analyze_sections()
    text = next(s for s in sections if s["name"] == ".text")
    assert text["is_executable"] is True
    assert text["is_readable"] is True


def test_section_analyzer_writable_flag() -> None:
    adapter = PESectionsAdapter()
    analyzer = SectionAnalyzer(adapter=adapter)
    sections = analyzer.analyze_sections()
    data = next(s for s in sections if s["name"] == ".data")
    assert data["is_writable"] is True
    assert data["is_executable"] is False


def test_section_analyzer_size_ratio() -> None:
    adapter = SuspiciousSectionsAdapter()
    analyzer = SectionAnalyzer(adapter=adapter)
    sections = analyzer.analyze_sections()
    # upxsec: vsize=0x20000, raw=0x100 → ratio = 512
    upxsec = next(s for s in sections if s["name"] == "upxsec")
    assert upxsec["size_ratio"] > 10


def test_section_analyzer_suspicious_indicators_wx() -> None:
    adapter = SuspiciousSectionsAdapter()
    analyzer = SectionAnalyzer(adapter=adapter)
    sections = analyzer.analyze_sections()
    upxsec = next(s for s in sections if s["name"] == "upxsec")
    indicators = upxsec["suspicious_indicators"]
    assert any("Writable and executable" in ind for ind in indicators)


def test_section_analyzer_suspicious_name_indicator() -> None:
    adapter = SuspiciousSectionsAdapter()
    analyzer = SectionAnalyzer(adapter=adapter)
    sections = analyzer.analyze_sections()
    upxsec = next(s for s in sections if s["name"] == "upxsec")
    indicators = upxsec["suspicious_indicators"]
    # upxsec contains "upx" → suspicious packer name
    assert any("upx" in ind.lower() or "packer" in ind.lower() or "suspicious" in ind.lower() for ind in indicators)


def test_section_analyzer_summary_counts() -> None:
    adapter = PESectionsAdapter()
    analyzer = SectionAnalyzer(adapter=adapter)
    summary = analyzer.get_section_summary()
    assert summary["total_sections"] == 2
    assert summary["executable_sections"] >= 1
    assert summary["writable_sections"] >= 1
    assert isinstance(summary["avg_entropy"], float)


def test_section_analyzer_get_category_and_description() -> None:
    analyzer = SectionAnalyzer(adapter=MinimalAdapter())
    assert analyzer.get_category() == "metadata"
    assert "section" in analyzer.get_description().lower()


def test_section_analyzer_supports_format() -> None:
    analyzer = SectionAnalyzer(adapter=MinimalAdapter())
    assert analyzer.supports_format("PE") is True
    assert analyzer.supports_format("ELF") is True
    assert analyzer.supports_format("MACH0") is True
    assert analyzer.supports_format("UNKNOWN") is False


def test_section_analyzer_pe_characteristics_flags() -> None:
    adapter = PESectionsAdapter()
    analyzer = SectionAnalyzer(adapter=adapter)
    sections = analyzer.analyze_sections()
    text = next(s for s in sections if s["name"] == ".text")
    assert "IMAGE_SCN_CNT_CODE" in text["pe_characteristics"]
    assert "IMAGE_SCN_MEM_EXECUTE" in text["pe_characteristics"]


def test_section_analyzer_decode_pe_characteristics_zero() -> None:
    analyzer = SectionAnalyzer(adapter=MinimalAdapter())
    result = analyzer._decode_pe_characteristics(0)
    assert result == []


def test_section_analyzer_check_entropy_indicators_high() -> None:
    analyzer = SectionAnalyzer(adapter=MinimalAdapter())
    result = analyzer._check_entropy_indicators(7.8)
    assert any("High entropy" in ind for ind in result)


def test_section_analyzer_check_entropy_indicators_moderate() -> None:
    analyzer = SectionAnalyzer(adapter=MinimalAdapter())
    result = analyzer._check_entropy_indicators(7.2)
    assert any("Moderate" in ind for ind in result)


def test_section_analyzer_check_entropy_indicators_normal() -> None:
    analyzer = SectionAnalyzer(adapter=MinimalAdapter())
    result = analyzer._check_entropy_indicators(5.0)
    assert result == []


def test_section_analyzer_check_size_indicators_large_ratio() -> None:
    analyzer = SectionAnalyzer(adapter=MinimalAdapter())
    result = analyzer._check_size_indicators(vsize=50000, raw_size=100)
    assert any("ratio" in ind.lower() for ind in result)


def test_section_analyzer_check_size_indicators_very_small() -> None:
    analyzer = SectionAnalyzer(adapter=MinimalAdapter())
    result = analyzer._check_size_indicators(vsize=50, raw_size=50)
    assert any("small" in ind.lower() for ind in result)


def test_section_analyzer_check_size_indicators_very_large() -> None:
    analyzer = SectionAnalyzer(adapter=MinimalAdapter())
    result = analyzer._check_size_indicators(vsize=60_000_000, raw_size=60_000_000)
    assert any("large" in ind.lower() for ind in result)


def test_section_analyzer_nop_count_non_x86_arch() -> None:
    """Non-x86 arch should return (0, 0) for NOP counting."""

    class ARMAdapter(MinimalAdapter):
        def get_file_info(self) -> dict[str, Any]:
            return {"arch": "arm"}

    analyzer = SectionAnalyzer(adapter=ARMAdapter())
    nops, sample = analyzer._count_nops_in_section(0x1000, 1024)
    assert nops == 0
    assert sample == 0


def test_section_analyzer_nop_count_x86() -> None:
    class X86Adapter(MinimalAdapter):
        def get_file_info(self) -> dict[str, Any]:
            return {"arch": "x86"}

        def read_bytes(self, addr: int, size: int) -> bytes:
            return b"\x90" * size  # all NOPs

    analyzer = SectionAnalyzer(adapter=X86Adapter())
    nops, sample = analyzer._count_nops_in_section(0x1000, 64)
    assert nops == 64
    assert sample == 64


# ---------------------------------------------------------------------------
# CompilerDetector tests
# ---------------------------------------------------------------------------


def test_compiler_detector_empty_adapter() -> None:
    adapter = MinimalAdapter()
    detector = CompilerDetector(adapter=adapter)
    result = detector.detect_compiler()
    assert "compiler" in result
    assert "detected" in result
    assert "confidence" in result


def test_compiler_detector_unknown_when_no_evidence() -> None:
    adapter = MinimalAdapter()
    detector = CompilerDetector(adapter=adapter)
    result = detector.detect_compiler()
    # No strings, imports, sections → confidence too low to detect
    assert result["detected"] is False or result["confidence"] <= 0.3


def test_compiler_detector_gcc_strings() -> None:
    adapter = GCCStringsAdapter()
    detector = CompilerDetector(adapter=adapter)
    result = detector.detect_compiler()
    assert result["detected"] is True
    assert result["compiler"] == "GCC"
    assert result["confidence"] > 0.3


def test_compiler_detector_msvc_imports() -> None:
    adapter = MSVCImportsAdapter()
    detector = CompilerDetector(adapter=adapter)
    result = detector.detect_compiler()
    assert result["detected"] is True
    assert result["compiler"] == "MSVC"


def test_compiler_detector_get_strings_via_adapter() -> None:
    adapter = GCCStringsAdapter()
    detector = CompilerDetector(adapter=adapter)
    strings = detector._get_strings()
    assert isinstance(strings, list)
    assert any("GCC" in s for s in strings)


def test_compiler_detector_get_imports_via_adapter() -> None:
    adapter = MSVCImportsAdapter()
    detector = CompilerDetector(adapter=adapter)
    imports = detector._get_imports()
    assert isinstance(imports, list)
    assert len(imports) > 0


def test_compiler_detector_get_sections_via_adapter() -> None:
    adapter = PESectionsAdapter()
    detector = CompilerDetector(adapter=adapter)
    sections = detector._get_sections()
    assert isinstance(sections, list)
    assert ".text" in sections


def test_compiler_detector_get_symbols_via_adapter() -> None:
    class SymAdapter(MinimalAdapter):
        def get_symbols(self) -> list[dict[str, Any]]:
            return [{"name": "_main"}, {"name": "_foo"}]

    detector = CompilerDetector(adapter=SymAdapter())
    symbols = detector._get_symbols()
    assert "_main" in symbols


def test_compiler_detector_get_file_format_elf() -> None:
    adapter = GCCStringsAdapter()
    detector = CompilerDetector(adapter=adapter)
    fmt = detector._get_file_format()
    assert fmt == "ELF"


def test_compiler_detector_get_file_format_pe() -> None:
    adapter = MSVCImportsAdapter()
    detector = CompilerDetector(adapter=adapter)
    fmt = detector._get_file_format()
    assert fmt == "PE"


def test_compiler_detector_get_file_format_unknown() -> None:
    adapter = MinimalAdapter()
    detector = CompilerDetector(adapter=adapter)
    fmt = detector._get_file_format()
    assert fmt == "Unknown"


def test_compiler_detector_detect_version_unknown_compiler() -> None:
    adapter = MinimalAdapter()
    detector = CompilerDetector(adapter=adapter)
    version = detector._detect_compiler_version("FancyUnknownCompiler", [], [])
    assert version == "Unknown"


def test_compiler_detector_coerce_dict_list_with_dict() -> None:
    result = CompilerDetector._coerce_dict_list({"a": 1})
    assert result == [{"a": 1}]


def test_compiler_detector_coerce_dict_list_with_mixed_list() -> None:
    result = CompilerDetector._coerce_dict_list([{"a": 1}, "not-a-dict", 42])
    assert result == [{"a": 1}]


def test_compiler_detector_coerce_dict_list_invalid() -> None:
    assert CompilerDetector._coerce_dict_list(None) == []
    assert CompilerDetector._coerce_dict_list(42) == []


# ---------------------------------------------------------------------------
# PackerDetector tests
# ---------------------------------------------------------------------------


def _make_config() -> Any:
    return Config()


def test_packer_detector_requires_config() -> None:
    with pytest.raises(ValueError):
        PackerDetector(adapter=MinimalAdapter(), config=None)


def test_packer_detector_clean_binary() -> None:
    adapter = MinimalAdapter()
    detector = PackerDetector(adapter=adapter, config=_make_config())
    result = detector.detect()
    assert result["is_packed"] is False
    assert "entropy_analysis" in result
    assert "section_analysis" in result


def test_packer_detector_upx_packed() -> None:
    adapter = UPXPackedAdapter()
    detector = PackerDetector(adapter=adapter, config=_make_config())
    result = detector.detect()
    assert result["is_packed"] is True
    assert result["packer_type"] is not None
    assert result["confidence"] > 0.0


def test_packer_detector_section_analysis() -> None:
    adapter = UPXPackedAdapter()
    detector = PackerDetector(adapter=adapter, config=_make_config())
    section_result = detector._analyze_sections()
    assert section_result["section_count"] == 2
    assert section_result["writable_executable"] >= 1


def test_packer_detector_count_imports() -> None:
    adapter = UPXPackedAdapter()
    detector = PackerDetector(adapter=adapter, config=_make_config())
    count = detector._count_imports()
    assert count == 1


def test_packer_detector_count_imports_empty() -> None:
    adapter = MinimalAdapter()
    detector = PackerDetector(adapter=adapter, config=_make_config())
    assert detector._count_imports() == 0


def test_packer_detector_overlay_info_no_file_info() -> None:
    adapter = MinimalAdapter()
    detector = PackerDetector(adapter=adapter, config=_make_config())
    result = detector.get_overlay_info()
    assert result == {}


def test_packer_detector_overlay_info_with_data() -> None:
    class OverlayAdapter(MinimalAdapter):
        def get_file_info(self) -> dict[str, Any]:
            return {"bin": {"size": 0x10000}}

        def get_sections(self) -> list[dict[str, Any]]:
            return [{"vaddr": 0x1000, "size": 0x8000}]

    adapter = OverlayAdapter()
    detector = PackerDetector(adapter=adapter, config=_make_config())
    result = detector.get_overlay_info()
    assert "has_overlay" in result
    assert result["has_overlay"] is True
    assert result["overlay_size"] == 0x10000 - 0x9000


def test_packer_detector_entropy_threshold_from_config() -> None:
    config = _make_config()
    adapter = MinimalAdapter()
    detector = PackerDetector(adapter=adapter, config=config)
    assert detector.entropy_threshold == config.typed_config.packer.entropy_threshold


def test_packer_detector_heuristic_score() -> None:
    adapter = MinimalAdapter()
    detector = PackerDetector(adapter=adapter, config=_make_config())
    entropy_results = {"summary": {"high_entropy_ratio": 0.8}}
    section_results = {
        "suspicious_sections": [{"name": "x"}],
        "section_count": 2,
        "writable_executable": 1,
    }
    score = detector._calculate_heuristic_score(entropy_results, section_results)
    assert 0.0 <= score <= 1.0
    assert score > 0.5


def test_packer_detector_heuristic_score_empty() -> None:
    adapter = MinimalAdapter()
    detector = PackerDetector(adapter=adapter, config=_make_config())
    # Empty entropy + no suspicious sections + no wx, but section_count=0 (≤3) adds 0.2
    score = detector._calculate_heuristic_score({}, {"section_count": 10, "suspicious_sections": [], "writable_executable": 0})
    assert score == 0.0


# ---------------------------------------------------------------------------
# packer_helpers tests
# ---------------------------------------------------------------------------


_UPX_SIGS: dict[str, list[bytes]] = {
    "UPX": [b"UPX!", b"UPX0", b"UPX1"],
    "ASPack": [b"aPLib", b"ASPack"],
}


def test_find_packer_signature_found() -> None:
    def search_hex(hex_sig: str) -> str:
        if "555058" in hex_sig.upper():  # UPX! hex prefix
            return "0x1000 hit"
        return ""

    result = find_packer_signature(search_hex, _UPX_SIGS)
    assert result is not None
    assert result["type"] == "UPX"


def test_find_packer_signature_not_found() -> None:
    def search_hex(_hex_sig: str) -> str:
        return ""

    result = find_packer_signature(search_hex, _UPX_SIGS)
    assert result is None


def test_find_packer_string_found() -> None:
    strings = [{"string": "This binary uses UPX compression"}]
    result = find_packer_string(strings, _UPX_SIGS)
    assert result is not None
    assert result["type"] == "UPX"


def test_find_packer_string_not_found() -> None:
    strings = [{"string": "hello world"}]
    result = find_packer_string(strings, _UPX_SIGS)
    assert result is None


def test_find_packer_string_empty_list() -> None:
    assert find_packer_string([], _UPX_SIGS) is None
    assert find_packer_string(None, _UPX_SIGS) is None  # type: ignore[arg-type]


def test_analyze_entropy_no_sections() -> None:
    result = analyze_entropy(None, lambda a, s: b"", 7.0)
    assert result == {}
    result = analyze_entropy([], lambda a, s: b"", 7.0)
    assert result == {}


def test_analyze_entropy_sections_summary() -> None:
    sections = [
        {"name": ".text", "vaddr": 0x1000, "size": 256},
        {"name": ".data", "vaddr": 0x2000, "size": 256},
    ]

    def read_bytes(addr: int, size: int) -> bytes:
        if addr == 0x1000:
            return bytes(range(256))  # high entropy ~8.0
        return b"\x00" * size  # zero entropy

    result = analyze_entropy(sections, read_bytes, 7.0)
    assert "summary" in result
    assert result["summary"]["total_sections"] == 2
    assert result["summary"]["high_entropy_sections"] >= 1
    assert ".text" in result
    assert ".data" in result


def test_analyze_entropy_threshold_respected() -> None:
    sections = [{"name": ".sec", "vaddr": 0, "size": 256}]

    def read_bytes(addr: int, size: int) -> bytes:
        return bytes(range(256))

    # With very high threshold, nothing is "high entropy"
    result = analyze_entropy(sections, read_bytes, 9.0)
    assert result["summary"]["high_entropy_sections"] == 0

    # With threshold below the actual entropy, it should be flagged
    result2 = analyze_entropy(sections, read_bytes, 4.0)
    assert result2["summary"]["high_entropy_sections"] == 1


def test_analyze_sections_empty() -> None:
    result = analyze_sections(None)
    assert result["section_count"] == 0
    assert result["suspicious_sections"] == []

    result2 = analyze_sections([])
    assert result2["section_count"] == 0


def test_analyze_sections_wx_section() -> None:
    sections = [
        {"name": ".weird", "vaddr": 0x1000, "size": 0x1000, "flags": "rwx"},
    ]
    result = analyze_sections(sections)
    assert result["writable_executable"] == 1
    assert result["executable_sections"] == 1
    assert len(result["suspicious_sections"]) >= 1


def test_analyze_sections_suspicious_name() -> None:
    sections = [
        {"name": ".upx", "vaddr": 0x1000, "size": 0x1000, "flags": "r"},
    ]
    result = analyze_sections(sections)
    suspicious_names = [s["name"] for s in result["suspicious_sections"]]
    assert ".upx" in suspicious_names


def test_analyze_sections_small_section() -> None:
    sections = [
        {"name": ".tiny", "vaddr": 0x1000, "size": 10, "flags": "r"},
    ]
    result = analyze_sections(sections)
    reasons = [s["reason"] for s in result["suspicious_sections"]]
    assert any("small" in r.lower() for r in reasons)


def test_analyze_sections_large_section() -> None:
    sections = [
        {"name": ".blob", "vaddr": 0x1000, "size": 20_000_000, "flags": "r"},
    ]
    result = analyze_sections(sections)
    reasons = [s["reason"] for s in result["suspicious_sections"]]
    assert any("large" in r.lower() for r in reasons)


def test_count_imports_normal() -> None:
    imports = [{"name": "CreateFile"}, {"name": "ReadFile"}, {"name": "CloseHandle"}]
    assert count_imports(imports) == 3


def test_count_imports_empty() -> None:
    assert count_imports([]) == 0
    assert count_imports(None) == 0  # type: ignore[arg-type]


def test_overlay_info_no_file_info() -> None:
    assert overlay_info(None, []) == {}
    assert overlay_info({}, []) == {}


def test_overlay_info_no_bin_key() -> None:
    assert overlay_info({"core": {"file": "x"}}, []) == {}


def test_overlay_info_no_sections() -> None:
    file_info = {"bin": {"size": 0x10000}}
    assert overlay_info(file_info, None) == {}
    assert overlay_info(file_info, []) == {}


def test_overlay_info_has_overlay() -> None:
    file_info = {"bin": {"size": 0x10000}}
    sections = [{"vaddr": 0x1000, "size": 0x8000}]
    result = overlay_info(file_info, sections)
    assert result["has_overlay"] is True
    assert result["overlay_size"] == 0x10000 - 0x9000
    assert 0.0 < result["overlay_ratio"] < 1.0


def test_overlay_info_no_overlay() -> None:
    file_info = {"bin": {"size": 0x9000}}
    sections = [{"vaddr": 0x1000, "size": 0x8000}]
    result = overlay_info(file_info, sections)
    assert result["has_overlay"] is False
    assert result["overlay_size"] <= 0


# ---------------------------------------------------------------------------
# AntiAnalysisDetector tests
# ---------------------------------------------------------------------------


def test_anti_analysis_detect_returns_structure() -> None:
    adapter = MinimalAdapter()
    detector = AntiAnalysisDetector(adapter=adapter)
    result = detector.detect()
    assert "anti_debug" in result
    assert "anti_vm" in result
    assert "anti_sandbox" in result
    assert "evasion_techniques" in result
    assert "suspicious_apis" in result
    assert "timing_checks" in result
    assert "environment_checks" in result


def test_anti_analysis_no_indicators_clean() -> None:
    adapter = MinimalAdapter()
    detector = AntiAnalysisDetector(adapter=adapter)
    result = detector.detect()
    assert result["anti_debug"] is False
    assert result["anti_vm"] is False
    assert result["anti_sandbox"] is False
    assert result["timing_checks"] is False
    assert result["suspicious_apis"] == []


def test_anti_analysis_anti_debug_detected() -> None:
    adapter = AntiDebugAdapter()
    detector = AntiAnalysisDetector(adapter=adapter)
    result = detector.detect()
    assert result["anti_debug"] is True
    evidence = result["detection_details"]["anti_debug_evidence"]
    assert len(evidence) > 0
    types = [e["type"] for e in evidence]
    assert "API Call" in types


def test_anti_analysis_timing_checks_detected() -> None:
    adapter = AntiDebugAdapter()
    detector = AntiAnalysisDetector(adapter=adapter)
    result = detector.detect()
    assert result["timing_checks"] is True


def test_anti_analysis_anti_vm_detected() -> None:
    adapter = AntiDebugAdapter()
    detector = AntiAnalysisDetector(adapter=adapter)
    result = detector.detect()
    assert result["anti_vm"] is True
    vm_evidence = result["detection_details"]["anti_vm_evidence"]
    assert len(vm_evidence) > 0


def test_anti_analysis_suspicious_apis_found() -> None:
    adapter = AntiDebugAdapter()
    detector = AntiAnalysisDetector(adapter=adapter)
    result = detector.detect()
    assert len(result["suspicious_apis"]) > 0


def test_anti_analysis_evasion_techniques_injection() -> None:
    adapter = AntiDebugAdapter()
    detector = AntiAnalysisDetector(adapter=adapter)
    result = detector.detect()
    # WriteProcessMemory is in INJECTION_APIS, so evasion techniques should be non-empty
    assert isinstance(result["evasion_techniques"], list)
    assert len(result["evasion_techniques"]) >= 1


def test_anti_analysis_rdtsc_evidence() -> None:
    adapter = AntiDebugAdapter()
    detector = AntiAnalysisDetector(adapter=adapter)
    debug_result = detector._detect_anti_debug_detailed()
    types = [e["type"] for e in debug_result["evidence"]]
    assert "Timing Check" in types


def test_anti_analysis_peb_access_evidence() -> None:
    adapter = AntiDebugAdapter()
    detector = AntiAnalysisDetector(adapter=adapter)
    debug_result = detector._detect_anti_debug_detailed()
    types = [e["type"] for e in debug_result["evidence"]]
    assert "PEB Access" in types


def test_anti_analysis_breakpoint_detection_evidence() -> None:
    adapter = AntiDebugAdapter()
    detector = AntiAnalysisDetector(adapter=adapter)
    debug_result = detector._detect_anti_debug_detailed()
    types = [e["type"] for e in debug_result["evidence"]]
    assert "Breakpoint Detection" in types


def test_anti_analysis_get_imports_via_adapter() -> None:
    adapter = AntiDebugAdapter()
    detector = AntiAnalysisDetector(adapter=adapter)
    imports = detector._get_imports()
    assert any(i["name"] == "IsDebuggerPresent" for i in imports)


def test_anti_analysis_get_strings_via_adapter() -> None:
    adapter = AntiDebugAdapter()
    detector = AntiAnalysisDetector(adapter=adapter)
    strings = detector._get_strings()
    assert any(s.get("string") == "VMware" for s in strings)


def test_anti_analysis_search_opcode_delegates_to_adapter() -> None:
    adapter = AntiDebugAdapter()
    detector = AntiAnalysisDetector(adapter=adapter)
    result = detector._search_opcode("rdtsc")
    assert "0x401000" in result


def test_anti_analysis_environment_checks_empty() -> None:
    adapter = MinimalAdapter()
    detector = AntiAnalysisDetector(adapter=adapter)
    checks = detector._detect_environment_checks()
    assert isinstance(checks, list)
