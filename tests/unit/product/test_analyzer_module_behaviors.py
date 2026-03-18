from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from r2inspect.modules.compiler_detector import CompilerDetector
from r2inspect.modules.packer_detector import PackerDetector
from r2inspect.modules.packer_helpers import analyze_entropy, find_packer_signature
from r2inspect.modules.section_analyzer import SectionAnalyzer


class SectionAdapter:
    def get_sections(self) -> list[dict[str, Any]]:
        return [
            {
                "name": ".text",
                "vaddr": 0x1000,
                "vsize": 0x2000,
                "size": 0x2000,
                "flags": "rx",
                "perm": "rx",
                "characteristics": 0x03000020,
            },
            {
                "name": "upxsec",
                "vaddr": 0x3000,
                "vsize": 0x20000,
                "size": 0x100,
                "flags": "rwx",
                "perm": "rwx",
                "characteristics": 0,
            },
        ]

    def read_bytes(self, addr: int, size: int) -> bytes:
        if addr == 0x1000:
            return (bytes(range(256)) * ((size // 256) + 1))[:size]
        return b"\xcc" * size

    def get_file_info(self) -> dict[str, Any]:
        return {"arch": "x86"}

    def cmdj(self, _cmd: str) -> list[dict[str, Any]]:
        return []


class CompilerAdapter:
    def get_strings(self) -> list[dict[str, Any]]:
        return [
            {"string": "GCC: (GNU) 11.3.0"},
            {"string": "__gxx_personality_v0"},
            {"string": "__stack_chk_fail"},
        ]

    def get_sections(self) -> list[dict[str, Any]]:
        return [
            {"name": ".text"},
            {"name": ".eh_frame"},
            {"name": ".gcc_except_table"},
        ]

    def get_imports(self) -> list[dict[str, Any]]:
        return [
            {"name": "libc.so.6", "libname": "libc.so.6"},
            {"name": "libgcc_s.so", "libname": "libgcc_s.so"},
        ]

    def get_symbols(self) -> list[dict[str, Any]]:
        return []

    def get_file_info(self) -> dict[str, Any]:
        return {"bin": {"class": "ELF64"}, "core": {"file": "/tmp/test.elf"}}

    def cmd(self, _cmd: str) -> str:
        return ""


class PackerAdapter:
    def get_sections(self) -> list[dict[str, Any]]:
        return [
            {"name": "UPX0", "vaddr": 0x1000, "vsize": 0x10000, "size": 0x10, "flags": "rwx"},
            {"name": "UPX1", "vaddr": 0x11000, "vsize": 0x5000, "size": 0x4000, "flags": "rwx"},
        ]

    def get_strings(self) -> list[dict[str, Any]]:
        return [{"string": "$Info: This file is packed with the UPX executable packer"}]

    def get_imports(self) -> list[dict[str, Any]]:
        return [{"name": "LoadLibraryA", "libname": "kernel32.dll"}]

    def read_bytes(self, _addr: int, size: int) -> bytes:
        return bytes(i % 256 for i in range(size))

    def search_hex(self, pattern: str) -> str:
        return "0x00001000 hit0_0" if "555058" in pattern.upper() else ""

    def search_text(self, _pattern: str) -> str:
        return ""

    def get_file_info(self) -> dict[str, Any]:
        return {}

    def cmd(self, _cmd: str) -> str:
        return ""

    def cmdj(self, _cmd: str) -> list[dict[str, Any]]:
        return []


def _packer_config() -> Any:
    return SimpleNamespace(
        typed_config=SimpleNamespace(packer=SimpleNamespace(entropy_threshold=7.0))
    )


def test_section_analyzer_reports_suspicious_sections_and_summary() -> None:
    analyzer = SectionAnalyzer(adapter=SectionAdapter())
    result = analyzer.analyze()

    assert result["total_sections"] == 2
    suspicious = next(item for item in result["sections"] if item["name"] == "upxsec")
    assert suspicious["size_ratio"] > 10
    assert any("Writable and executable" in value for value in suspicious["suspicious_indicators"])
    assert result["summary"]["suspicious_sections"] >= 1


def test_compiler_detector_identifies_gcc_like_binary() -> None:
    result = CompilerDetector(adapter=CompilerAdapter()).detect_compiler()
    assert result["detected"] is True
    assert result["compiler"] == "GCC"
    assert result["confidence"] > 0


def test_packer_detector_and_helpers_report_upx_like_indicators() -> None:
    detector = PackerDetector(adapter=PackerAdapter(), config=_packer_config())
    result = detector.detect()

    assert result["is_packed"] is True
    assert result["packer_type"] == "UPX"
    assert any("Packer signature" in item for item in result["indicators"])

    signature = find_packer_signature(lambda _hex: "hit", {"UPX": [b"UPX!"]})
    entropy = analyze_entropy(
        [{"name": "UPX0", "vaddr": 0x1000, "size": 0x100}],
        lambda _addr, size: bytes(range(256))[:size],
        7.0,
    )
    assert signature == {"type": "UPX", "signature": "UPX!"}
    assert entropy["summary"]["total_sections"] == 1
