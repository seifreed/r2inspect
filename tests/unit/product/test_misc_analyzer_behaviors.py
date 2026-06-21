from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from r2inspect.modules.anti_analysis import AntiAnalysisDetector
from r2inspect.modules.export_analyzer import ExportAnalyzer
from r2inspect.modules.macho_analyzer import MachOAnalyzer


class MinimalAdapter:
    def get_imports(self) -> list[dict[str, Any]]:
        return []

    def get_strings(self) -> list[dict[str, Any]]:
        return []

    def get_strings_filtered(self, _command: str) -> str:
        return ""

    def search_text(self, _pattern: str) -> str:
        return ""

    def search_hex(self, _pattern: str) -> str:
        return ""

    def cmd(self, _command: str) -> str:
        return ""

    def cmdj(self, _command: str) -> Any:
        return []

    def get_exports(self) -> list[dict[str, Any]]:
        return []

    def get_sections(self) -> list[dict[str, Any]]:
        return []


class BrokenImportsAdapter(MinimalAdapter):
    def get_imports(self) -> list[dict[str, Any]]:
        raise RuntimeError("imports failed")


class ExportAdapter(MinimalAdapter):
    def get_exports(self) -> list[dict[str, Any]]:
        return [
            {"name": "DllMain", "vaddr": 0x1000, "ordinal": 1, "type": "func", "size": 80},
            {"name": "execute_payload", "vaddr": 0x2000, "ordinal": 2, "type": "func", "size": 120},
        ]

    def cmdj(self, command: str) -> Any:
        if command.startswith("afij"):
            return [{"size": 64, "cc": 2}]
        return []


def test_anti_analysis_detector_falls_back_to_safe_error_shapes() -> None:
    detector = AntiAnalysisDetector(BrokenImportsAdapter())

    anti_debug = detector._detect_anti_debug_detailed()
    suspicious = detector._find_suspicious_apis()
    timing = detector._detect_timing_checks_detailed()

    assert anti_debug["detected"] is False
    assert anti_debug["evidence"][0]["type"] == "Error"
    assert suspicious == []
    assert timing["detected"] is False


def test_export_analyzer_reports_suspicious_exports_and_statistics() -> None:
    analyzer = ExportAnalyzer(ExportAdapter())

    result = analyzer.analyze()

    assert result["total_exports"] == 2
    assert result["statistics"]["suspicious_exports"] >= 1
    assert "execute_payload" in result["statistics"]["export_names"]
    assert any(item["characteristics"].get("suspicious_name") for item in result["exports"])


def test_macho_analyzer_collects_dylib_compilation_info_and_tolerates_bad_headers() -> None:
    dylib_header = {
        "name": "load_command_0_LC_ID_DYLIB",
        "pf": [
            {"name": "cmd", "label": "LC_ID_DYLIB"},
            {
                "name": "dylib",
                "value": [
                    {"name": "timestamp", "value": 1234567890},
                    {"name": "current_version", "value": 1 << 16},
                    {"name": "compatibility_version", "value": 1 << 16},
                    {"name": "name", "value": "libfoo.dylib"},
                ],
            },
        ],
    }
    with_dylib = MachOAnalyzer(MinimalAdapter(), headers_provider=lambda _adapter: [dylib_header])
    info = with_dylib._get_compilation_info()
    assert info["dylib_name"] == "libfoo.dylib"

    with_bad_headers = MachOAnalyzer(MinimalAdapter(), headers_provider=lambda _adapter: [None])
    assert isinstance(with_bad_headers._extract_dylib_info(), dict)
    assert with_bad_headers._get_load_commands() == []
