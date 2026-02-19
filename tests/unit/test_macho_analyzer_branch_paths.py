#!/usr/bin/env python3
"""Branch-path tests for r2inspect/modules/macho_analyzer.py - real objects only."""

from __future__ import annotations

from typing import Any

import pytest

from r2inspect.modules.macho_analyzer import MachOAnalyzer


# ---------------------------------------------------------------------------
# Real adapter classes - no mocks
# ---------------------------------------------------------------------------


class MinimalAdapter:
    """Adapter returning empty / minimal data for all methods."""

    def get_file_info(self) -> dict[str, Any]:
        return {}

    def get_headers_json(self) -> list[dict[str, Any]]:
        return []

    def get_sections(self) -> list[dict[str, Any]]:
        return []

    def get_symbols(self) -> list[dict[str, Any]]:
        return []


class FullInfoAdapter:
    """Adapter returning complete Mach-O header data."""

    def get_file_info(self) -> dict[str, Any]:
        return {
            "bin": {
                "arch": "arm64",
                "machine": "ARM64",
                "bits": 64,
                "endian": "little",
                "class": "MACH064",
                "format": "mach0",
                "baddr": 0x100000000,
                "cpu": "ARM_64",
                "filetype": "EXECUTE",
            }
        }

    def get_headers_json(self) -> list[dict[str, Any]]:
        return [
            {
                "type": "LC_BUILD_VERSION",
                "platform": "macOS",
                "minos": "10.15.0",
                "sdk": "11.0",
            },
            {
                "type": "LC_UUID",
                "uuid": "AABBCCDD-1122-3344-5566-778899AABBCC",
            },
            {
                "type": "LC_LOAD_DYLIB",
                "name": "/usr/lib/libSystem.B.dylib",
                "size": 56,
            },
        ]

    def get_sections(self) -> list[dict[str, Any]]:
        return [
            {"name": "__text", "segment": "__TEXT", "size": 4096, "vaddr": 0x100001000},
            {"name": "__data", "segment": "__DATA", "size": 256, "vaddr": 0x100002000},
        ]

    def get_symbols(self) -> list[dict[str, Any]]:
        return [
            {"name": "_printf"},
            {"name": "_objc_retain"},
        ]


class VersionMinAdapter:
    """Adapter with LC_VERSION_MIN_MACOSX load command."""

    def get_file_info(self) -> dict[str, Any]:
        return {"bin": {"arch": "x86_64", "bits": 64}}

    def get_headers_json(self) -> list[dict[str, Any]]:
        return [
            {
                "type": "LC_VERSION_MIN_MACOSX",
                "version": "10.14.0",
                "sdk": "10.15.0",
            }
        ]

    def get_sections(self) -> list[dict[str, Any]]:
        return []

    def get_symbols(self) -> list[dict[str, Any]]:
        return []


class DylibTimestampAdapter:
    """Adapter with LC_ID_DYLIB and a real timestamp."""

    def get_file_info(self) -> dict[str, Any]:
        return {"bin": {"arch": "x86_64", "bits": 64}}

    def get_headers_json(self) -> list[dict[str, Any]]:
        return [
            {
                "type": "LC_ID_DYLIB",
                "timestamp": 1609459200,  # 2021-01-01 00:00:00 UTC
                "name": "libFoo.dylib",
                "version": "1.0.0",
                "compatibility": "1.0.0",
            }
        ]

    def get_sections(self) -> list[dict[str, Any]]:
        return []

    def get_symbols(self) -> list[dict[str, Any]]:
        return []


class ZeroTimestampDylibAdapter:
    """Adapter with LC_ID_DYLIB that has timestamp=0."""

    def get_file_info(self) -> dict[str, Any]:
        return {}

    def get_headers_json(self) -> list[dict[str, Any]]:
        return [
            {
                "type": "LC_ID_DYLIB",
                "timestamp": 0,
                "name": "libFoo.dylib",
                "version": "1.0.0",
                "compatibility": "1.0.0",
            }
        ]

    def get_sections(self) -> list[dict[str, Any]]:
        return []

    def get_symbols(self) -> list[dict[str, Any]]:
        return []


class SDKVersionNoEstimateAdapter:
    """Adapter with LC_BUILD_VERSION that has no SDK estimate match."""

    def get_file_info(self) -> dict[str, Any]:
        return {}

    def get_headers_json(self) -> list[dict[str, Any]]:
        return [
            {
                "type": "LC_BUILD_VERSION",
                "platform": "iOS",
                "minos": "14.0",
                "sdk": "",  # Empty SDK - no estimate
            }
        ]

    def get_sections(self) -> list[dict[str, Any]]:
        return []

    def get_symbols(self) -> list[dict[str, Any]]:
        return []


class NonListSectionsAdapter:
    """Adapter whose get_sections returns None (non-list)."""

    def get_file_info(self) -> dict[str, Any]:
        return {}

    def get_headers_json(self) -> list[dict[str, Any]]:
        return []

    def get_sections(self):
        return None

    def get_symbols(self) -> list[dict[str, Any]]:
        return []


# ---------------------------------------------------------------------------
# get_category / get_description / supports_format (line 36)
# ---------------------------------------------------------------------------


def test_get_category_returns_format():
    analyzer = MachOAnalyzer(MinimalAdapter())
    assert analyzer.get_category() == "format"


def test_get_description_mentions_macho():
    analyzer = MachOAnalyzer(MinimalAdapter())
    assert "Mach-O" in analyzer.get_description()


def test_supports_format_mach0_uppercase():
    analyzer = MachOAnalyzer(MinimalAdapter())
    assert analyzer.supports_format("MACH0") is True


def test_supports_format_macho_uppercase():
    analyzer = MachOAnalyzer(MinimalAdapter())
    assert analyzer.supports_format("MACHO") is True


def test_supports_format_mach_hyphen_o():
    analyzer = MachOAnalyzer(MinimalAdapter())
    assert analyzer.supports_format("MACH-O") is True


def test_supports_format_mach064():
    analyzer = MachOAnalyzer(MinimalAdapter())
    assert analyzer.supports_format("MACH064") is True


def test_supports_format_lowercase_accepted():
    analyzer = MachOAnalyzer(MinimalAdapter())
    assert analyzer.supports_format("mach0") is True


def test_supports_format_pe_rejected():
    analyzer = MachOAnalyzer(MinimalAdapter())
    assert analyzer.supports_format("PE") is False


# ---------------------------------------------------------------------------
# _get_macho_headers (lines 95-96, 108, 113, 118, 123, 129-160)
# ---------------------------------------------------------------------------


def test_get_macho_headers_empty_response():
    analyzer = MachOAnalyzer(MinimalAdapter())
    result = analyzer._get_macho_headers()
    assert isinstance(result, dict)


def test_get_macho_headers_full_bin_info():
    analyzer = MachOAnalyzer(FullInfoAdapter())
    result = analyzer._get_macho_headers()
    assert result["architecture"] == "arm64"
    assert result["machine"] == "ARM64"
    assert result["bits"] == 64
    assert result["endian"] == "little"
    assert result["cpu_type"] == "ARM_64"
    assert result["file_type"] == "EXECUTE"
    assert result["entry_point"] == 0x100000000


def test_get_macho_headers_missing_bin_key_returns_empty():
    class NoBinAdapter(MinimalAdapter):
        def get_file_info(self):
            return {"something_else": {}}

    analyzer = MachOAnalyzer(NoBinAdapter())
    result = analyzer._get_macho_headers()
    assert result == {}


def test_get_macho_headers_defaults_for_missing_fields():
    class PartialBinAdapter(MinimalAdapter):
        def get_file_info(self):
            return {"bin": {"arch": "x86_64"}}

    analyzer = MachOAnalyzer(PartialBinAdapter())
    result = analyzer._get_macho_headers()
    assert result["architecture"] == "x86_64"
    assert result["bits"] == 0
    assert result["machine"] == "Unknown"


# ---------------------------------------------------------------------------
# _extract_build_version (lines 145-160)
# ---------------------------------------------------------------------------


def test_extract_build_version_with_lc_build_version():
    analyzer = MachOAnalyzer(FullInfoAdapter())
    result = analyzer._extract_build_version()
    assert result["platform"] == "macOS"
    assert result["min_os_version"] == "10.15.0"
    assert result["sdk_version"] == "11.0"
    assert result["sdk_version_info"] == "11.0"
    assert "compile_time" in result  # estimate from sdk 11.0 -> 2020


def test_extract_build_version_empty_sdk_no_estimate():
    analyzer = MachOAnalyzer(SDKVersionNoEstimateAdapter())
    result = analyzer._extract_build_version()
    assert result["platform"] == "iOS"
    assert "compile_time" not in result


def test_extract_build_version_no_lc_build_version_header():
    analyzer = MachOAnalyzer(VersionMinAdapter())
    result = analyzer._extract_build_version()
    assert result == {}


def test_extract_build_version_empty_headers():
    analyzer = MachOAnalyzer(MinimalAdapter())
    result = analyzer._extract_build_version()
    assert result == {}


# ---------------------------------------------------------------------------
# _extract_version_min (lines 175-187)
# ---------------------------------------------------------------------------


def test_extract_version_min_with_lc_version_min_macosx():
    analyzer = MachOAnalyzer(VersionMinAdapter())
    result = analyzer._extract_version_min()
    assert result["version_min_type"] == "LC_VERSION_MIN_MACOSX"
    assert result["min_version"] == "10.14.0"
    assert result["sdk_version"] == "10.15.0"
    assert result["platform"] == "macOS"


def test_extract_version_min_empty_headers():
    analyzer = MachOAnalyzer(MinimalAdapter())
    result = analyzer._extract_version_min()
    assert result == {}


def test_extract_version_min_no_matching_type():
    analyzer = MachOAnalyzer(FullInfoAdapter())
    # FullInfoAdapter has LC_BUILD_VERSION - no LC_VERSION_MIN_*
    result = analyzer._extract_version_min()
    assert result == {}


class IphoneVersionMinAdapter(MinimalAdapter):
    def get_headers_json(self):
        return [{"type": "LC_VERSION_MIN_IPHONEOS", "version": "14.0", "sdk": "14.5"}]


def test_extract_version_min_iphoneos_platform():
    analyzer = MachOAnalyzer(IphoneVersionMinAdapter())
    result = analyzer._extract_version_min()
    assert result["platform"] == "iOS"


class UnknownVersionMinAdapter(MinimalAdapter):
    def get_headers_json(self):
        return [{"type": "LC_VERSION_MIN_UNKNOWN_OS", "version": "1.0", "sdk": "1.0"}]


def test_extract_version_min_unknown_platform_not_in_result():
    analyzer = MachOAnalyzer(UnknownVersionMinAdapter())
    result = analyzer._extract_version_min()
    assert result["version_min_type"] == "LC_VERSION_MIN_UNKNOWN_OS"
    assert "platform" not in result


# ---------------------------------------------------------------------------
# _extract_dylib_info (lines 202-216)
# ---------------------------------------------------------------------------


def test_extract_dylib_info_with_timestamp():
    analyzer = MachOAnalyzer(DylibTimestampAdapter())
    result = analyzer._extract_dylib_info()
    assert "compile_time" in result
    assert result["dylib_name"] == "libFoo.dylib"
    assert result["dylib_version"] == "1.0.0"
    assert result["dylib_compatibility"] == "1.0.0"
    assert "dylib_timestamp" in result


def test_extract_dylib_info_zero_timestamp_no_compile_time():
    analyzer = MachOAnalyzer(ZeroTimestampDylibAdapter())
    result = analyzer._extract_dylib_info()
    assert "compile_time" not in result
    assert result["dylib_name"] == "libFoo.dylib"


def test_extract_dylib_info_empty_headers():
    analyzer = MachOAnalyzer(MinimalAdapter())
    result = analyzer._extract_dylib_info()
    assert result == {}


# ---------------------------------------------------------------------------
# _extract_uuid (lines 228-234)
# ---------------------------------------------------------------------------


def test_extract_uuid_with_lc_uuid():
    analyzer = MachOAnalyzer(FullInfoAdapter())
    result = analyzer._extract_uuid()
    assert result == "AABBCCDD-1122-3344-5566-778899AABBCC"


def test_extract_uuid_empty_headers_returns_none():
    analyzer = MachOAnalyzer(MinimalAdapter())
    result = analyzer._extract_uuid()
    assert result is None


class EmptyUuidAdapter(MinimalAdapter):
    def get_headers_json(self):
        return [{"type": "LC_UUID", "uuid": ""}]


def test_extract_uuid_empty_string_returns_none():
    analyzer = MachOAnalyzer(EmptyUuidAdapter())
    result = analyzer._extract_uuid()
    assert result is None


# ---------------------------------------------------------------------------
# _estimate_from_sdk_version (lines 240-246)
# ---------------------------------------------------------------------------


def test_estimate_from_sdk_version_known_version():
    analyzer = MachOAnalyzer(MinimalAdapter())
    result = analyzer._estimate_from_sdk_version("14.0")
    assert result is not None
    assert "2023" in result


def test_estimate_from_sdk_version_unknown_version_returns_none():
    analyzer = MachOAnalyzer(MinimalAdapter())
    result = analyzer._estimate_from_sdk_version("99.0")
    assert result is None


def test_estimate_from_sdk_version_empty_string_returns_none():
    analyzer = MachOAnalyzer(MinimalAdapter())
    result = analyzer._estimate_from_sdk_version("")
    assert result is None


# ---------------------------------------------------------------------------
# _estimate_compile_time (line 261)
# ---------------------------------------------------------------------------


def test_estimate_compile_time_returns_empty_string():
    analyzer = MachOAnalyzer(MinimalAdapter())
    result = analyzer._estimate_compile_time()
    assert result == ""


# ---------------------------------------------------------------------------
# _get_load_commands (lines 262, 274)
# ---------------------------------------------------------------------------


def test_get_load_commands_with_headers():
    analyzer = MachOAnalyzer(FullInfoAdapter())
    commands = analyzer._get_load_commands()
    assert isinstance(commands, list)
    assert len(commands) == 3  # 3 headers in FullInfoAdapter


def test_get_load_commands_empty_headers():
    analyzer = MachOAnalyzer(MinimalAdapter())
    commands = analyzer._get_load_commands()
    assert commands == []


# ---------------------------------------------------------------------------
# _get_section_info (lines 277-278)
# ---------------------------------------------------------------------------


def test_get_section_info_with_real_sections():
    analyzer = MachOAnalyzer(FullInfoAdapter())
    sections = analyzer._get_section_info()
    assert isinstance(sections, list)
    assert len(sections) == 2
    assert sections[0]["name"] == "__text"
    assert sections[1]["name"] == "__data"


def test_get_section_info_empty_sections():
    analyzer = MachOAnalyzer(MinimalAdapter())
    sections = analyzer._get_section_info()
    assert sections == []


def test_get_section_info_none_adapter():
    analyzer = MachOAnalyzer(MinimalAdapter())
    analyzer.adapter = None
    sections = analyzer._get_section_info()
    assert sections == []


def test_get_section_info_non_list_get_sections():
    analyzer = MachOAnalyzer(NonListSectionsAdapter())
    sections = analyzer._get_section_info()
    assert sections == []


# ---------------------------------------------------------------------------
# _get_compilation_info integration
# ---------------------------------------------------------------------------


def test_get_compilation_info_with_build_version():
    analyzer = MachOAnalyzer(FullInfoAdapter())
    result = analyzer._get_compilation_info()
    assert result["platform"] == "macOS"
    assert result["uuid"] == "AABBCCDD-1122-3344-5566-778899AABBCC"
    assert "compile_time" in result


def test_get_compilation_info_uses_estimate_when_no_compile_time():
    analyzer = MachOAnalyzer(MinimalAdapter())
    result = analyzer._get_compilation_info()
    # No compile time sources, so uses _estimate_compile_time -> ""
    assert result.get("compile_time") == ""


def test_get_compilation_info_with_version_min_adapter():
    analyzer = MachOAnalyzer(VersionMinAdapter())
    result = analyzer._get_compilation_info()
    assert result["platform"] == "macOS"


# ---------------------------------------------------------------------------
# get_security_features
# ---------------------------------------------------------------------------


def test_get_security_features_returns_dict():
    analyzer = MachOAnalyzer(FullInfoAdapter())
    features = analyzer.get_security_features()
    assert isinstance(features, dict)
    assert "pie" in features


def test_get_security_features_with_minimal_adapter():
    analyzer = MachOAnalyzer(MinimalAdapter())
    features = analyzer.get_security_features()
    assert isinstance(features, dict)


# ---------------------------------------------------------------------------
# analyze - full integration (lines 95-133)
# ---------------------------------------------------------------------------


def test_analyze_returns_dict_with_required_keys():
    analyzer = MachOAnalyzer(MinimalAdapter())
    result = analyzer.analyze()
    assert isinstance(result, dict)
    assert "load_commands" in result
    assert "sections" in result
    assert "security_features" in result


def test_analyze_full_adapter_populates_arch():
    analyzer = MachOAnalyzer(FullInfoAdapter())
    result = analyzer.analyze()
    assert result["architecture"] == "arm64"
    assert result["bits"] == 64


def test_analyze_full_adapter_populates_load_commands():
    analyzer = MachOAnalyzer(FullInfoAdapter())
    result = analyzer.analyze()
    assert len(result["load_commands"]) == 3


def test_analyze_full_adapter_populates_sections():
    analyzer = MachOAnalyzer(FullInfoAdapter())
    result = analyzer.analyze()
    assert len(result["sections"]) == 2


def test_analyze_populates_uuid():
    analyzer = MachOAnalyzer(FullInfoAdapter())
    result = analyzer.analyze()
    assert result.get("uuid") == "AABBCCDD-1122-3344-5566-778899AABBCC"
