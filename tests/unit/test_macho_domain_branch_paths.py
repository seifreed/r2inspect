"""Branch-path coverage for r2inspect/modules/macho_domain.py."""

from __future__ import annotations

import pytest

from r2inspect.modules.macho_domain import (
    build_load_commands,
    build_sections,
    dylib_timestamp_to_string,
    estimate_from_sdk_version,
    platform_from_version_min,
)


# ---------------------------------------------------------------------------
# estimate_from_sdk_version (lines 21-26)
# ---------------------------------------------------------------------------


def test_estimate_from_sdk_version_known_version_returns_label():
    result = estimate_from_sdk_version("macOS 13.0")
    assert result == "~2022 (SDK macOS 13.0)"


def test_estimate_from_sdk_version_another_known_version():
    result = estimate_from_sdk_version("10.15.4")
    assert result == "~2019 (SDK 10.15.4)"


def test_estimate_from_sdk_version_unknown_version_returns_none():
    result = estimate_from_sdk_version("9.0")
    assert result is None


def test_estimate_from_sdk_version_no_digits_returns_none():
    result = estimate_from_sdk_version("no-version-here")
    assert result is None


def test_estimate_from_sdk_version_all_known_sdk_keys():
    mapping = {
        "10.15": "2019",
        "11.0": "2020",
        "12.0": "2021",
        "13.0": "2022",
        "14.0": "2023",
        "15.0": "2024",
    }
    for sdk, year in mapping.items():
        result = estimate_from_sdk_version(sdk)
        assert result is not None
        assert year in result


# ---------------------------------------------------------------------------
# platform_from_version_min (lines 30-38)
# ---------------------------------------------------------------------------


def test_platform_from_version_min_macosx():
    assert platform_from_version_min("VERSION_MIN_MACOSX") == "macOS"


def test_platform_from_version_min_iphoneos():
    assert platform_from_version_min("VERSION_MIN_IPHONEOS") == "iOS"


def test_platform_from_version_min_tvos():
    assert platform_from_version_min("VERSION_MIN_TVOS") == "tvOS"


def test_platform_from_version_min_watchos():
    assert platform_from_version_min("VERSION_MIN_WATCHOS") == "watchOS"


def test_platform_from_version_min_unknown_returns_none():
    assert platform_from_version_min("UNKNOWN_LOAD_CMD") is None


def test_platform_from_version_min_empty_string_returns_none():
    assert platform_from_version_min("") is None


# ---------------------------------------------------------------------------
# dylib_timestamp_to_string (lines 42-48)
# ---------------------------------------------------------------------------


def test_dylib_timestamp_to_string_valid_timestamp():
    date_str, ts = dylib_timestamp_to_string(1000000000)
    assert date_str is not None
    assert ts == 1000000000
    assert "200" in date_str  # year 2001


def test_dylib_timestamp_to_string_zero_returns_none():
    date_str, ts = dylib_timestamp_to_string(0)
    assert date_str is None
    assert ts is None


def test_dylib_timestamp_to_string_negative_returns_none():
    date_str, ts = dylib_timestamp_to_string(-1)
    assert date_str is None
    assert ts is None


def test_dylib_timestamp_to_string_overflow_returns_none_and_ts():
    # Extremely large timestamp causes OverflowError in fromtimestamp
    huge_ts = 10**18
    date_str, ts = dylib_timestamp_to_string(huge_ts)
    assert date_str is None
    assert ts == huge_ts


def test_dylib_timestamp_to_string_recent_timestamp():
    # A timestamp for 2020-01-01
    ts_2020 = 1577836800
    date_str, ts = dylib_timestamp_to_string(ts_2020)
    assert date_str is not None
    assert "2020" in date_str
    assert ts == ts_2020


# ---------------------------------------------------------------------------
# build_load_commands (lines 52-60)
# ---------------------------------------------------------------------------


def test_build_load_commands_extracts_fields():
    headers = [
        {"type": "LC_SEGMENT_64", "size": 72, "offset": 0x40, "extra": "ignored"},
        {"type": "LC_DYLIB", "size": 56, "offset": 0x88},
    ]
    commands = build_load_commands(headers)
    assert len(commands) == 2
    assert commands[0]["type"] == "LC_SEGMENT_64"
    assert commands[0]["size"] == 72
    assert commands[0]["offset"] == 0x40
    assert commands[0]["data"] is headers[0]


def test_build_load_commands_defaults_for_missing_fields():
    headers = [{}]
    commands = build_load_commands(headers)
    assert commands[0]["type"] == "Unknown"
    assert commands[0]["size"] == 0
    assert commands[0]["offset"] == 0


def test_build_load_commands_empty_list():
    assert build_load_commands([]) == []


# ---------------------------------------------------------------------------
# build_sections (lines 64-74)
# ---------------------------------------------------------------------------


def test_build_sections_extracts_all_fields():
    sections = [
        {
            "name": "__text",
            "segment": "__TEXT",
            "type": "regular",
            "flags": "pure-instructions",
            "size": 4096,
            "vaddr": 0x100001000,
            "paddr": 0x1000,
        }
    ]
    result = build_sections(sections)
    assert len(result) == 1
    assert result[0]["name"] == "__text"
    assert result[0]["segment"] == "__TEXT"
    assert result[0]["size"] == 4096
    assert result[0]["vaddr"] == 0x100001000
    assert result[0]["paddr"] == 0x1000


def test_build_sections_defaults_for_missing_fields():
    result = build_sections([{}])
    assert result[0]["name"] == "Unknown"
    assert result[0]["segment"] == "Unknown"
    assert result[0]["type"] == "Unknown"
    assert result[0]["flags"] == ""
    assert result[0]["size"] == 0
    assert result[0]["vaddr"] == 0
    assert result[0]["paddr"] == 0


def test_build_sections_empty_list():
    assert build_sections([]) == []


def test_build_sections_multiple_sections():
    sections = [{"name": f"sec{i}"} for i in range(5)]
    result = build_sections(sections)
    assert len(result) == 5
    assert result[3]["name"] == "sec3"
