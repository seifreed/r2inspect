#!/usr/bin/env python3
"""Tests targeting missing coverage branches in resource_analyzer.py."""
from __future__ import annotations

from typing import Any

from r2inspect.modules.resource_analyzer import ResourceAnalyzer


# ---------------------------------------------------------------------------
# Fake adapter helpers
# ---------------------------------------------------------------------------


class FakeAdapter:
    """Minimal adapter that returns preconfigured data for each command method."""

    def __init__(
        self,
        data_directories: Any = None,
        resources_info: Any = None,
        sections: Any = None,
        bytes_data: Any = None,
        raise_on: str | None = None,
    ) -> None:
        self._data_directories = data_directories
        self._resources_info = resources_info
        self._sections = sections
        self._bytes_data = bytes_data
        self._raise_on = raise_on

    def get_data_directories(self) -> Any:
        if self._raise_on == "get_data_directories":
            raise RuntimeError("forced error")
        return self._data_directories

    def get_resources_info(self) -> Any:
        if self._raise_on == "get_resources_info":
            raise RuntimeError("forced error")
        return self._resources_info

    def get_sections(self) -> Any:
        if self._raise_on == "get_sections":
            raise RuntimeError("forced error")
        return self._sections

    def read_bytes_list(self, address: int, size: int) -> Any:
        if self._raise_on == "read_bytes_list":
            raise RuntimeError("forced error")
        return self._bytes_data


def make_analyzer(**kwargs: Any) -> ResourceAnalyzer:
    return ResourceAnalyzer(adapter=FakeAdapter(**kwargs))


# ---------------------------------------------------------------------------
# _get_resource_directory – loop body, early returns, exception path
# ---------------------------------------------------------------------------


def test_get_resource_directory_returns_dict_when_resource_entry_found():
    analyzer = make_analyzer(
        data_directories=[{"name": "RESOURCE", "vaddr": 0x1000, "paddr": 0x800, "size": 512}]
    )
    result = analyzer._get_resource_directory()
    assert result is not None
    assert result["offset"] == 0x800
    assert result["size"] == 512
    assert result["virtual_address"] == 0x1000


def test_get_resource_directory_skips_non_resource_entries_then_finds_resource():
    analyzer = make_analyzer(
        data_directories=[
            {"name": "IMPORT", "vaddr": 0x2000, "paddr": 0x1500, "size": 100},
            {"name": "RESOURCE", "vaddr": 0x3000, "paddr": 0x2000, "size": 200},
        ]
    )
    result = analyzer._get_resource_directory()
    assert result is not None
    assert result["virtual_address"] == 0x3000


def test_get_resource_directory_returns_none_when_vaddr_is_zero():
    analyzer = make_analyzer(
        data_directories=[{"name": "RESOURCE", "vaddr": 0, "paddr": 0x800, "size": 200}]
    )
    assert analyzer._get_resource_directory() is None


def test_get_resource_directory_returns_none_when_entry_not_dict():
    analyzer = make_analyzer(data_directories=["not_a_dict", None])
    assert analyzer._get_resource_directory() is None


def test_get_resource_directory_returns_none_when_data_dirs_none():
    assert make_analyzer(data_directories=None)._get_resource_directory() is None


def test_get_resource_directory_exception_returns_none():
    analyzer = make_analyzer(raise_on="get_data_directories")
    assert analyzer._get_resource_directory() is None


# ---------------------------------------------------------------------------
# _parse_resources – loop body, entropy/hash branch, exception fallback
# ---------------------------------------------------------------------------


def test_parse_resources_returns_list_for_valid_resource_without_size():
    analyzer = make_analyzer(
        resources_info=[
            {
                "name": "ICON_1",
                "type": "RT_ICON",
                "type_id": 3,
                "lang": "en",
                "paddr": 0,
                "size": 0,
                "vaddr": 0,
            }
        ]
    )
    result = analyzer._parse_resources()
    assert len(result) == 1
    assert result[0]["type_name"] == "RT_ICON"


def test_parse_resources_skips_non_dict_entries():
    analyzer = make_analyzer(resources_info=["string_entry", None, 42])
    assert analyzer._parse_resources() == []


def test_parse_resources_returns_empty_for_none():
    assert make_analyzer(resources_info=None)._parse_resources() == []


def test_parse_resources_triggers_analyze_when_size_and_offset_nonzero():
    analyzer = make_analyzer(
        resources_info=[
            {
                "name": "RES1",
                "type": "RT_RCDATA",
                "type_id": 10,
                "lang": "en",
                "paddr": 0x1000,
                "size": 256,
                "vaddr": 0x2000,
            }
        ],
        bytes_data=list(range(256)),
    )
    result = analyzer._parse_resources()
    assert len(result) == 1
    assert result[0]["entropy"] > 0.0


def test_parse_resources_exception_falls_back_to_manual():
    analyzer = make_analyzer(
        raise_on="get_resources_info",
        sections=None,
    )
    result = analyzer._parse_resources()
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# _parse_resources_manual – various early-return branches
# ---------------------------------------------------------------------------


def test_parse_resources_manual_returns_empty_when_no_rsrc_section():
    assert make_analyzer(sections=[])._parse_resources_manual() == []


def test_parse_resources_manual_returns_empty_when_rsrc_offset_zero():
    analyzer = make_analyzer(sections=[{"name": ".rsrc", "paddr": 0, "size": 100}])
    assert analyzer._parse_resources_manual() == []


def test_parse_resources_manual_returns_empty_when_dir_header_too_short():
    analyzer = make_analyzer(
        sections=[{"name": ".rsrc", "paddr": 0x1000, "size": 100}],
        bytes_data=[1, 2, 3],
    )
    assert analyzer._parse_resources_manual() == []


def test_parse_resources_manual_returns_empty_when_sections_none():
    assert make_analyzer(sections=None)._parse_resources_manual() == []


def test_parse_resources_manual_exception_returns_empty():
    analyzer = make_analyzer(raise_on="get_sections")
    assert analyzer._parse_resources_manual() == []


def test_parse_resources_manual_parses_entries_when_header_valid():
    # Valid 16-byte dir header: named=0, id=1 → 1 entry
    header = [0] * 12 + [0, 0, 1, 0]

    class AdapterWithSequence:
        def __init__(self) -> None:
            self._calls = 0

        def get_sections(self) -> list:
            return [{"name": ".rsrc", "paddr": 0x1000, "size": 256}]

        def read_bytes_list(self, address: int, size: int) -> list:
            self._calls += 1
            if self._calls == 1:
                return header
            # entry data: type_id=3 (RT_ICON), offset=0x100
            return [3, 0, 0, 0, 0x00, 0x01, 0x00, 0x00]

    analyzer = ResourceAnalyzer(adapter=AdapterWithSequence())
    result = analyzer._parse_resources_manual()
    assert len(result) == 1
    assert result[0]["type_name"] == "RT_ICON"


# ---------------------------------------------------------------------------
# _get_rsrc_section
# ---------------------------------------------------------------------------


def test_get_rsrc_section_returns_section_when_found():
    analyzer = make_analyzer(
        sections=[
            {"name": ".text", "paddr": 0x400},
            {"name": ".rsrc", "paddr": 0x2000, "size": 512},
        ]
    )
    result = analyzer._get_rsrc_section()
    assert result is not None
    assert result["paddr"] == 0x2000


def test_get_rsrc_section_returns_none_when_not_found():
    analyzer = make_analyzer(sections=[{"name": ".text", "paddr": 0x400}])
    assert analyzer._get_rsrc_section() is None


def test_get_rsrc_section_returns_none_when_sections_not_list():
    analyzer = make_analyzer(sections={"not": "a list"})
    assert analyzer._get_rsrc_section() is None


# ---------------------------------------------------------------------------
# _is_valid_dir_header
# ---------------------------------------------------------------------------


def test_is_valid_dir_header_returns_false_for_none():
    assert make_analyzer()._is_valid_dir_header(None) is False


def test_is_valid_dir_header_returns_false_for_short_data():
    assert make_analyzer()._is_valid_dir_header([0] * 10) is False


def test_is_valid_dir_header_returns_true_for_16_bytes():
    assert make_analyzer()._is_valid_dir_header([0] * 16) is True


# ---------------------------------------------------------------------------
# _get_dir_total_entries
# ---------------------------------------------------------------------------


def test_get_dir_total_entries_sums_named_and_id_entries():
    data = [0] * 12 + [2, 0, 3, 0]
    assert make_analyzer()._get_dir_total_entries(data) == 5


def test_get_dir_total_entries_zero_entries():
    assert make_analyzer()._get_dir_total_entries([0] * 16) == 0


# ---------------------------------------------------------------------------
# _parse_dir_entries
# ---------------------------------------------------------------------------


def test_parse_dir_entries_returns_empty_when_total_is_zero():
    assert make_analyzer()._parse_dir_entries(0x1000, 0) == []


def test_parse_dir_entries_parses_one_valid_entry():
    analyzer = make_analyzer(bytes_data=[3, 0, 0, 0, 0x00, 0x01, 0, 0])
    result = analyzer._parse_dir_entries(0x1000, 1)
    assert len(result) == 1
    assert result[0]["type_name"] == "RT_ICON"


def test_parse_dir_entries_skips_invalid_entries():
    analyzer = make_analyzer(bytes_data=[0, 1])
    result = analyzer._parse_dir_entries(0x1000, 2)
    assert result == []


# ---------------------------------------------------------------------------
# _parse_dir_entry
# ---------------------------------------------------------------------------


def test_parse_dir_entry_returns_none_for_short_data():
    assert make_analyzer()._parse_dir_entry(0x1000, [0, 1, 2], 0) is None


def test_parse_dir_entry_returns_none_for_empty_data():
    assert make_analyzer()._parse_dir_entry(0x1000, [], 0) is None


def test_parse_dir_entry_named_resource_when_high_bit_set():
    entry = [0x00, 0x00, 0x00, 0x80, 0x00, 0x01, 0x00, 0x00]
    result = make_analyzer()._parse_dir_entry(0x1000, entry, 5)
    assert result is not None
    assert result["name"] == "Named_5"


def test_parse_dir_entry_returns_typed_resource_for_known_type_id():
    entry = [3, 0, 0, 0, 0x00, 0x01, 0x00, 0x00]
    result = make_analyzer()._parse_dir_entry(0x1000, entry, 0)
    assert result is not None
    assert result["type_name"] == "RT_ICON"
    assert result["type_id"] == 3


def test_parse_dir_entry_marks_directory_when_data_offset_high_bit_set():
    entry = [3, 0, 0, 0, 0x00, 0x00, 0x00, 0x80]
    result = make_analyzer()._parse_dir_entry(0x1000, entry, 0)
    assert result is not None
    assert result["is_directory"] is True


# ---------------------------------------------------------------------------
# _get_resource_type_name
# ---------------------------------------------------------------------------


def test_get_resource_type_name_returns_known_type():
    analyzer = make_analyzer()
    assert analyzer._get_resource_type_name(3) == "RT_ICON"
    assert analyzer._get_resource_type_name(24) == "RT_MANIFEST"


def test_get_resource_type_name_returns_unknown_for_unregistered_id():
    assert make_analyzer()._get_resource_type_name(999) == "UNKNOWN_999"


# ---------------------------------------------------------------------------
# _analyze_resource_data
# ---------------------------------------------------------------------------


def test_analyze_resource_data_skips_when_offset_zero():
    called = []

    class TrackingAdapter:
        def read_bytes_list(self, *args: Any) -> list:
            called.append(args)
            return []

    analyzer = ResourceAnalyzer(adapter=TrackingAdapter())
    resource: dict[str, Any] = {"offset": 0, "size": 100, "entropy": 0.0, "hashes": {}}
    analyzer._analyze_resource_data(resource)
    assert called == []
    assert resource["entropy"] == 0.0


def test_analyze_resource_data_skips_when_size_zero():
    called = []

    class TrackingAdapter:
        def read_bytes_list(self, *args: Any) -> list:
            called.append(args)
            return []

    analyzer = ResourceAnalyzer(adapter=TrackingAdapter())
    resource: dict[str, Any] = {"offset": 0x1000, "size": 0, "entropy": 0.0, "hashes": {}}
    analyzer._analyze_resource_data(resource)
    assert called == []


def test_analyze_resource_data_skips_when_data_empty():
    analyzer = make_analyzer(bytes_data=[])
    resource: dict[str, Any] = {"offset": 0x1000, "size": 100, "entropy": 0.0, "hashes": {}}
    analyzer._analyze_resource_data(resource)
    assert resource["entropy"] == 0.0


def test_analyze_resource_data_computes_entropy_and_hashes():
    analyzer = make_analyzer(bytes_data=list(range(256)) * 4)
    resource: dict[str, Any] = {"offset": 0x1000, "size": 1024, "entropy": 0.0, "hashes": {}}
    analyzer._analyze_resource_data(resource)
    assert resource["entropy"] > 0.0
    assert isinstance(resource["hashes"], dict)


# ---------------------------------------------------------------------------
# _calculate_entropy
# ---------------------------------------------------------------------------


def test_calculate_entropy_returns_zero_for_single_byte_value():
    assert make_analyzer()._calculate_entropy([0] * 100) == 0.0


def test_calculate_entropy_returns_eight_for_uniform_256_value_distribution():
    data = list(range(256)) * 4
    assert make_analyzer()._calculate_entropy(data) == 8.0


# ---------------------------------------------------------------------------
# _analyze_resource_types
# ---------------------------------------------------------------------------


def test_analyze_resource_types_counts_and_sizes_correctly():
    result: dict[str, Any] = {}
    resources = [
        {"type_name": "RT_ICON", "size": 100},
        {"type_name": "RT_ICON", "size": 200},
        {"type_name": "RT_STRING", "size": 50},
    ]
    make_analyzer()._analyze_resource_types(result, resources)
    assert result["total_size"] == 350
    types = {t["type"]: t for t in result["resource_types"]}
    assert types["RT_ICON"]["count"] == 2
    assert types["RT_ICON"]["total_size"] == 300
    assert types["RT_STRING"]["count"] == 1


def test_analyze_resource_types_handles_empty_list():
    result: dict[str, Any] = {}
    make_analyzer()._analyze_resource_types(result, [])
    assert result["total_size"] == 0
    assert result["resource_types"] == []


# ---------------------------------------------------------------------------
# _extract_version_info
# ---------------------------------------------------------------------------


def test_extract_version_info_no_rt_version_resource_leaves_result_unchanged():
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_ICON", "offset": 0x1000, "size": 100}]
    make_analyzer()._extract_version_info(result, resources)
    assert "version_info" not in result


def test_extract_version_info_skips_when_offset_zero():
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_VERSION", "offset": 0, "size": 512}]
    make_analyzer()._extract_version_info(result, resources)
    assert "version_info" not in result


# ---------------------------------------------------------------------------
# _parse_version_info
# ---------------------------------------------------------------------------


def test_parse_version_info_returns_none_when_offset_zero():
    assert make_analyzer()._parse_version_info(0, 512) is None


def test_parse_version_info_returns_none_when_size_below_64():
    assert make_analyzer()._parse_version_info(0x1000, 32) is None


def test_parse_version_info_returns_none_when_read_returns_empty():
    assert make_analyzer(bytes_data=None)._parse_version_info(0x1000, 512) is None


def test_parse_version_info_returns_none_when_no_strings_extractable():
    assert make_analyzer(bytes_data=[0xAA] * 128)._parse_version_info(0x1000, 512) is None


# ---------------------------------------------------------------------------
# _read_version_info_data
# ---------------------------------------------------------------------------


def test_read_version_info_data_returns_none_for_short_read():
    assert make_analyzer(bytes_data=[0] * 10)._read_version_info_data(0x1000, 512) is None


def test_read_version_info_data_returns_none_for_empty_read():
    assert make_analyzer(bytes_data=[])._read_version_info_data(0x1000, 512) is None


def test_read_version_info_data_returns_none_for_none_read():
    assert make_analyzer(bytes_data=None)._read_version_info_data(0x1000, 512) is None


def test_read_version_info_data_returns_list_when_data_sufficient():
    result = make_analyzer(bytes_data=[0xAB] * 100)._read_version_info_data(0x1000, 512)
    assert result is not None
    assert len(result) == 100


# ---------------------------------------------------------------------------
# _find_vs_signature / _find_pattern
# ---------------------------------------------------------------------------


def test_find_vs_signature_returns_negative_one_when_not_found():
    assert make_analyzer()._find_vs_signature([0x00] * 64) == -1


def test_find_vs_signature_returns_position_when_found():
    data = [0x00] * 20 + [0xBD, 0x04, 0xEF, 0xFE] + [0x00] * 40
    assert make_analyzer()._find_vs_signature(data) == 20


def test_find_pattern_returns_negative_one_when_not_found():
    assert make_analyzer()._find_pattern([1, 2, 3, 4], [5, 6]) == -1


def test_find_pattern_returns_zero_for_match_at_start():
    assert make_analyzer()._find_pattern([1, 2, 3], [1, 2]) == 0


def test_find_pattern_returns_index_for_match_in_middle():
    assert make_analyzer()._find_pattern([0, 0, 1, 2, 0], [1, 2]) == 2


# ---------------------------------------------------------------------------
# _parse_fixed_file_info
# ---------------------------------------------------------------------------


def test_parse_fixed_file_info_returns_empty_when_data_too_short():
    assert make_analyzer()._parse_fixed_file_info([0] * 10, 0) == ""


def test_parse_fixed_file_info_returns_version_string_for_valid_data():
    data = [0] * 52
    data[8] = 0x01
    data[10] = 0x05
    result = make_analyzer()._parse_fixed_file_info(data, 0)
    assert "." in result


# ---------------------------------------------------------------------------
# _read_version_string_value / _extract_version_strings
# ---------------------------------------------------------------------------


def test_read_version_string_value_returns_empty_when_key_not_found():
    data = [0x41, 0x42, 0x43, 0x44] * 20
    assert make_analyzer()._read_version_string_value(data, "CompanyName") == ""


def test_read_version_string_value_returns_empty_when_value_out_of_bounds():
    key = "Co"
    data = list(key.encode("utf-16le"))
    assert make_analyzer()._read_version_string_value(data, key) == ""


def test_extract_version_strings_returns_empty_dict_when_no_keys_match():
    assert make_analyzer()._extract_version_strings([0x00] * 256) == {}


def test_read_version_string_value_returns_string_type():
    key = "Co"
    key_bytes = list(key.encode("utf-16le"))
    hi_bytes = list("Hi".encode("utf-16le")) + [0, 0]
    data = [0x00] * 4 + key_bytes + [0x00] * 4 + hi_bytes + [0x00] * 10
    result = make_analyzer()._read_version_string_value(data, key)
    assert isinstance(result, str)


# ---------------------------------------------------------------------------
# _extract_manifest
# ---------------------------------------------------------------------------


def test_extract_manifest_skips_when_no_rt_manifest_resource():
    class TrackingAdapter:
        called = False

        def read_bytes_list(self, *args: Any) -> list:
            TrackingAdapter.called = True
            return []

    analyzer = ResourceAnalyzer(adapter=TrackingAdapter())
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_ICON", "offset": 0x1000, "size": 100}]
    analyzer._extract_manifest(result, resources)
    assert "manifest" not in result
    assert TrackingAdapter.called is False


def test_extract_manifest_stores_content_when_data_returned():
    xml = b'<?xml version="1.0"?><assembly></assembly>'
    analyzer = make_analyzer(bytes_data=list(xml))
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_MANIFEST", "offset": 0x1000, "size": len(xml)}]
    analyzer._extract_manifest(result, resources)
    assert "manifest" in result
    assert result["manifest"]["size"] == len(xml)


def test_extract_manifest_flags_requires_admin():
    xml = '<requestedExecutionLevel level="requireAdministrator"/>'
    # Encode as UTF-16LE so _read_resource_as_string returns the string with the keyword
    xml_bytes = list(xml.encode("utf-16le"))
    analyzer = make_analyzer(bytes_data=xml_bytes)
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_MANIFEST", "offset": 0x1000, "size": len(xml_bytes)}]
    analyzer._extract_manifest(result, resources)
    assert result["manifest"]["requires_admin"] is True


def test_extract_manifest_skips_when_read_returns_empty():
    analyzer = make_analyzer(bytes_data=[])
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_MANIFEST", "offset": 0x1000, "size": 50}]
    analyzer._extract_manifest(result, resources)
    assert "manifest" not in result


# ---------------------------------------------------------------------------
# _extract_icons
# ---------------------------------------------------------------------------


def test_extract_icons_returns_empty_list_when_no_icon_resources():
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_STRING", "size": 100, "offset": 0x1000, "entropy": 0.0}]
    make_analyzer()._extract_icons(result, resources)
    assert result["icons"] == []


def test_extract_icons_collects_rt_icon_and_rt_group_icon():
    result: dict[str, Any] = {}
    resources = [
        {"type_name": "RT_ICON", "size": 512, "offset": 0x1000, "entropy": 3.0},
        {"type_name": "RT_GROUP_ICON", "size": 128, "offset": 0x2000, "entropy": 2.0},
    ]
    make_analyzer()._extract_icons(result, resources)
    assert len(result["icons"]) == 2


def test_extract_icons_flags_high_entropy_icon_as_suspicious():
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_ICON", "size": 512, "offset": 0x1000, "entropy": 7.9}]
    make_analyzer()._extract_icons(result, resources)
    assert "suspicious" in result["icons"][0]


def test_extract_icons_does_not_flag_normal_entropy_icon():
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_ICON", "size": 512, "offset": 0x1000, "entropy": 4.0}]
    make_analyzer()._extract_icons(result, resources)
    assert "suspicious" not in result["icons"][0]


# ---------------------------------------------------------------------------
# _extract_strings
# ---------------------------------------------------------------------------


def test_extract_strings_returns_empty_list_when_no_rt_string_resource():
    class TrackingAdapter:
        called = False

        def read_bytes_list(self, *args: Any) -> list:
            TrackingAdapter.called = True
            return []

    analyzer = ResourceAnalyzer(adapter=TrackingAdapter())
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_ICON", "offset": 0x1000, "size": 100}]
    analyzer._extract_strings(result, resources)
    assert result["strings"] == []
    assert TrackingAdapter.called is False


def test_extract_strings_processes_rt_string_resource():
    analyzer = make_analyzer(bytes_data=list(b"hello\x00world\x00"))
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_STRING", "offset": 0x1000, "size": 12}]
    analyzer._extract_strings(result, resources)
    assert isinstance(result["strings"], list)


# ---------------------------------------------------------------------------
# _read_resource_as_string
# ---------------------------------------------------------------------------


def test_read_resource_as_string_returns_none_when_offset_zero():
    assert make_analyzer()._read_resource_as_string(0, 100) is None


def test_read_resource_as_string_returns_none_when_size_zero():
    assert make_analyzer()._read_resource_as_string(0x1000, 0) is None


def test_read_resource_as_string_returns_none_when_data_empty():
    assert make_analyzer(bytes_data=[])._read_resource_as_string(0x1000, 100) is None


def test_read_resource_as_string_returns_text_for_ascii_data():
    analyzer = make_analyzer(bytes_data=list(b"Hello World"))
    result = analyzer._read_resource_as_string(0x1000, 11)
    assert result is not None
    assert isinstance(result, str)


def test_read_resource_as_string_returns_text_for_utf16le_data():
    analyzer = make_analyzer(bytes_data=list("Test".encode("utf-16le")))
    result = analyzer._read_resource_as_string(0x1000, 8)
    assert result is not None


def test_read_resource_as_string_returns_none_on_exception():
    analyzer = make_analyzer(raise_on="read_bytes_list")
    assert analyzer._read_resource_as_string(0x1000, 100) is None


# ---------------------------------------------------------------------------
# _calculate_statistics
# ---------------------------------------------------------------------------


def test_calculate_statistics_returns_early_for_empty_resources():
    result: dict[str, Any] = {}
    make_analyzer()._calculate_statistics(result, [])
    assert "statistics" not in result


def test_calculate_statistics_computes_correct_values():
    result: dict[str, Any] = {}
    resources = [
        {"size": 100, "entropy": 3.0, "type_name": "RT_ICON"},
        {"size": 200, "entropy": 5.0, "type_name": "RT_ICON"},
        {"size": 0, "entropy": 0.0, "type_name": "RT_STRING"},
    ]
    make_analyzer()._calculate_statistics(result, resources)
    stats = result["statistics"]
    assert stats["total_resources"] == 3
    assert stats["total_size"] == 300
    assert stats["max_size"] == 200
    assert stats["min_size"] == 100
    assert stats["average_entropy"] == 4.0


def test_calculate_statistics_handles_all_zero_sizes_and_entropies():
    result: dict[str, Any] = {}
    resources = [{"size": 0, "entropy": 0.0, "type_name": "RT_STRING"}]
    make_analyzer()._calculate_statistics(result, resources)
    stats = result["statistics"]
    assert stats["average_size"] == 0
    assert stats["max_entropy"] == 0


# ---------------------------------------------------------------------------
# _check_suspicious_resources
# ---------------------------------------------------------------------------


def test_check_suspicious_resources_empty_for_normal_small_icon():
    analyzer = make_analyzer(bytes_data=[])
    result: dict[str, Any] = {}
    resources = [
        {"name": "RES1", "type_name": "RT_ICON", "size": 100, "entropy": 3.0, "offset": 0}
    ]
    analyzer._check_suspicious_resources(result, resources)
    assert result["suspicious_resources"] == []


# ---------------------------------------------------------------------------
# _check_resource_entropy
# ---------------------------------------------------------------------------


def test_check_resource_entropy_flags_high_entropy_non_icon():
    res = {"name": "DATA", "type_name": "RT_RCDATA", "size": 100, "entropy": 7.8}
    flags = make_analyzer()._check_resource_entropy(res)
    assert len(flags) == 1
    assert "entropy" in flags[0]["reason"].lower()


def test_check_resource_entropy_skips_rt_icon_even_with_high_entropy():
    res = {"name": "ICO", "type_name": "RT_ICON", "size": 100, "entropy": 7.9}
    assert make_analyzer()._check_resource_entropy(res) == []


def test_check_resource_entropy_skips_rt_bitmap_even_with_high_entropy():
    res = {"name": "BMP", "type_name": "RT_BITMAP", "size": 100, "entropy": 7.9}
    assert make_analyzer()._check_resource_entropy(res) == []


def test_check_resource_entropy_returns_empty_for_normal_entropy():
    res = {"name": "RES", "type_name": "RT_STRING", "size": 100, "entropy": 3.0}
    assert make_analyzer()._check_resource_entropy(res) == []


# ---------------------------------------------------------------------------
# _check_resource_size
# ---------------------------------------------------------------------------


def test_check_resource_size_flags_resource_over_1mb():
    res = {"name": "BIG", "type_name": "RT_RCDATA", "size": 2 * 1024 * 1024, "entropy": 3.0}
    flags = make_analyzer()._check_resource_size(res)
    assert len(flags) == 1
    assert "large" in flags[0]["reason"].lower()


def test_check_resource_size_returns_empty_for_normal_size():
    res = {"name": "SMALL", "type_name": "RT_STRING", "size": 100, "entropy": 3.0}
    assert make_analyzer()._check_resource_size(res) == []


# ---------------------------------------------------------------------------
# _check_resource_rcdata
# ---------------------------------------------------------------------------


def test_check_resource_rcdata_flags_large_rcdata():
    res = {"name": "DATA", "type_name": "RT_RCDATA", "size": 20480, "entropy": 3.0}
    flags = make_analyzer()._check_resource_rcdata(res)
    assert len(flags) == 1
    assert "RCDATA" in flags[0]["reason"]


def test_check_resource_rcdata_returns_empty_for_small_rcdata():
    res = {"name": "DATA", "type_name": "RT_RCDATA", "size": 100, "entropy": 3.0}
    assert make_analyzer()._check_resource_rcdata(res) == []


def test_check_resource_rcdata_returns_empty_for_non_rcdata_type():
    res = {"name": "ICO", "type_name": "RT_ICON", "size": 20480, "entropy": 3.0}
    assert make_analyzer()._check_resource_rcdata(res) == []


# ---------------------------------------------------------------------------
# _check_resource_embedded_pe
# ---------------------------------------------------------------------------


def test_check_resource_embedded_pe_flags_mz_header():
    analyzer = make_analyzer(bytes_data=[0x4D, 0x5A])
    res = {"name": "EMBED", "type_name": "RT_RCDATA", "size": 2048, "offset": 0x1000}
    flags = analyzer._check_resource_embedded_pe(res)
    assert len(flags) == 1
    assert "PE" in flags[0]["reason"]


def test_check_resource_embedded_pe_returns_empty_for_non_mz_header():
    analyzer = make_analyzer(bytes_data=[0x7F, 0x45])
    res = {"name": "EMBED", "type_name": "RT_RCDATA", "size": 2048, "offset": 0x1000}
    assert analyzer._check_resource_embedded_pe(res) == []


def test_check_resource_embedded_pe_returns_empty_for_non_rcdata_type():
    class TrackingAdapter:
        called = False

        def read_bytes_list(self, *args: Any) -> list:
            TrackingAdapter.called = True
            return []

    analyzer = ResourceAnalyzer(adapter=TrackingAdapter())
    res = {"name": "ICO", "type_name": "RT_ICON", "size": 2048, "offset": 0x1000}
    assert analyzer._check_resource_embedded_pe(res) == []
    assert TrackingAdapter.called is False


def test_check_resource_embedded_pe_returns_empty_when_header_data_too_short():
    analyzer = make_analyzer(bytes_data=[0x4D])
    res = {"name": "EMBED", "type_name": "RT_RCDATA", "size": 2048, "offset": 0x1000}
    assert analyzer._check_resource_embedded_pe(res) == []


def test_check_resource_embedded_pe_returns_empty_for_small_resource():
    class TrackingAdapter:
        called = False

        def read_bytes_list(self, *args: Any) -> list:
            TrackingAdapter.called = True
            return []

    analyzer = ResourceAnalyzer(adapter=TrackingAdapter())
    res = {"name": "EMBED", "type_name": "RT_RCDATA", "size": 100, "offset": 0x1000}
    assert analyzer._check_resource_embedded_pe(res) == []
    assert TrackingAdapter.called is False


def test_check_resource_embedded_pe_handles_unknown_type():
    analyzer = make_analyzer(bytes_data=[0x4D, 0x5A])
    res = {"name": "X", "type_name": "UNKNOWN", "size": 2048, "offset": 0x1000}
    flags = analyzer._check_resource_embedded_pe(res)
    assert len(flags) == 1
