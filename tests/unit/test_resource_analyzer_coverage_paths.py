from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

from r2inspect.modules.resource_analyzer import ResourceAnalyzer


def test_resource_analyzer_init() -> None:
    adapter = MagicMock()
    analyzer = ResourceAnalyzer(adapter=adapter)
    assert analyzer.adapter == adapter


def test_resource_analyzer_get_resource_directory_none() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = None

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._get_resource_directory()
    assert result is None


def test_resource_analyzer_get_resource_directory_not_list() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = {"not": "a list"}

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._get_resource_directory()
    assert result is None


def test_resource_analyzer_get_resource_directory_no_resource() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = [{"name": "OTHER", "vaddr": 100, "size": 200}]

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._get_resource_directory()
    assert result is None


def test_resource_analyzer_get_resource_directory_resource_zero_vaddr() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = [{"name": "RESOURCE", "vaddr": 0, "size": 200, "paddr": 100}]

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._get_resource_directory()
    assert result is None


def test_resource_analyzer_get_resource_directory_valid() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = [
        {"name": "RESOURCE", "vaddr": 0x1000, "size": 500, "paddr": 0x800}
    ]

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._get_resource_directory()
    assert result is not None
    assert result["offset"] == 0x800
    assert result["size"] == 500
    assert result["virtual_address"] == 0x1000


def test_resource_analyzer_get_resource_directory_exception() -> None:
    adapter = MagicMock()
    adapter.cmdj.side_effect = Exception("Test error")

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._get_resource_directory()
    assert result is None


def test_resource_analyzer_parse_resources_empty() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = []

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._parse_resources()
    assert result == []


def test_resource_analyzer_parse_resources_none() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = None

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._parse_resources()
    assert result == []


def test_resource_analyzer_parse_resources_not_dict() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = ["not a dict", 123, None]

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._parse_resources()
    assert result == []


def test_resource_analyzer_parse_resources_valid() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = [
        {
            "name": "test.ico",
            "type": "RT_ICON",
            "type_id": 3,
            "lang": "en-US",
            "paddr": 0x1000,
            "size": 256,
            "vaddr": 0x2000,
        }
    ]

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._parse_resources()
    assert len(result) == 1
    assert result[0]["name"] == "test.ico"
    assert result[0]["type_name"] == "RT_ICON"


def test_resource_analyzer_parse_resources_zero_offset() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = [
        {
            "name": "test",
            "type": "RT_STRING",
            "type_id": 6,
            "lang": "en-US",
            "paddr": 0,
            "size": 100,
            "vaddr": 0x2000,
        }
    ]

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._parse_resources()
    assert len(result) == 1
    assert result[0]["entropy"] == 0.0


def test_resource_analyzer_parse_resources_exception() -> None:
    adapter = MagicMock()
    adapter.cmdj.side_effect = Exception("Test error")

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._parse_resources()
    assert result == []


def test_resource_analyzer_parse_resources_manual_no_rsrc() -> None:
    adapter = MagicMock()
    adapter.cmdj.side_effect = [Exception("iRj error"), []]

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._parse_resources()
    assert result == []


def test_resource_analyzer_get_rsrc_section_none() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = None

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._get_rsrc_section()
    assert result is None


def test_resource_analyzer_get_rsrc_section_not_list() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = {"not": "a list"}

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._get_rsrc_section()
    assert result is None


def test_resource_analyzer_get_rsrc_section_no_rsrc() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = [{"name": ".text"}, {"name": ".data"}]

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._get_rsrc_section()
    assert result is None


def test_resource_analyzer_get_rsrc_section_found() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = [
        {"name": ".text"},
        {"name": ".rsrc", "paddr": 0x1000, "size": 500},
    ]

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._get_rsrc_section()
    assert result is not None
    assert result["name"] == ".rsrc"


def test_resource_analyzer_is_valid_dir_header_none() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    assert analyzer._is_valid_dir_header(None) is False


def test_resource_analyzer_is_valid_dir_header_too_short() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    assert analyzer._is_valid_dir_header([0] * 10) is False


def test_resource_analyzer_is_valid_dir_header_valid() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    assert analyzer._is_valid_dir_header([0] * 16) is True


def test_resource_analyzer_get_dir_total_entries() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    dir_data = [0] * 12 + [2, 0, 3, 0]
    result = analyzer._get_dir_total_entries(dir_data)
    assert result == 5


def test_resource_analyzer_parse_dir_entries_empty() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = []

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._parse_dir_entries(0x1000, 0)
    assert result == []


def test_resource_analyzer_parse_dir_entries_limit() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = [0] * 8

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._parse_dir_entries(0x1000, 30)
    assert len(result) <= 20


def test_resource_analyzer_parse_dir_entry_none() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    result = analyzer._parse_dir_entry(0x1000, None, 0)
    assert result is None


def test_resource_analyzer_parse_dir_entry_too_short() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    result = analyzer._parse_dir_entry(0x1000, [0] * 4, 0)
    assert result is None


def test_resource_analyzer_parse_dir_entry_named() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    entry_data = [0, 0, 0, 0x80, 0, 0, 0, 0]
    result = analyzer._parse_dir_entry(0x1000, entry_data, 5)
    assert result is not None
    assert "Named_5" in result["name"]


def test_resource_analyzer_parse_dir_entry_with_type() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    entry_data = [3, 0, 0, 0, 0, 0, 0, 0]
    result = analyzer._parse_dir_entry(0x1000, entry_data, 0)
    assert result is not None
    assert result["type_name"] == "RT_ICON"


def test_resource_analyzer_parse_dir_entry_is_directory() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    entry_data = [3, 0, 0, 0, 0, 0, 0, 0x80]
    result = analyzer._parse_dir_entry(0x1000, entry_data, 0)
    assert result is not None
    assert result["is_directory"] is True


def test_resource_analyzer_get_resource_type_name_known() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    assert analyzer._get_resource_type_name(1) == "RT_CURSOR"
    assert analyzer._get_resource_type_name(2) == "RT_BITMAP"
    assert analyzer._get_resource_type_name(3) == "RT_ICON"


def test_resource_analyzer_get_resource_type_name_unknown() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    assert analyzer._get_resource_type_name(9999) == "UNKNOWN_9999"


def test_resource_analyzer_analyze_resource_data_zero_offset() -> None:
    adapter = MagicMock()
    analyzer = ResourceAnalyzer(adapter=adapter)

    resource = {"offset": 0, "size": 100}
    analyzer._analyze_resource_data(resource)
    assert resource["entropy"] == 0.0


def test_resource_analyzer_analyze_resource_data_zero_size() -> None:
    adapter = MagicMock()
    analyzer = ResourceAnalyzer(adapter=adapter)

    resource = {"offset": 0x1000, "size": 0}
    analyzer._analyze_resource_data(resource)
    assert resource["entropy"] == 0.0


def test_resource_analyzer_analyze_resource_data_no_data() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = None

    analyzer = ResourceAnalyzer(adapter=adapter)
    resource = {"offset": 0x1000, "size": 100}
    analyzer._analyze_resource_data(resource)
    assert resource["entropy"] == 0.0


def test_resource_analyzer_analyze_resource_data_valid() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = [ord("a")] * 100

    analyzer = ResourceAnalyzer(adapter=adapter)
    resource = {"offset": 0x1000, "size": 100}
    analyzer._analyze_resource_data(resource)
    assert resource["entropy"] > 0


def test_resource_analyzer_analyze_resource_data_hash_error() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = [300, 400]

    analyzer = ResourceAnalyzer(adapter=adapter)
    resource = {"offset": 0x1000, "size": 2}
    analyzer._analyze_resource_data(resource)
    assert resource["hashes"] == {}


def test_resource_analyzer_analyze_resource_data_exception() -> None:
    adapter = MagicMock()
    adapter.cmdj.side_effect = Exception("Test error")

    analyzer = ResourceAnalyzer(adapter=adapter)
    resource = {"offset": 0x1000, "size": 100}
    analyzer._analyze_resource_data(resource)


def test_resource_analyzer_calculate_entropy() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    data = [0] * 100
    entropy = analyzer._calculate_entropy(data)
    assert entropy == 0.0


def test_resource_analyzer_calculate_entropy_mixed() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    data = list(range(256))
    entropy = analyzer._calculate_entropy(data)
    assert entropy > 0


def test_resource_analyzer_analyze_resource_types_empty() -> None:
    adapter = MagicMock()
    analyzer = ResourceAnalyzer(adapter=adapter)

    result: dict[str, Any] = {}
    analyzer._analyze_resource_types(result, [])
    assert result["resource_types"] == []
    assert result["total_size"] == 0


def test_resource_analyzer_analyze_resource_types_valid() -> None:
    adapter = MagicMock()
    analyzer = ResourceAnalyzer(adapter=adapter)

    resources = [
        {"type_name": "RT_ICON", "size": 100},
        {"type_name": "RT_ICON", "size": 200},
        {"type_name": "RT_MANIFEST", "size": 50},
    ]

    result: dict[str, Any] = {}
    analyzer._analyze_resource_types(result, resources)
    assert len(result["resource_types"]) == 2
    assert result["total_size"] == 350


def test_resource_analyzer_extract_version_info_no_version() -> None:
    adapter = MagicMock()
    analyzer = ResourceAnalyzer(adapter=adapter)

    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_ICON", "offset": 0x1000, "size": 100}]
    analyzer._extract_version_info(result, resources)
    assert "version_info" not in result


def test_resource_analyzer_extract_version_info_exception() -> None:
    adapter = MagicMock()
    adapter.cmdj.side_effect = Exception("Test error")

    analyzer = ResourceAnalyzer(adapter=adapter)
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_VERSION", "offset": 0x1000, "size": 100}]
    analyzer._extract_version_info(result, resources)


def test_resource_analyzer_parse_version_info_zero_offset() -> None:
    adapter = MagicMock()
    analyzer = ResourceAnalyzer(adapter=adapter)

    result = analyzer._parse_version_info(0, 100)
    assert result is None


def test_resource_analyzer_parse_version_info_small_size() -> None:
    adapter = MagicMock()
    analyzer = ResourceAnalyzer(adapter=adapter)

    result = analyzer._parse_version_info(0x1000, 50)
    assert result is None


def test_resource_analyzer_parse_version_info_no_data() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = None

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._parse_version_info(0x1000, 100)
    assert result is None


def test_resource_analyzer_parse_version_info_no_strings() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = [0] * 100

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._parse_version_info(0x1000, 100)
    assert result is None


def test_resource_analyzer_parse_version_info_exception() -> None:
    adapter = MagicMock()
    adapter.cmdj.side_effect = Exception("Test error")

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._parse_version_info(0x1000, 100)
    assert result is None


def test_resource_analyzer_read_version_info_data_none() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = None

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._read_version_info_data(0x1000, 100)
    assert result is None


def test_resource_analyzer_read_version_info_data_too_small() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = [0] * 50

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._read_version_info_data(0x1000, 100)
    assert result is None


def test_resource_analyzer_read_version_info_data_valid() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = [0] * 100

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._read_version_info_data(0x1000, 100)
    assert result is not None
    assert len(result) == 100


def test_resource_analyzer_find_vs_signature() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    data = [0] * 50 + [0xBD, 0x04, 0xEF, 0xFE] + [0] * 50
    result = analyzer._find_vs_signature(data)
    assert result == 50


def test_resource_analyzer_find_vs_signature_not_found() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    data = [0] * 100
    result = analyzer._find_vs_signature(data)
    assert result == -1


def test_resource_analyzer_parse_fixed_file_info_not_enough_data() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    data = [0] * 50
    result = analyzer._parse_fixed_file_info(data, 0)
    assert result == ""


def test_resource_analyzer_parse_fixed_file_info_valid() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    data = [0] * 100
    result = analyzer._parse_fixed_file_info(data, 0)
    assert result == "0.0.0.0"


def test_resource_analyzer_extract_version_strings() -> None:
    adapter = MagicMock()
    analyzer = ResourceAnalyzer(adapter=adapter)

    data = [0] * 100
    result = analyzer._extract_version_strings(data)
    assert isinstance(result, dict)


def test_resource_analyzer_version_string_keys() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    keys = analyzer._version_string_keys()
    assert "CompanyName" in keys
    assert "FileVersion" in keys


def test_resource_analyzer_read_version_string_value_not_found() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    data = [0] * 100
    result = analyzer._read_version_string_value(data, "CompanyName")
    assert result == ""


def test_resource_analyzer_read_version_string_value_no_value() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    key_pattern = list("CompanyName".encode("utf-16le"))
    data = key_pattern + [0, 0, 0, 0]
    result = analyzer._read_version_string_value(data, "CompanyName")
    assert result == ""


def test_resource_analyzer_read_version_string_value_valid() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    key = "CompanyName"
    value = "Test Corp"
    key_pattern = list(key.encode("utf-16le"))
    value_pattern = list(value.encode("utf-16le"))
    data = key_pattern + [0, 0, 0, 0] + value_pattern + [0, 0]
    result = analyzer._read_version_string_value(data, key)
    assert result == value


def test_resource_analyzer_read_version_string_value_non_printable() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    key = "CompanyName"
    key_pattern = list(key.encode("utf-16le"))
    data = key_pattern + [0, 0, 0, 0, 1, 0, 2, 0, 3, 0, 0, 0]
    result = analyzer._read_version_string_value(data, key)
    assert result == ""


def test_resource_analyzer_read_version_string_value_decode_error() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    key = "CompanyName"
    key_pattern = list(key.encode("utf-16le"))
    data = key_pattern + [0, 0, 0, 0, 0xFF, 0xFF, 0, 0]
    result = analyzer._read_version_string_value(data, key)
    assert result == ""


def test_resource_analyzer_extract_manifest_no_manifest() -> None:
    adapter = MagicMock()
    analyzer = ResourceAnalyzer(adapter=adapter)

    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_ICON", "offset": 0x1000, "size": 100}]
    analyzer._extract_manifest(result, resources)
    assert "manifest" not in result


def test_resource_analyzer_extract_manifest_exception() -> None:
    adapter = MagicMock()
    adapter.cmdj.side_effect = Exception("Test error")

    analyzer = ResourceAnalyzer(adapter=adapter)
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_MANIFEST", "offset": 0x1000, "size": 100}]
    analyzer._extract_manifest(result, resources)


def test_resource_analyzer_extract_icons_empty() -> None:
    adapter = MagicMock()
    analyzer = ResourceAnalyzer(adapter=adapter)

    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_STRING", "offset": 0x1000, "size": 100}]
    analyzer._extract_icons(result, resources)
    assert result["icons"] == []


def test_resource_analyzer_extract_icons_valid() -> None:
    adapter = MagicMock()
    analyzer = ResourceAnalyzer(adapter=adapter)

    result: dict[str, Any] = {}
    resources = [
        {"type_name": "RT_ICON", "offset": 0x1000, "size": 100, "entropy": 3.5},
        {"type_name": "RT_GROUP_ICON", "offset": 0x2000, "size": 50, "entropy": 7.8},
    ]
    analyzer._extract_icons(result, resources)
    assert len(result["icons"]) == 2
    assert "suspicious" in result["icons"][1]


def test_resource_analyzer_extract_strings_empty() -> None:
    adapter = MagicMock()
    analyzer = ResourceAnalyzer(adapter=adapter)

    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_ICON", "offset": 0x1000, "size": 100}]
    analyzer._extract_strings(result, resources)
    assert result["strings"] == []


def test_resource_analyzer_extract_strings_exception() -> None:
    adapter = MagicMock()
    adapter.cmdj.side_effect = Exception("Test error")

    analyzer = ResourceAnalyzer(adapter=adapter)
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_STRING", "offset": 0x1000, "size": 100}]
    analyzer._extract_strings(result, resources)


def test_resource_analyzer_read_resource_as_string_zero_offset() -> None:
    adapter = MagicMock()
    analyzer = ResourceAnalyzer(adapter=adapter)

    result = analyzer._read_resource_as_string(0, 100)
    assert result is None


def test_resource_analyzer_read_resource_as_string_zero_size() -> None:
    adapter = MagicMock()
    analyzer = ResourceAnalyzer(adapter=adapter)

    result = analyzer._read_resource_as_string(0x1000, 0)
    assert result is None


def test_resource_analyzer_read_resource_as_string_no_data() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = None

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._read_resource_as_string(0x1000, 100)
    assert result is None


def test_resource_analyzer_read_resource_as_string_utf16() -> None:
    adapter = MagicMock()
    text = "Test String"
    adapter.cmdj.return_value = list(text.encode("utf-16le"))

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._read_resource_as_string(0x1000, 100)
    assert result == text


def test_resource_analyzer_read_resource_as_string_utf8() -> None:
    adapter = MagicMock()
    text = "Test String"
    adapter.cmdj.return_value = list(text.encode("utf-8"))

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._read_resource_as_string(0x1000, 100)
    assert result == text


def test_resource_analyzer_read_resource_as_string_ascii() -> None:
    adapter = MagicMock()
    text = "Test"
    adapter.cmdj.return_value = list(text.encode("ascii"))

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._read_resource_as_string(0x1000, 100)
    assert result == text


def test_resource_analyzer_read_resource_as_string_no_printable() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = [0, 1, 2, 3, 4, 5]

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._read_resource_as_string(0x1000, 100)
    assert result is None


def test_resource_analyzer_read_resource_as_string_exception() -> None:
    adapter = MagicMock()
    adapter.cmdj.side_effect = Exception("Test error")

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._read_resource_as_string(0x1000, 100)
    assert result is None


def test_resource_analyzer_calculate_statistics_empty() -> None:
    adapter = MagicMock()
    analyzer = ResourceAnalyzer(adapter=adapter)

    result: dict[str, Any] = {}
    analyzer._calculate_statistics(result, [])
    assert "statistics" not in result


def test_resource_analyzer_calculate_statistics_valid() -> None:
    adapter = MagicMock()
    analyzer = ResourceAnalyzer(adapter=adapter)

    resources = [
        {"size": 100, "entropy": 3.5},
        {"size": 200, "entropy": 5.0},
        {"size": 50, "entropy": 2.0},
    ]

    result: dict[str, Any] = {}
    analyzer._calculate_statistics(result, resources)
    assert result["statistics"]["total_resources"] == 3
    assert result["statistics"]["total_size"] == 350
    assert result["statistics"]["max_size"] == 200
    assert result["statistics"]["min_size"] == 50


def test_resource_analyzer_calculate_statistics_no_sizes() -> None:
    adapter = MagicMock()
    analyzer = ResourceAnalyzer(adapter=adapter)

    resources = [{"size": 0, "entropy": 0}]

    result: dict[str, Any] = {}
    analyzer._calculate_statistics(result, resources)
    assert result["statistics"]["average_size"] == 0


def test_resource_analyzer_check_suspicious_resources_empty() -> None:
    adapter = MagicMock()
    analyzer = ResourceAnalyzer(adapter=adapter)

    result: dict[str, Any] = {}
    analyzer._check_suspicious_resources(result, [])
    assert result["suspicious_resources"] == []


def test_resource_analyzer_check_resource_entropy_low() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    res = {"name": "test", "type_name": "RT_STRING", "entropy": 5.0, "size": 100}
    result = analyzer._check_resource_entropy(res)
    assert result == []


def test_resource_analyzer_check_resource_entropy_icon() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    res = {"name": "icon", "type_name": "RT_ICON", "entropy": 8.0, "size": 100}
    result = analyzer._check_resource_entropy(res)
    assert result == []


def test_resource_analyzer_check_resource_entropy_high() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    res = {"name": "test", "type_name": "RT_STRING", "entropy": 7.8, "size": 100}
    result = analyzer._check_resource_entropy(res)
    assert len(result) == 1
    assert "High entropy" in result[0]["reason"]


def test_resource_analyzer_check_resource_size_small() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    res = {"name": "test", "type_name": "RT_STRING", "size": 1024}
    result = analyzer._check_resource_size(res)
    assert result == []


def test_resource_analyzer_check_resource_size_large() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    res = {"name": "test", "type_name": "RT_STRING", "size": 2 * 1024 * 1024}
    result = analyzer._check_resource_size(res)
    assert len(result) == 1
    assert "large" in result[0]["reason"].lower()


def test_resource_analyzer_check_resource_rcdata_not_rcdata() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    res = {"name": "test", "type_name": "RT_STRING", "size": 20000}
    result = analyzer._check_resource_rcdata(res)
    assert result == []


def test_resource_analyzer_check_resource_rcdata_small() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    res = {"name": "test", "type_name": "RT_RCDATA", "size": 5000, "entropy": 3.5}
    result = analyzer._check_resource_rcdata(res)
    assert result == []


def test_resource_analyzer_check_resource_rcdata_large() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    res = {"name": "test", "type_name": "RT_RCDATA", "size": 20000, "entropy": 3.5}
    result = analyzer._check_resource_rcdata(res)
    assert len(result) == 1
    assert "RCDATA" in result[0]["reason"]


def test_resource_analyzer_check_resource_embedded_pe_wrong_type() -> None:
    adapter = MagicMock()
    analyzer = ResourceAnalyzer(adapter=adapter)

    res = {"name": "test", "type_name": "RT_ICON", "size": 2000, "offset": 0x1000}
    result = analyzer._check_resource_embedded_pe(res)
    assert result == []


def test_resource_analyzer_check_resource_embedded_pe_too_small() -> None:
    adapter = MagicMock()
    analyzer = ResourceAnalyzer(adapter=adapter)

    res = {"name": "test", "type_name": "RT_RCDATA", "size": 500, "offset": 0x1000}
    result = analyzer._check_resource_embedded_pe(res)
    assert result == []


def test_resource_analyzer_check_resource_embedded_pe_zero_offset() -> None:
    adapter = MagicMock()
    analyzer = ResourceAnalyzer(adapter=adapter)

    res = {"name": "test", "type_name": "RT_RCDATA", "size": 2000, "offset": 0}
    result = analyzer._check_resource_embedded_pe(res)
    assert result == []


def test_resource_analyzer_check_resource_embedded_pe_no_data() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = None

    analyzer = ResourceAnalyzer(adapter=adapter)
    res = {"name": "test", "type_name": "RT_RCDATA", "size": 2000, "offset": 0x1000}
    result = analyzer._check_resource_embedded_pe(res)
    assert result == []


def test_resource_analyzer_check_resource_embedded_pe_too_short() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = [0x4D]

    analyzer = ResourceAnalyzer(adapter=adapter)
    res = {"name": "test", "type_name": "RT_RCDATA", "size": 2000, "offset": 0x1000}
    result = analyzer._check_resource_embedded_pe(res)
    assert result == []


def test_resource_analyzer_check_resource_embedded_pe_not_pe() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = [0x00, 0x00]

    analyzer = ResourceAnalyzer(adapter=adapter)
    res = {"name": "test", "type_name": "RT_RCDATA", "size": 2000, "offset": 0x1000}
    result = analyzer._check_resource_embedded_pe(res)
    assert result == []


def test_resource_analyzer_check_resource_embedded_pe_found() -> None:
    adapter = MagicMock()
    adapter.cmdj.return_value = [0x4D, 0x5A]

    analyzer = ResourceAnalyzer(adapter=adapter)
    res = {"name": "test", "type_name": "RT_RCDATA", "size": 2000, "offset": 0x1000}
    result = analyzer._check_resource_embedded_pe(res)
    assert len(result) == 1
    assert "embedded PE" in result[0]["reason"]


def test_resource_analyzer_find_pattern_not_found() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    data = [1, 2, 3, 4, 5]
    pattern = [6, 7, 8]
    result = analyzer._find_pattern(data, pattern)
    assert result == -1


def test_resource_analyzer_find_pattern_found() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    data = [1, 2, 3, 4, 5, 6, 7]
    pattern = [3, 4, 5]
    result = analyzer._find_pattern(data, pattern)
    assert result == 2


def test_resource_analyzer_find_pattern_at_start() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    data = [1, 2, 3, 4, 5]
    pattern = [1, 2]
    result = analyzer._find_pattern(data, pattern)
    assert result == 0


def test_resource_analyzer_find_pattern_at_end() -> None:
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    data = [1, 2, 3, 4, 5]
    pattern = [4, 5]
    result = analyzer._find_pattern(data, pattern)
    assert result == 3


def test_resource_analyzer_parse_resources_manual_exception() -> None:
    adapter = MagicMock()
    adapter.cmdj.side_effect = [Exception("iRj error"), Exception("sections error")]

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._parse_resources_manual()
    assert result == []


def test_resource_analyzer_parse_resources_manual_zero_offset() -> None:
    adapter = MagicMock()

    def mock_cmdj(cmd: str, default: Any) -> Any:
        if "iRj" in cmd:
            raise Exception("iRj error")
        elif "iSj" in cmd:
            return [{"name": ".rsrc", "paddr": 0}]
        return default

    adapter.cmdj.side_effect = mock_cmdj

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._parse_resources()
    assert result == []


def test_resource_analyzer_parse_resources_manual_invalid_header() -> None:
    adapter = MagicMock()

    def mock_cmdj(cmd: str, default: Any) -> Any:
        if "iRj" in cmd:
            raise Exception("iRj error")
        elif "iSj" in cmd:
            return [{"name": ".rsrc", "paddr": 0x1000}]
        elif "pxj" in cmd:
            return [0] * 10
        return default

    adapter.cmdj.side_effect = mock_cmdj

    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._parse_resources()
    assert result == []
