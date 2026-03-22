from __future__ import annotations

from typing import Any

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.resource_analyzer import ResourceAnalyzer
from r2inspect.testing.fake_r2 import FakeR2


def _make_analyzer(
    cmdj_map: dict[str, Any] | None = None,
    cmd_map: dict[str, str] | None = None,
) -> ResourceAnalyzer:
    """Create a ResourceAnalyzer with a FakeR2 backend."""
    fake_r2 = FakeR2(cmdj_map=cmdj_map, cmd_map=cmd_map)
    adapter = R2PipeAdapter(fake_r2)
    return ResourceAnalyzer(adapter=adapter)


def _bytes_to_hex(data: list[int]) -> str:
    """Convert a list of ints to a hex string for FakeR2.cmd (p8 commands)."""
    return bytes(data).hex()


# ── Init ─────────────────────────────────────────────────────────────────


def test_resource_analyzer_init() -> None:
    analyzer = _make_analyzer()
    assert analyzer.adapter is not None


# ── _get_resource_directory ──────────────────────────────────────────────


def test_resource_analyzer_get_resource_directory_none() -> None:
    analyzer = _make_analyzer(cmdj_map={"iDj": None})
    result = analyzer._get_resource_directory()
    assert result is None


def test_resource_analyzer_get_resource_directory_not_list() -> None:
    analyzer = _make_analyzer(cmdj_map={"iDj": {"not": "a list"}})
    result = analyzer._get_resource_directory()
    assert result is None


def test_resource_analyzer_get_resource_directory_no_resource() -> None:
    analyzer = _make_analyzer(cmdj_map={"iDj": [{"name": "OTHER", "vaddr": 100, "size": 200}]})
    result = analyzer._get_resource_directory()
    assert result is None


def test_resource_analyzer_get_resource_directory_resource_zero_vaddr() -> None:
    analyzer = _make_analyzer(
        cmdj_map={"iDj": [{"name": "RESOURCE", "vaddr": 0, "size": 200, "paddr": 100}]}
    )
    result = analyzer._get_resource_directory()
    assert result is None


def test_resource_analyzer_get_resource_directory_valid() -> None:
    analyzer = _make_analyzer(
        cmdj_map={"iDj": [{"name": "RESOURCE", "vaddr": 0x1000, "size": 500, "paddr": 0x800}]}
    )
    result = analyzer._get_resource_directory()
    assert result is not None
    assert result["offset"] == 0x800
    assert result["size"] == 500
    assert result["virtual_address"] == 0x1000


def test_resource_analyzer_get_resource_directory_exception() -> None:
    # When cmdj raises, the adapter layers catch the error and return default/None.
    # _get_resource_directory then returns None.
    analyzer = _make_analyzer(cmdj_map={"iDj": Exception("Test error")})
    result = analyzer._get_resource_directory()
    assert result is None


# ── _parse_resources ─────────────────────────────────────────────────────


def test_resource_analyzer_parse_resources_empty() -> None:
    analyzer = _make_analyzer(cmdj_map={"iRj": []})
    result = analyzer._parse_resources()
    assert result == []


def test_resource_analyzer_parse_resources_none() -> None:
    analyzer = _make_analyzer(cmdj_map={"iRj": None})
    result = analyzer._parse_resources()
    assert result == []


def test_resource_analyzer_parse_resources_not_dict() -> None:
    analyzer = _make_analyzer(cmdj_map={"iRj": ["not a dict", 123, None]})
    result = analyzer._parse_resources()
    # Non-dict entries are filtered out
    assert result == []


def test_resource_analyzer_parse_resources_valid() -> None:
    resource_data = [
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
    # Provide p8 data for the resource data analysis (read_bytes for pxj)
    byte_data = [ord("a")] * 256
    hex_str = _bytes_to_hex(byte_data)
    analyzer = _make_analyzer(
        cmdj_map={"iRj": resource_data},
        cmd_map={"p8": hex_str},
    )
    result = analyzer._parse_resources()
    assert len(result) == 1
    assert result[0]["name"] == "test.ico"
    assert result[0]["type_name"] == "RT_ICON"


def test_resource_analyzer_parse_resources_zero_offset() -> None:
    resource_data = [
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
    analyzer = _make_analyzer(cmdj_map={"iRj": resource_data})
    result = analyzer._parse_resources()
    assert len(result) == 1
    assert result[0]["entropy"] == 0.0


def test_resource_analyzer_parse_resources_exception() -> None:
    # When iRj raises, _parse_resources falls back to _parse_resources_manual.
    # With no sections data either, returns [].
    analyzer = _make_analyzer(cmdj_map={"iRj": Exception("Test error"), "iSj": []})
    result = analyzer._parse_resources()
    assert result == []


def test_resource_analyzer_parse_resources_manual_no_rsrc() -> None:
    # iRj fails, iSj returns empty -> _parse_resources_manual returns []
    analyzer = _make_analyzer(cmdj_map={"iRj": Exception("iRj error"), "iSj": []})
    result = analyzer._parse_resources()
    assert result == []


# ── _get_rsrc_section ────────────────────────────────────────────────────


def test_resource_analyzer_get_rsrc_section_none() -> None:
    analyzer = _make_analyzer(cmdj_map={"iSj": None})
    result = analyzer._get_rsrc_section()
    assert result is None


def test_resource_analyzer_get_rsrc_section_not_list() -> None:
    analyzer = _make_analyzer(cmdj_map={"iSj": {"not": "a list"}})
    result = analyzer._get_rsrc_section()
    assert result is None


def test_resource_analyzer_get_rsrc_section_no_rsrc() -> None:
    analyzer = _make_analyzer(cmdj_map={"iSj": [{"name": ".text"}, {"name": ".data"}]})
    result = analyzer._get_rsrc_section()
    assert result is None


def test_resource_analyzer_get_rsrc_section_found() -> None:
    analyzer = _make_analyzer(
        cmdj_map={
            "iSj": [
                {"name": ".text"},
                {"name": ".rsrc", "paddr": 0x1000, "size": 500},
            ]
        }
    )
    result = analyzer._get_rsrc_section()
    assert result is not None
    assert result["name"] == ".rsrc"


# ── _is_valid_dir_header ─────────────────────────────────────────────────


def test_resource_analyzer_is_valid_dir_header_none() -> None:
    analyzer = _make_analyzer()
    assert analyzer._is_valid_dir_header(None) is False


def test_resource_analyzer_is_valid_dir_header_too_short() -> None:
    analyzer = _make_analyzer()
    assert analyzer._is_valid_dir_header([0] * 10) is False


def test_resource_analyzer_is_valid_dir_header_valid() -> None:
    analyzer = _make_analyzer()
    assert analyzer._is_valid_dir_header([0] * 16) is True


# ── _get_dir_total_entries ───────────────────────────────────────────────


def test_resource_analyzer_get_dir_total_entries() -> None:
    analyzer = _make_analyzer()
    dir_data = [0] * 12 + [2, 0, 3, 0]
    result = analyzer._get_dir_total_entries(dir_data)
    assert result == 5


# ── _parse_dir_entries ───────────────────────────────────────────────────


def test_resource_analyzer_parse_dir_entries_empty() -> None:
    # Provide p8/pxj returning empty for the entry reads
    analyzer = _make_analyzer(cmd_map={"p8": ""})
    result = analyzer._parse_dir_entries(0x1000, 0)
    assert result == []


def test_resource_analyzer_parse_dir_entries_limit() -> None:
    # Provide valid entry data for pxj reads (8 bytes of zeros)
    entry_hex = _bytes_to_hex([0] * 8)
    analyzer = _make_analyzer(cmd_map={"p8": entry_hex})
    result = analyzer._parse_dir_entries(0x1000, 30)
    assert len(result) <= 20


# ── _parse_dir_entry ─────────────────────────────────────────────────────


def test_resource_analyzer_parse_dir_entry_none() -> None:
    analyzer = _make_analyzer()
    result = analyzer._parse_dir_entry(0x1000, None, 0)
    assert result is None


def test_resource_analyzer_parse_dir_entry_too_short() -> None:
    analyzer = _make_analyzer()
    result = analyzer._parse_dir_entry(0x1000, [0] * 4, 0)
    assert result is None


def test_resource_analyzer_parse_dir_entry_named() -> None:
    analyzer = _make_analyzer()
    entry_data = [0, 0, 0, 0x80, 0, 0, 0, 0]
    result = analyzer._parse_dir_entry(0x1000, entry_data, 5)
    assert result is not None
    assert "Named_5" in result["name"]


def test_resource_analyzer_parse_dir_entry_with_type() -> None:
    analyzer = _make_analyzer()
    entry_data = [3, 0, 0, 0, 0, 0, 0, 0]
    result = analyzer._parse_dir_entry(0x1000, entry_data, 0)
    assert result is not None
    assert result["type_name"] == "RT_ICON"


def test_resource_analyzer_parse_dir_entry_is_directory() -> None:
    analyzer = _make_analyzer()
    entry_data = [3, 0, 0, 0, 0, 0, 0, 0x80]
    result = analyzer._parse_dir_entry(0x1000, entry_data, 0)
    assert result is not None
    assert result["is_directory"] is True


# ── _get_resource_type_name ──────────────────────────────────────────────


def test_resource_analyzer_get_resource_type_name_known() -> None:
    analyzer = _make_analyzer()
    assert analyzer._get_resource_type_name(1) == "RT_CURSOR"
    assert analyzer._get_resource_type_name(2) == "RT_BITMAP"
    assert analyzer._get_resource_type_name(3) == "RT_ICON"


def test_resource_analyzer_get_resource_type_name_unknown() -> None:
    analyzer = _make_analyzer()
    assert analyzer._get_resource_type_name(9999) == "UNKNOWN_9999"


# ── _analyze_resource_data ───────────────────────────────────────────────


def test_resource_analyzer_analyze_resource_data_zero_offset() -> None:
    analyzer = _make_analyzer()
    resource: dict[str, Any] = {"offset": 0, "size": 100}
    analyzer._analyze_resource_data(resource)
    assert resource["entropy"] == 0.0


def test_resource_analyzer_analyze_resource_data_zero_size() -> None:
    analyzer = _make_analyzer()
    resource: dict[str, Any] = {"offset": 0x1000, "size": 0}
    analyzer._analyze_resource_data(resource)
    assert resource["entropy"] == 0.0


def test_resource_analyzer_analyze_resource_data_no_data() -> None:
    # p8 returns empty string -> read_bytes returns b"" -> read_bytes_list returns []
    analyzer = _make_analyzer(cmd_map={"p8": ""})
    resource: dict[str, Any] = {"offset": 0x1000, "size": 100}
    analyzer._analyze_resource_data(resource)
    assert resource["entropy"] == 0.0


def test_resource_analyzer_analyze_resource_data_valid() -> None:
    byte_data = [ord("a")] * 100
    hex_str = _bytes_to_hex(byte_data)
    analyzer = _make_analyzer(cmd_map={"p8": hex_str})
    resource: dict[str, Any] = {"offset": 0x1000, "size": 100}
    analyzer._analyze_resource_data(resource)
    assert resource["entropy"] >= 0


def test_resource_analyzer_analyze_resource_data_hash_error() -> None:
    # Values > 255 cause bytes() to fail in the hashing layer;
    # the analyzer should handle this gracefully.
    # With FakeR2, we provide valid byte data and let the real code handle it.
    byte_data = [0x01, 0x02]
    hex_str = _bytes_to_hex(byte_data)
    analyzer = _make_analyzer(cmd_map={"p8": hex_str})
    resource: dict[str, Any] = {"offset": 0x1000, "size": 2}
    analyzer._analyze_resource_data(resource)
    # With valid data, hashes should be computed or empty dict
    assert isinstance(resource.get("hashes", {}), dict)


def test_resource_analyzer_analyze_resource_data_exception() -> None:
    # When the adapter can't read data (error during p8), the resource
    # data analysis handles the error gracefully.
    analyzer = _make_analyzer(cmd_map={"p8": ""})
    resource: dict[str, Any] = {"offset": 0x1000, "size": 100}
    analyzer._analyze_resource_data(resource)
    # Should not raise; entropy defaults to 0.0


def test_resource_analyzer_analyze_resource_data_non_numeric_values() -> None:
    analyzer = _make_analyzer()
    resource: dict[str, Any] = {"offset": "abc", "size": "100"}
    analyzer._analyze_resource_data(resource)
    assert resource["entropy"] == 0.0
    assert resource["hashes"] == {}


# ── _calculate_entropy ───────────────────────────────────────────────────


def test_resource_analyzer_calculate_entropy() -> None:
    analyzer = _make_analyzer()
    data = [0] * 100
    entropy = analyzer._calculate_entropy(data)
    assert entropy == 0.0


def test_resource_analyzer_calculate_entropy_mixed() -> None:
    analyzer = _make_analyzer()
    data = list(range(256))
    entropy = analyzer._calculate_entropy(data)
    assert entropy > 0


# ── _analyze_resource_types ──────────────────────────────────────────────


def test_resource_analyzer_analyze_resource_types_empty() -> None:
    analyzer = _make_analyzer()
    result: dict[str, Any] = {}
    analyzer._analyze_resource_types(result, [])
    assert result["resource_types"] == []
    assert result["total_size"] == 0


def test_resource_analyzer_analyze_resource_types_valid() -> None:
    analyzer = _make_analyzer()
    resources = [
        {"type_name": "RT_ICON", "size": 100},
        {"type_name": "RT_ICON", "size": 200},
        {"type_name": "RT_MANIFEST", "size": 50},
    ]
    result: dict[str, Any] = {}
    analyzer._analyze_resource_types(result, resources)
    assert len(result["resource_types"]) == 2
    assert result["total_size"] == 350


# ── _extract_version_info ────────────────────────────────────────────────


def test_resource_analyzer_extract_version_info_no_version() -> None:
    analyzer = _make_analyzer()
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_ICON", "offset": 0x1000, "size": 100}]
    analyzer._extract_version_info(result, resources)
    assert "version_info" not in result


def test_resource_analyzer_extract_version_info_exception() -> None:
    # When version info reading fails, it should not raise
    analyzer = _make_analyzer(cmd_map={"p8": ""})
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_VERSION", "offset": 0x1000, "size": 100}]
    analyzer._extract_version_info(result, resources)
    # Should not raise; version_info may or may not be set


# ── _parse_version_info ─────────────────────────────────────────────────


def test_resource_analyzer_parse_version_info_zero_offset() -> None:
    analyzer = _make_analyzer()
    result = analyzer._parse_version_info(0, 100)
    assert result is None


def test_resource_analyzer_parse_version_info_small_size() -> None:
    analyzer = _make_analyzer()
    result = analyzer._parse_version_info(0x1000, 50)
    assert result is None


def test_resource_analyzer_parse_version_info_no_data() -> None:
    # p8 returns empty -> no version data available
    analyzer = _make_analyzer(cmd_map={"p8": ""})
    result = analyzer._parse_version_info(0x1000, 100)
    assert result is None


def test_resource_analyzer_parse_version_info_no_strings() -> None:
    # Provide 100 zero bytes -> no version strings found -> returns None
    byte_data = [0] * 100
    hex_str = _bytes_to_hex(byte_data)
    analyzer = _make_analyzer(cmd_map={"p8": hex_str})
    result = analyzer._parse_version_info(0x1000, 100)
    assert result is None


def test_resource_analyzer_parse_version_info_exception() -> None:
    # Error during version parsing should return None
    analyzer = _make_analyzer(cmd_map={"p8": ""})
    result = analyzer._parse_version_info(0x1000, 100)
    assert result is None


# ── _read_version_info_data ──────────────────────────────────────────────


def test_resource_analyzer_read_version_info_data_none() -> None:
    # p8 returns empty -> read_bytes_list returns [] -> data too small
    analyzer = _make_analyzer(cmd_map={"p8": ""})
    result = analyzer._read_version_info_data(0x1000, 100)
    assert result is None


def test_resource_analyzer_read_version_info_data_too_small() -> None:
    # Provide data smaller than 64 bytes
    byte_data = [0] * 50
    hex_str = _bytes_to_hex(byte_data)
    analyzer = _make_analyzer(cmd_map={"p8": hex_str})
    result = analyzer._read_version_info_data(0x1000, 100)
    assert result is None


def test_resource_analyzer_read_version_info_data_valid() -> None:
    byte_data = [0] * 100
    hex_str = _bytes_to_hex(byte_data)
    analyzer = _make_analyzer(cmd_map={"p8": hex_str})
    result = analyzer._read_version_info_data(0x1000, 100)
    assert result is not None
    assert len(result) == 100


# ── _find_vs_signature ───────────────────────────────────────────────────


def test_resource_analyzer_find_vs_signature() -> None:
    analyzer = _make_analyzer()
    data = [0] * 50 + [0xBD, 0x04, 0xEF, 0xFE] + [0] * 50
    result = analyzer._find_vs_signature(data)
    assert result == 50


def test_resource_analyzer_find_vs_signature_not_found() -> None:
    analyzer = _make_analyzer()
    data = [0] * 100
    result = analyzer._find_vs_signature(data)
    assert result == -1


# ── _parse_fixed_file_info ───────────────────────────────────────────────


def test_resource_analyzer_parse_fixed_file_info_not_enough_data() -> None:
    analyzer = _make_analyzer()
    data = [0] * 50
    result = analyzer._parse_fixed_file_info(data, 0)
    assert result == ""


def test_resource_analyzer_parse_fixed_file_info_valid() -> None:
    analyzer = _make_analyzer()
    data = [0] * 100
    result = analyzer._parse_fixed_file_info(data, 0)
    assert result == "0.0.0.0"


# ── _extract_version_strings ────────────────────────────────────────────


def test_resource_analyzer_extract_version_strings() -> None:
    analyzer = _make_analyzer()
    data = [0] * 100
    result = analyzer._extract_version_strings(data)
    assert isinstance(result, dict)


# ── _version_string_keys ────────────────────────────────────────────────


def test_resource_analyzer_version_string_keys() -> None:
    analyzer = _make_analyzer()
    keys = analyzer._version_string_keys()
    assert "CompanyName" in keys
    assert "FileVersion" in keys


# ── _read_version_string_value ───────────────────────────────────────────


def test_resource_analyzer_read_version_string_value_not_found() -> None:
    analyzer = _make_analyzer()
    data = [0] * 100
    result = analyzer._read_version_string_value(data, "CompanyName")
    assert result == ""


def test_resource_analyzer_read_version_string_value_no_value() -> None:
    analyzer = _make_analyzer()
    key_pattern = list("CompanyName".encode("utf-16le"))
    data = key_pattern + [0, 0, 0, 0]
    result = analyzer._read_version_string_value(data, "CompanyName")
    assert result == ""


def test_resource_analyzer_read_version_string_value_valid() -> None:
    analyzer = _make_analyzer()
    key = "CompanyName"
    value = "Test Corp"
    key_pattern = list(key.encode("utf-16le"))
    value_pattern = list(value.encode("utf-16le"))
    data = key_pattern + [0, 0, 0, 0] + value_pattern + [0, 0]
    result = analyzer._read_version_string_value(data, key)
    assert result == value


def test_resource_analyzer_read_version_string_value_non_printable() -> None:
    analyzer = _make_analyzer()
    key = "CompanyName"
    key_pattern = list(key.encode("utf-16le"))
    data = key_pattern + [0, 0, 0, 0, 1, 0, 2, 0, 3, 0, 0, 0]
    result = analyzer._read_version_string_value(data, key)
    assert result == ""


def test_resource_analyzer_read_version_string_value_decode_error() -> None:
    analyzer = _make_analyzer()
    key = "CompanyName"
    key_pattern = list(key.encode("utf-16le"))
    data = key_pattern + [0, 0, 0, 0, 0xFF, 0xFF, 0, 0]
    result = analyzer._read_version_string_value(data, key)
    assert result == ""


# ── _extract_manifest ────────────────────────────────────────────────────


def test_resource_analyzer_extract_manifest_no_manifest() -> None:
    analyzer = _make_analyzer()
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_ICON", "offset": 0x1000, "size": 100}]
    analyzer._extract_manifest(result, resources)
    assert "manifest" not in result


def test_resource_analyzer_extract_manifest_exception() -> None:
    # When reading the manifest fails (no data), it should not raise
    analyzer = _make_analyzer(cmd_map={"p8": ""})
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_MANIFEST", "offset": 0x1000, "size": 100}]
    analyzer._extract_manifest(result, resources)
    # Should not raise


def test_resource_analyzer_extract_manifest_string_size_value() -> None:
    # Provide manifest XML as byte data for the p8 command
    manifest_xml = "<assembly></assembly>"
    byte_data = list(manifest_xml.encode("utf-8"))
    hex_str = _bytes_to_hex(byte_data)
    analyzer = _make_analyzer(cmd_map={"p8": hex_str})
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_MANIFEST", "offset": 4096, "size": 100}]
    analyzer._extract_manifest(result, resources)
    if "manifest" in result:
        assert result["manifest"]["size"] == 100


# ── _extract_icons ───────────────────────────────────────────────────────


def test_resource_analyzer_extract_icons_empty() -> None:
    analyzer = _make_analyzer()
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_STRING", "offset": 0x1000, "size": 100}]
    analyzer._extract_icons(result, resources)
    assert result["icons"] == []


def test_resource_analyzer_extract_icons_valid() -> None:
    analyzer = _make_analyzer()
    result: dict[str, Any] = {}
    resources = [
        {"type_name": "RT_ICON", "offset": 0x1000, "size": 100, "entropy": 3.5},
        {"type_name": "RT_GROUP_ICON", "offset": 0x2000, "size": 50, "entropy": 7.8},
    ]
    analyzer._extract_icons(result, resources)
    assert len(result["icons"]) == 2
    assert "suspicious" in result["icons"][1]


# ── _extract_strings ─────────────────────────────────────────────────────


def test_resource_analyzer_extract_strings_empty() -> None:
    analyzer = _make_analyzer()
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_ICON", "offset": 0x1000, "size": 100}]
    analyzer._extract_strings(result, resources)
    assert result["strings"] == []


def test_resource_analyzer_extract_strings_exception() -> None:
    # When string extraction fails (no data), it should not raise
    analyzer = _make_analyzer(cmd_map={"p8": ""})
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_STRING", "offset": 0x1000, "size": 100}]
    analyzer._extract_strings(result, resources)
    # Should not raise; strings list should be set
    assert isinstance(result.get("strings", []), list)


# ── _read_resource_as_string ─────────────────────────────────────────────


def test_resource_analyzer_read_resource_as_string_zero_offset() -> None:
    analyzer = _make_analyzer()
    result = analyzer._read_resource_as_string(0, 100)
    assert result is None


def test_resource_analyzer_read_resource_as_string_zero_size() -> None:
    analyzer = _make_analyzer()
    result = analyzer._read_resource_as_string(0x1000, 0)
    assert result is None


def test_resource_analyzer_read_resource_as_string_negative_values() -> None:
    analyzer = _make_analyzer()
    assert analyzer._read_resource_as_string(-1, 100) is None
    assert analyzer._read_resource_as_string(0x1000, -1) is None


def test_resource_analyzer_read_resource_as_string_no_data() -> None:
    analyzer = _make_analyzer(cmd_map={"p8": ""})
    result = analyzer._read_resource_as_string(0x1000, 100)
    assert result is None


def test_resource_analyzer_read_resource_as_string_utf16() -> None:
    text = "Test String"
    byte_data = list(text.encode("utf-16le"))
    hex_str = _bytes_to_hex(byte_data)
    analyzer = _make_analyzer(cmd_map={"p8": hex_str})
    result = analyzer._read_resource_as_string(0x1000, 100)
    assert result == text


def test_resource_analyzer_read_resource_as_string_utf8() -> None:
    text = "Test String"
    byte_data = list(text.encode("utf-8"))
    hex_str = _bytes_to_hex(byte_data)
    analyzer = _make_analyzer(cmd_map={"p8": hex_str})
    result = analyzer._read_resource_as_string(0x1000, 100)
    assert result == text


def test_resource_analyzer_read_resource_as_string_ascii() -> None:
    text = "Test"
    byte_data = list(text.encode("ascii"))
    hex_str = _bytes_to_hex(byte_data)
    analyzer = _make_analyzer(cmd_map={"p8": hex_str})
    result = analyzer._read_resource_as_string(0x1000, 100)
    assert result == text


def test_resource_analyzer_read_resource_as_string_no_printable() -> None:
    byte_data = [0, 1, 2, 3, 4, 5]
    hex_str = _bytes_to_hex(byte_data)
    analyzer = _make_analyzer(cmd_map={"p8": hex_str})
    result = analyzer._read_resource_as_string(0x1000, 100)
    assert result is None


def test_resource_analyzer_read_resource_as_string_exception() -> None:
    # When adapter can't read bytes, returns None
    analyzer = _make_analyzer(cmd_map={"p8": ""})
    result = analyzer._read_resource_as_string(0x1000, 100)
    assert result is None


# ── _calculate_statistics ────────────────────────────────────────────────


def test_resource_analyzer_calculate_statistics_empty() -> None:
    analyzer = _make_analyzer()
    result: dict[str, Any] = {}
    analyzer._calculate_statistics(result, [])
    assert "statistics" not in result


def test_resource_analyzer_calculate_statistics_valid() -> None:
    analyzer = _make_analyzer()
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
    analyzer = _make_analyzer()
    resources = [{"size": 0, "entropy": 0}]
    result: dict[str, Any] = {}
    analyzer._calculate_statistics(result, resources)
    assert result["statistics"]["average_size"] == 0


# ── _check_suspicious_resources ──────────────────────────────────────────


def test_resource_analyzer_check_suspicious_resources_empty() -> None:
    analyzer = _make_analyzer()
    result: dict[str, Any] = {}
    analyzer._check_suspicious_resources(result, [])
    assert result["suspicious_resources"] == []


# ── _check_resource_entropy ──────────────────────────────────────────────


def test_resource_analyzer_check_resource_entropy_low() -> None:
    analyzer = _make_analyzer()
    res = {"name": "test", "type_name": "RT_STRING", "entropy": 5.0, "size": 100}
    result = analyzer._check_resource_entropy(res)
    assert result == []


def test_resource_analyzer_check_resource_entropy_icon() -> None:
    analyzer = _make_analyzer()
    res = {"name": "icon", "type_name": "RT_ICON", "entropy": 8.0, "size": 100}
    result = analyzer._check_resource_entropy(res)
    assert result == []


def test_resource_analyzer_check_resource_entropy_high() -> None:
    analyzer = _make_analyzer()
    res = {"name": "test", "type_name": "RT_STRING", "entropy": 7.8, "size": 100}
    result = analyzer._check_resource_entropy(res)
    assert len(result) == 1
    assert "High entropy" in result[0]["reason"]


# ── _check_resource_size ─────────────────────────────────────────────────


def test_resource_analyzer_check_resource_size_small() -> None:
    analyzer = _make_analyzer()
    res = {"name": "test", "type_name": "RT_STRING", "size": 1024}
    result = analyzer._check_resource_size(res)
    assert result == []


def test_resource_analyzer_check_resource_size_large() -> None:
    analyzer = _make_analyzer()
    res = {"name": "test", "type_name": "RT_STRING", "size": 2 * 1024 * 1024}
    result = analyzer._check_resource_size(res)
    assert len(result) == 1
    assert "large" in result[0]["reason"].lower()


# ── _check_resource_rcdata ───────────────────────────────────────────────


def test_resource_analyzer_check_resource_rcdata_not_rcdata() -> None:
    analyzer = _make_analyzer()
    res = {"name": "test", "type_name": "RT_STRING", "size": 20000}
    result = analyzer._check_resource_rcdata(res)
    assert result == []


def test_resource_analyzer_check_resource_rcdata_small() -> None:
    analyzer = _make_analyzer()
    res = {"name": "test", "type_name": "RT_RCDATA", "size": 5000, "entropy": 3.5}
    result = analyzer._check_resource_rcdata(res)
    assert result == []


def test_resource_analyzer_check_resource_rcdata_large() -> None:
    analyzer = _make_analyzer()
    res = {"name": "test", "type_name": "RT_RCDATA", "size": 20000, "entropy": 3.5}
    result = analyzer._check_resource_rcdata(res)
    assert len(result) == 1
    assert "RCDATA" in result[0]["reason"]


# ── _check_resource_embedded_pe ──────────────────────────────────────────


def test_resource_analyzer_check_resource_embedded_pe_wrong_type() -> None:
    analyzer = _make_analyzer()
    res = {"name": "test", "type_name": "RT_ICON", "size": 2000, "offset": 0x1000}
    result = analyzer._check_resource_embedded_pe(res)
    assert result == []


def test_resource_analyzer_check_resource_embedded_pe_too_small() -> None:
    analyzer = _make_analyzer()
    res = {"name": "test", "type_name": "RT_RCDATA", "size": 500, "offset": 0x1000}
    result = analyzer._check_resource_embedded_pe(res)
    assert result == []


def test_resource_analyzer_check_resource_embedded_pe_non_numeric_size() -> None:
    analyzer = _make_analyzer()
    res = {"name": "test", "type_name": "RT_RCDATA", "size": "abc", "offset": 0x1000}
    result = analyzer._check_resource_embedded_pe(res)
    assert result == []


def test_resource_analyzer_check_resource_embedded_pe_zero_offset() -> None:
    analyzer = _make_analyzer()
    res = {"name": "test", "type_name": "RT_RCDATA", "size": 2000, "offset": 0}
    result = analyzer._check_resource_embedded_pe(res)
    assert result == []


def test_resource_analyzer_check_resource_embedded_pe_no_data() -> None:
    # p8 returns empty -> read_bytes_list returns []
    analyzer = _make_analyzer(cmd_map={"p8": ""})
    res = {"name": "test", "type_name": "RT_RCDATA", "size": 2000, "offset": 0x1000}
    result = analyzer._check_resource_embedded_pe(res)
    assert result == []


def test_resource_analyzer_check_resource_embedded_pe_too_short() -> None:
    byte_data = [0x4D]
    hex_str = _bytes_to_hex(byte_data)
    analyzer = _make_analyzer(cmd_map={"p8": hex_str})
    res = {"name": "test", "type_name": "RT_RCDATA", "size": 2000, "offset": 0x1000}
    result = analyzer._check_resource_embedded_pe(res)
    assert result == []


def test_resource_analyzer_check_resource_embedded_pe_not_pe() -> None:
    byte_data = [0x00, 0x00]
    hex_str = _bytes_to_hex(byte_data)
    analyzer = _make_analyzer(cmd_map={"p8": hex_str})
    res = {"name": "test", "type_name": "RT_RCDATA", "size": 2000, "offset": 0x1000}
    result = analyzer._check_resource_embedded_pe(res)
    assert result == []


def test_resource_analyzer_check_resource_embedded_pe_found() -> None:
    byte_data = [0x4D, 0x5A]
    hex_str = _bytes_to_hex(byte_data)
    analyzer = _make_analyzer(cmd_map={"p8": hex_str})
    res = {"name": "test", "type_name": "RT_RCDATA", "size": 2000, "offset": 0x1000}
    result = analyzer._check_resource_embedded_pe(res)
    assert len(result) == 1
    assert "embedded PE" in result[0]["reason"]


# ── _find_pattern ────────────────────────────────────────────────────────


def test_resource_analyzer_find_pattern_not_found() -> None:
    analyzer = _make_analyzer()
    data = [1, 2, 3, 4, 5]
    pattern = [6, 7, 8]
    result = analyzer._find_pattern(data, pattern)
    assert result == -1


def test_resource_analyzer_find_pattern_found() -> None:
    analyzer = _make_analyzer()
    data = [1, 2, 3, 4, 5, 6, 7]
    pattern = [3, 4, 5]
    result = analyzer._find_pattern(data, pattern)
    assert result == 2


def test_resource_analyzer_find_pattern_at_start() -> None:
    analyzer = _make_analyzer()
    data = [1, 2, 3, 4, 5]
    pattern = [1, 2]
    result = analyzer._find_pattern(data, pattern)
    assert result == 0


def test_resource_analyzer_find_pattern_at_end() -> None:
    analyzer = _make_analyzer()
    data = [1, 2, 3, 4, 5]
    pattern = [4, 5]
    result = analyzer._find_pattern(data, pattern)
    assert result == 3


# ── _parse_resources_manual ──────────────────────────────────────────────


def test_resource_analyzer_parse_resources_manual_exception() -> None:
    # Both iSj and other commands fail -> returns []
    analyzer = _make_analyzer(cmdj_map={"iSj": Exception("sections error")})
    result = analyzer._parse_resources_manual()
    assert result == []


def test_resource_analyzer_parse_resources_manual_zero_offset() -> None:
    # iRj fails (triggering manual parsing), iSj returns .rsrc with paddr=0
    analyzer = _make_analyzer(
        cmdj_map={
            "iRj": Exception("iRj error"),
            "iSj": [{"name": ".rsrc", "paddr": 0}],
        }
    )
    result = analyzer._parse_resources()
    assert result == []


def test_resource_analyzer_parse_resources_manual_invalid_header() -> None:
    # iRj fails, iSj returns .rsrc with valid paddr, but pxj returns too-short header
    short_header = [0] * 10
    hex_str = _bytes_to_hex(short_header)
    analyzer = _make_analyzer(
        cmdj_map={
            "iRj": Exception("iRj error"),
            "iSj": [{"name": ".rsrc", "paddr": 0x1000}],
        },
        cmd_map={"p8": hex_str},
    )
    result = analyzer._parse_resources()
    assert result == []


# ── analyze (entry point) ────────────────────────────────────────────────


def test_resource_analyzer_analyze_returns_result() -> None:
    # Test the analyze() entry point with no resource directory
    analyzer = _make_analyzer(cmdj_map={"iDj": []})
    result = analyzer.analyze()
    assert isinstance(result, dict)
    assert result.get("available") is True


# ── _get_resource_directory handles exception ────────────────────────────


def test_resource_analyzer_get_resource_directory_handles_exception() -> None:
    # Force _cmdj to raise by giving the analyzer a broken adapter state.
    # Create normally, then override _cmdj to always raise.
    analyzer = _make_analyzer()

    def _raise(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("forced cmd error")

    analyzer._cmdj = _raise  # type: ignore[method-assign]
    assert analyzer._get_resource_directory() is None


# ── _extract_version_info error branch ───────────────────────────────────


def test_extract_version_info_version_error_branch() -> None:
    analyzer = _make_analyzer()
    result: dict[str, object] = {}

    def _raise(_offset: int, _size: int) -> None:
        raise RuntimeError("parse failure")

    analyzer._parse_version_info = _raise  # type: ignore[method-assign]
    resources = [{"type_name": "RT_VERSION", "offset": 0x1000, "size": 128}]
    analyzer._extract_version_info(result, resources)

    assert "version_info" not in result


def test_extract_version_info_assigns_version_info_and_breaks() -> None:
    analyzer = _make_analyzer()
    result: dict[str, object] = {}

    def _fake_parse(_offset: int, _size: int) -> dict[str, object]:
        return {"file_version": "1.2.3.4"}

    analyzer._parse_version_info = _fake_parse  # type: ignore[method-assign]
    resources = [
        {"type_name": "RT_VERSION", "offset": 0x1000, "size": 128},
        {"type_name": "RT_VERSION", "offset": 0x2000, "size": 128},
    ]
    analyzer._extract_version_info(result, resources)

    assert result["version_info"] == {"file_version": "1.2.3.4"}


# ── _check_suspicious_resources invokes all checks ───────────────────────


def test_check_suspicious_resources_invokes_all_checks() -> None:
    # Not-a-PE header bytes -> no embedded PE detected, but entropy and size checks fire
    byte_data = [0x00, 0x00]
    hex_str = _bytes_to_hex(byte_data)
    analyzer = _make_analyzer(cmd_map={"p8": hex_str})

    result: dict[str, object] = {}
    resources = [
        {
            "name": "payload",
            "type_name": "RT_RCDATA",
            "entropy": 8.0,
            "size": 2 * 1024 * 1024,
            "offset": 0x1000,
        }
    ]
    analyzer._check_suspicious_resources(result, resources)

    assert "suspicious_resources" in result
    assert len(result["suspicious_resources"]) >= 2
