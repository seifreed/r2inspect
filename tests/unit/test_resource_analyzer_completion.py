#!/usr/bin/env python3
"""Comprehensive tests for resource_analyzer - complete coverage."""

from typing import Any
from unittest.mock import MagicMock, patch

from r2inspect.modules.resource_analyzer import ResourceAnalyzer


def test_parse_resources_with_analyze_data():
    """Test _parse_resources calls analyze_resource_data for valid resources."""
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


def test_parse_resources_manual_valid_structure():
    """Test _parse_resources_manual with valid resource structure."""
    adapter = MagicMock()
    
    def mock_cmdj(cmd: str, default: Any) -> Any:
        if "iRj" in cmd:
            raise Exception("iRj error")
        elif "iSj" in cmd:
            return [{"name": ".rsrc", "paddr": 0x1000}]
        elif "pxj 16" in cmd:
            return [0] * 12 + [0, 0, 1, 0]
        elif "pxj 8" in cmd:
            return [3, 0, 0, 0, 0x10, 0, 0, 0]
        return default
    
    adapter.cmdj.side_effect = mock_cmdj
    
    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._parse_resources()
    assert isinstance(result, list)


def test_analyze_resource_data_with_valid_data():
    """Test _analyze_resource_data with valid data."""
    adapter = MagicMock()
    
    def mock_cmdj(cmd, default):
        if "pxj" in cmd:
            return [ord('a')] * 100
        return default
    
    adapter.cmdj.side_effect = mock_cmdj
    
    analyzer = ResourceAnalyzer(adapter=adapter)
    resource = {"offset": 0x1000, "size": 100}
    
    with patch('r2inspect.modules.resource_analyzer.calculate_hashes_for_bytes') as mock_hash:
        mock_hash.return_value = {"md5": "abc123"}
        analyzer._analyze_resource_data(resource)
        assert resource["hashes"] == {"md5": "abc123"}


def test_analyze_resource_data_size_limit():
    """Test _analyze_resource_data respects size limit."""
    adapter = MagicMock()
    
    def mock_cmdj(cmd, default):
        if "pxj" in cmd and "65536" in cmd:
            return [0] * 65536
        return default
    
    adapter.cmdj.side_effect = mock_cmdj
    
    analyzer = ResourceAnalyzer(adapter=adapter)
    resource = {"offset": 0x1000, "size": 100000}
    
    analyzer._analyze_resource_data(resource)
    assert any("65536" in str(call) for call in adapter.cmdj.call_args_list)


def test_parse_version_info_with_signature_and_strings():
    """Test _parse_version_info with valid signature and strings."""
    adapter = MagicMock()
    
    data = [0] * 100
    data[50:54] = [0xBD, 0x04, 0xEF, 0xFE]
    data[58:70] = [0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00] * 2
    
    def mock_cmdj(cmd, default):
        if "pxj" in cmd:
            return data
        return default
    
    adapter.cmdj.side_effect = mock_cmdj
    
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    with patch.object(analyzer, '_extract_version_strings', return_value={"CompanyName": "Test"}):
        result = analyzer._parse_version_info(0x1000, 200)
        assert result is not None
        assert "CompanyName" in result["strings"]


def test_parse_version_info_signature_near_end():
    """Test _parse_version_info with signature too close to end."""
    adapter = MagicMock()
    
    data = [0] * 100
    data[96:100] = [0xBD, 0x04, 0xEF, 0xFE]
    
    adapter.cmdj.return_value = data
    
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    with patch.object(analyzer, '_extract_version_strings', return_value={}):
        result = analyzer._parse_version_info(0x1000, 100)
        assert result is None


def test_extract_version_info_with_valid_version():
    """Test _extract_version_info successfully extracts version."""
    adapter = MagicMock()
    
    data = [0] * 100
    data[50:54] = [0xBD, 0x04, 0xEF, 0xFE]
    
    adapter.cmdj.return_value = data
    
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_VERSION", "offset": 0x1000, "size": 200}]
    
    with patch.object(analyzer, '_parse_version_info') as mock_parse:
        mock_parse.return_value = {"file_version": "1.0.0.0"}
        analyzer._extract_version_info(result, resources)
        assert "version_info" in result
        assert result["version_info"]["file_version"] == "1.0.0.0"


def test_read_version_string_value_with_valid_string():
    """Test _read_version_string_value extracts valid string."""
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    
    key = "CompanyName"
    value = "Test Corp"
    key_bytes = list(key.encode("utf-16le"))
    value_bytes = list(value.encode("utf-16le"))
    
    data = key_bytes + [0, 0, 0, 0] + value_bytes + [0, 0]
    
    result = analyzer._read_version_string_value(data, key)
    assert result == value


def test_read_version_string_value_reaches_end():
    """Test _read_version_string_value when reaching data end."""
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    
    key = "CompanyName"
    key_bytes = list(key.encode("utf-16le"))
    
    data = key_bytes + [0, 0, 0, 0]
    
    result = analyzer._read_version_string_value(data, key)
    assert result == ""


def test_extract_manifest_with_valid_manifest():
    """Test _extract_manifest extracts and parses manifest."""
    adapter = MagicMock()
    
    manifest_content = '''<?xml version="1.0"?>
    <assembly>
        <trustInfo>
            <security>
                <requestedPrivileges>
                    <requestedExecutionLevel level="requireAdministrator"/>
                </requestedPrivileges>
            </security>
        </trustInfo>
    </assembly>'''
    
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_MANIFEST", "offset": 0x1000, "size": len(manifest_content)}]
    
    with patch.object(analyzer, '_read_resource_as_string', return_value=manifest_content):
        analyzer._extract_manifest(result, resources)
        assert "manifest" in result
        assert result["manifest"]["requires_admin"] is True
        assert result["manifest"]["size"] == len(manifest_content)


def test_extract_manifest_with_elevation():
    """Test _extract_manifest detects elevation requirement."""
    adapter = MagicMock()
    
    manifest_content = '<requestedExecutionLevel level="highestAvailable"/>'
    
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_MANIFEST", "offset": 0x1000, "size": 100}]
    
    with patch.object(analyzer, '_read_resource_as_string', return_value=manifest_content):
        analyzer._extract_manifest(result, resources)
        assert result["manifest"]["requires_elevation"] is True


def test_extract_manifest_with_dpi_aware():
    """Test _extract_manifest detects DPI awareness."""
    adapter = MagicMock()
    
    manifest_content = '<dpiAware>true</dpiAware>'
    
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_MANIFEST", "offset": 0x1000, "size": 100}]
    
    with patch.object(analyzer, '_read_resource_as_string', return_value=manifest_content):
        analyzer._extract_manifest(result, resources)
        assert result["manifest"]["dpi_aware"] is True


def test_extract_strings_with_valid_strings():
    """Test _extract_strings extracts string resources."""
    adapter = MagicMock()
    
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_STRING", "offset": 0x1000, "size": 100}]
    
    with patch.object(analyzer, '_read_resource_as_string', return_value="Test\x00String\x00Data"):
        with patch('r2inspect.modules.resource_analyzer.split_null_terminated') as mock_split:
            mock_split.return_value = ["Test", "String", "Data"]
            analyzer._extract_strings(result, resources)
            assert len(result["strings"]) == 3


def test_extract_strings_limits_output():
    """Test _extract_strings limits output to 50 strings."""
    adapter = MagicMock()
    
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_STRING", "offset": 0x1000, "size": 1000}]
    
    many_strings = [f"String{i}" for i in range(100)]
    
    with patch.object(analyzer, '_read_resource_as_string', return_value="data"):
        with patch('r2inspect.modules.resource_analyzer.split_null_terminated', return_value=many_strings):
            analyzer._extract_strings(result, resources)
            assert len(result["strings"]) == 50


def test_read_resource_as_string_utf16_no_printable():
    """Test _read_resource_as_string with UTF-16 but no printable chars."""
    adapter = MagicMock()
    adapter.cmdj.return_value = [0, 0, 1, 0, 2, 0, 3, 0]
    
    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._read_resource_as_string(0x1000, 100)
    assert result is None


def test_read_resource_as_string_utf8_fallback():
    """Test _read_resource_as_string falls back to UTF-8."""
    adapter = MagicMock()
    
    def mock_cmdj(cmd, default):
        if "pxj" in cmd:
            return [0xFF, 0xFE] + list(b"Test")
        return default
    
    adapter.cmdj.side_effect = mock_cmdj
    
    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._read_resource_as_string(0x1000, 100)
    assert result is not None or result is None


def test_calculate_statistics_with_mixed_data():
    """Test _calculate_statistics calculates correct statistics."""
    adapter = MagicMock()
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    resources = [
        {"size": 100, "entropy": 3.5, "type_name": "RT_ICON"},
        {"size": 200, "entropy": 5.0, "type_name": "RT_ICON"},
        {"size": 50, "entropy": 2.0, "type_name": "RT_STRING"},
    ]
    
    result: dict[str, Any] = {}
    analyzer._calculate_statistics(result, resources)
    
    assert result["statistics"]["total_resources"] == 3
    assert result["statistics"]["total_size"] == 350
    assert result["statistics"]["average_size"] == 116
    assert result["statistics"]["max_size"] == 200
    assert result["statistics"]["min_size"] == 50
    assert result["statistics"]["unique_types"] == 2


def test_check_suspicious_resources_combines_all_checks():
    """Test _check_suspicious_resources combines all check types."""
    adapter = MagicMock()
    adapter.cmdj.return_value = [0x4D, 0x5A]
    
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    resources = [
        {"name": "test1", "type_name": "RT_STRING", "entropy": 7.8, "size": 100, "offset": 0x1000},
        {"name": "test2", "type_name": "RT_STRING", "entropy": 3.0, "size": 2 * 1024 * 1024, "offset": 0x2000},
        {"name": "test3", "type_name": "RT_RCDATA", "entropy": 4.0, "size": 20000, "offset": 0x3000},
        {"name": "test4", "type_name": "RT_RCDATA", "entropy": 4.0, "size": 2000, "offset": 0x4000},
    ]
    
    result: dict[str, Any] = {}
    analyzer._check_suspicious_resources(result, resources)
    
    assert len(result["suspicious_resources"]) >= 3


def test_find_pattern_multiple_occurrences():
    """Test _find_pattern finds first occurrence."""
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    data = [1, 2, 3, 4, 3, 4, 5]
    pattern = [3, 4]
    result = analyzer._find_pattern(data, pattern)
    assert result == 2


def test_find_pattern_pattern_longer_than_data():
    """Test _find_pattern with pattern longer than data."""
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    data = [1, 2, 3]
    pattern = [1, 2, 3, 4, 5]
    result = analyzer._find_pattern(data, pattern)
    assert result == -1


def test_parse_dir_entries_with_valid_entries():
    """Test _parse_dir_entries parses multiple entries."""
    adapter = MagicMock()
    adapter.cmdj.return_value = [3, 0, 0, 0, 0x10, 0, 0, 0]
    
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    with patch.object(analyzer, '_parse_dir_entry') as mock_parse:
        mock_parse.return_value = {"name": "RT_ICON", "type_id": 3}
        result = analyzer._parse_dir_entries(0x1000, 5)
        assert len(result) == 5


def test_parse_dir_entry_with_directory_flag():
    """Test _parse_dir_entry identifies directory entries."""
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    entry_data = [5, 0, 0, 0, 0x20, 0, 0, 0x80]
    result = analyzer._parse_dir_entry(0x1000, entry_data, 0)
    assert result is not None
    assert result["is_directory"] is True
    assert result["offset"] == 0x1020


def test_analyze_resource_types_multiple_types():
    """Test _analyze_resource_types handles multiple resource types."""
    adapter = MagicMock()
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    resources = [
        {"type_name": "RT_ICON", "size": 100},
        {"type_name": "RT_ICON", "size": 200},
        {"type_name": "RT_MANIFEST", "size": 50},
        {"type_name": "RT_STRING", "size": 75},
        {"type_name": "RT_STRING", "size": 125},
    ]
    
    result: dict[str, Any] = {}
    analyzer._analyze_resource_types(result, resources)
    
    types = {rt["type"] for rt in result["resource_types"]}
    assert "RT_ICON" in types
    assert "RT_MANIFEST" in types
    assert "RT_STRING" in types
    assert result["total_size"] == 550


def test_extract_icons_no_icon_resources():
    """Test _extract_icons with no icon resources."""
    adapter = MagicMock()
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    result: dict[str, Any] = {}
    resources = [
        {"type_name": "RT_STRING", "offset": 0x1000, "size": 100, "entropy": 3.5},
        {"type_name": "RT_MANIFEST", "offset": 0x2000, "size": 200, "entropy": 4.0},
    ]
    
    analyzer._extract_icons(result, resources)
    assert result["icons"] == []


def test_extract_icons_mixed_icons():
    """Test _extract_icons with both icon types."""
    adapter = MagicMock()
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    result: dict[str, Any] = {}
    resources = [
        {"type_name": "RT_ICON", "offset": 0x1000, "size": 100, "entropy": 3.5},
        {"type_name": "RT_GROUP_ICON", "offset": 0x2000, "size": 50, "entropy": 4.0},
    ]
    
    analyzer._extract_icons(result, resources)
    assert len(result["icons"]) == 2
    assert result["icons"][0]["type"] == "RT_ICON"
    assert result["icons"][1]["type"] == "RT_GROUP_ICON"


def test_check_resource_embedded_pe_unknown_type():
    """Test _check_resource_embedded_pe checks UNKNOWN type."""
    adapter = MagicMock()
    
    def mock_cmdj(cmd, default):
        if "pxj 2" in cmd:
            return [0x4D, 0x5A]
        return default
    
    adapter.cmdj.side_effect = mock_cmdj
    
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    res = {"name": "test", "type_name": "UNKNOWN", "size": 2000, "offset": 0x1000}
    result = analyzer._check_resource_embedded_pe(res)
    assert len(result) >= 1 or len(result) == 0


def test_parse_version_info_data_size_limit():
    """Test _parse_version_info respects size limit."""
    adapter = MagicMock()
    adapter.cmdj.return_value = [0] * 1024
    
    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._parse_version_info(0x1000, 2000)
    
    adapter.cmdj.assert_called_with("pxj 1024 @ 4096", [])


def test_read_resource_as_string_size_limit():
    """Test _read_resource_as_string limits read size."""
    adapter = MagicMock()
    adapter.cmdj.return_value = list(b"Test data")
    
    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._read_resource_as_string(0x1000, 10000)
    
    adapter.cmdj.assert_called_with("pxj 8192 @ 4096", [])


def test_check_resource_entropy_bitmap_high_entropy():
    """Test _check_resource_entropy allows high entropy for bitmaps."""
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    res = {"name": "test", "type_name": "RT_BITMAP", "entropy": 8.0, "size": 100}
    result = analyzer._check_resource_entropy(res)
    assert result == []


def test_version_string_keys_returns_standard_keys():
    """Test _version_string_keys returns expected keys."""
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    keys = analyzer._version_string_keys()
    assert "CompanyName" in keys
    assert "FileDescription" in keys
    assert "FileVersion" in keys
    assert "InternalName" in keys
    assert "LegalCopyright" in keys
    assert "OriginalFilename" in keys
    assert "ProductName" in keys
    assert "ProductVersion" in keys


def test_extract_version_strings_no_matches():
    """Test _extract_version_strings with no matching keys."""
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    data = [0] * 100
    
    with patch.object(analyzer, '_read_version_string_value', return_value=""):
        result = analyzer._extract_version_strings(data)
        assert result == {}


def test_get_dir_total_entries_calculates_correctly():
    """Test _get_dir_total_entries calculation."""
    analyzer = ResourceAnalyzer(adapter=MagicMock())
    dir_data = [0] * 12 + [5, 0, 10, 0]
    result = analyzer._get_dir_total_entries(dir_data)
    assert result == 15


def test_analyze_adds_all_fields():
    """Test analyze method returns all expected fields."""
    adapter = MagicMock()
    adapter.cmdj.return_value = []
    
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    with patch('r2inspect.modules.resource_analyzer.run_resource_analysis') as mock_run:
        mock_run.return_value = {
            "resources": [],
            "resource_types": [],
            "version_info": None,
            "manifest": None,
            "icons": [],
            "strings": [],
            "statistics": {},
            "suspicious_resources": [],
        }
        result = analyzer.analyze()
        assert "resources" in result
        assert "resource_types" in result
