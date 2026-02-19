"""Comprehensive tests for resource_analyzer.py - 100% coverage target."""

from unittest.mock import Mock, patch

from r2inspect.modules.resource_analyzer import ResourceAnalyzer


def test_resource_analyzer_init():
    """Test ResourceAnalyzer initialization."""
    adapter = Mock()
    analyzer = ResourceAnalyzer(adapter)
    assert analyzer.adapter == adapter


def test_analyze_basic():
    """Test basic analyze method."""
    adapter = Mock()
    analyzer = ResourceAnalyzer(adapter)
    
    with patch("r2inspect.modules.resource_analysis.run_resource_analysis") as mock_run:
        mock_run.return_value = {"test": "result"}
        result = analyzer.analyze()
        
        assert result == {"test": "result"}
        mock_run.assert_called_once()


def test_get_resource_directory_success():
    """Test _get_resource_directory with valid data."""
    adapter = Mock()
    analyzer = ResourceAnalyzer(adapter)
    analyzer._cmdj = Mock(return_value=[
        {"name": "EXPORT", "vaddr": 100, "paddr": 50, "size": 100},
        {"name": "RESOURCE", "vaddr": 200, "paddr": 150, "size": 500}
    ])
    
    result = analyzer._get_resource_directory()
    
    assert result is not None
    assert result["offset"] == 150
    assert result["size"] == 500
    assert result["virtual_address"] == 200


def test_get_resource_directory_no_data():
    """Test _get_resource_directory with no data."""
    adapter = Mock()
    analyzer = ResourceAnalyzer(adapter)
    analyzer._cmdj = Mock(return_value=[])
    
    result = analyzer._get_resource_directory()
    
    assert result is None


def test_get_resource_directory_exception():
    """Test _get_resource_directory with exception."""
    adapter = Mock()
    analyzer = ResourceAnalyzer(adapter)
    analyzer._cmdj = Mock(side_effect=Exception("Test error"))
    
    result = analyzer._get_resource_directory()
    
    assert result is None


def test_parse_resources_success():
    """Test _parse_resources with valid resources."""
    adapter = Mock()
    analyzer = ResourceAnalyzer(adapter)
    analyzer._cmdj = Mock(return_value=[
        {
            "name": "RT_ICON",
            "type": "ICON",
            "type_id": 3,
            "lang": "en-US",
            "paddr": 1000,
            "size": 256,
            "vaddr": 2000
        }
    ])
    analyzer._analyze_resource_data = Mock()
    
    result = analyzer._parse_resources()
    
    assert len(result) == 1
    assert result[0]["name"] == "RT_ICON"
    assert result[0]["size"] == 256


def test_parse_resources_no_data():
    """Test _parse_resources with no resources."""
    adapter = Mock()
    analyzer = ResourceAnalyzer(adapter)
    analyzer._cmdj = Mock(return_value=None)
    analyzer._parse_resources_manual = Mock(return_value=[])
    
    result = analyzer._parse_resources()
    
    assert result == []


def test_parse_resources_exception():
    """Test _parse_resources with exception."""
    adapter = Mock()
    analyzer = ResourceAnalyzer(adapter)
    analyzer._cmdj = Mock(side_effect=Exception("Parse error"))
    analyzer._parse_resources_manual = Mock(return_value=[])
    
    result = analyzer._parse_resources()
    
    assert result == []


def test_get_rsrc_section_found():
    """Test _get_rsrc_section when section exists."""
    adapter = Mock()
    analyzer = ResourceAnalyzer(adapter)
    analyzer._cmdj = Mock(return_value=[
        {"name": ".text", "paddr": 100},
        {"name": ".rsrc", "paddr": 2000, "size": 5000}
    ])
    
    result = analyzer._get_rsrc_section()
    
    assert result is not None
    assert result["name"] == ".rsrc"
    assert result["paddr"] == 2000


def test_get_rsrc_section_not_found():
    """Test _get_rsrc_section when section not found."""
    adapter = Mock()
    analyzer = ResourceAnalyzer(adapter)
    analyzer._cmdj = Mock(return_value=[
        {"name": ".text", "paddr": 100}
    ])
    
    result = analyzer._get_rsrc_section()
    
    assert result is None


def test_is_valid_dir_header_valid():
    """Test _is_valid_dir_header with valid data."""
    analyzer = ResourceAnalyzer(Mock())
    data = [0] * 16
    
    assert analyzer._is_valid_dir_header(data) is True


def test_is_valid_dir_header_invalid():
    """Test _is_valid_dir_header with invalid data."""
    analyzer = ResourceAnalyzer(Mock())
    
    assert analyzer._is_valid_dir_header(None) is False
    assert analyzer._is_valid_dir_header([0] * 10) is False


def test_get_dir_total_entries():
    """Test _get_dir_total_entries calculation."""
    analyzer = ResourceAnalyzer(Mock())
    data = [0] * 16
    data[12] = 2  # named entries
    data[13] = 0
    data[14] = 3  # id entries
    data[15] = 0
    
    result = analyzer._get_dir_total_entries(data)
    
    assert result == 5


def test_analyze_resource_types():
    """Test _analyze_resource_types."""
    analyzer = ResourceAnalyzer(Mock())
    result = {}
    resources = [
        {"type_name": "RT_ICON", "size": 100},
        {"type_name": "RT_ICON", "size": 200},
        {"type_name": "RT_VERSION", "size": 300}
    ]
    
    analyzer._analyze_resource_types(result, resources)
    
    assert "resource_types" in result
    assert len(result["resource_types"]) == 2
    assert result["total_size"] == 600


def test_calculate_entropy():
    """Test _calculate_entropy method."""
    analyzer = ResourceAnalyzer(Mock())
    data = [0, 1, 2, 3, 4, 5, 6, 7] * 10
    
    result = analyzer._calculate_entropy(data)
    
    assert isinstance(result, float)
    assert 0 <= result <= 8


def test_extract_version_info():
    """Test _extract_version_info method."""
    analyzer = ResourceAnalyzer(Mock())
    result = {}
    resources = [
        {"type_name": "RT_VERSION", "offset": 1000, "size": 512}
    ]
    analyzer._parse_version_info = Mock(return_value={"file_version": "1.0"})
    
    analyzer._extract_version_info(result, resources)
    
    assert "version_info" in result


def test_extract_version_info_exception():
    """Test _extract_version_info with exception."""
    analyzer = ResourceAnalyzer(Mock())
    result = {}
    resources = [
        {"type_name": "RT_VERSION", "offset": 1000, "size": 512}
    ]
    analyzer._parse_version_info = Mock(side_effect=Exception("Parse error"))
    
    analyzer._extract_version_info(result, resources)
    
    assert "version_info" not in result


def test_find_vs_signature():
    """Test _find_vs_signature method."""
    analyzer = ResourceAnalyzer(Mock())
    data = [0] * 100
    data[50:54] = [0xBD, 0x04, 0xEF, 0xFE]
    
    result = analyzer._find_vs_signature(data)
    
    assert result == 50


def test_find_vs_signature_not_found():
    """Test _find_vs_signature when not found."""
    analyzer = ResourceAnalyzer(Mock())
    data = [0] * 100
    
    result = analyzer._find_vs_signature(data)
    
    assert result == -1


def test_extract_manifest():
    """Test _extract_manifest method."""
    analyzer = ResourceAnalyzer(Mock())
    result = {}
    resources = [
        {"type_name": "RT_MANIFEST", "offset": 1000, "size": 512}
    ]
    analyzer._read_resource_as_string = Mock(return_value='<?xml version="1.0"?><assembly><requestedExecutionLevel level="requireAdministrator"/></assembly>')
    
    analyzer._extract_manifest(result, resources)
    
    assert "manifest" in result
    assert result["manifest"]["requires_admin"] is True


def test_extract_icons():
    """Test _extract_icons method."""
    analyzer = ResourceAnalyzer(Mock())
    result = {}
    resources = [
        {"type_name": "RT_ICON", "size": 256, "offset": 1000, "entropy": 5.5},
        {"type_name": "RT_GROUP_ICON", "size": 128, "offset": 2000, "entropy": 7.8}
    ]
    
    analyzer._extract_icons(result, resources)
    
    assert "icons" in result
    assert len(result["icons"]) == 2
    assert result["icons"][1]["suspicious"] == "High entropy (possibly encrypted)"


def test_extract_strings():
    """Test _extract_strings method."""
    analyzer = ResourceAnalyzer(Mock())
    result = {}
    resources = [
        {"type_name": "RT_STRING", "offset": 1000, "size": 256}
    ]
    analyzer._read_resource_as_string = Mock(return_value="Test string data")
    
    with patch("r2inspect.modules.resource_analyzer.split_null_terminated", return_value=["string1", "string2"]):
        analyzer._extract_strings(result, resources)
    
    assert "strings" in result
    assert len(result["strings"]) == 2


def test_calculate_statistics():
    """Test _calculate_statistics method."""
    analyzer = ResourceAnalyzer(Mock())
    result = {}
    resources = [
        {"size": 100, "entropy": 5.5, "type_name": "RT_ICON"},
        {"size": 200, "entropy": 6.0, "type_name": "RT_VERSION"},
        {"size": 0, "entropy": 0, "type_name": "RT_MANIFEST"}
    ]
    
    analyzer._calculate_statistics(result, resources)
    
    assert "statistics" in result
    stats = result["statistics"]
    assert stats["total_resources"] == 3
    assert stats["total_size"] == 300
    assert stats["unique_types"] == 3


def test_check_suspicious_resources():
    """Test _check_suspicious_resources method."""
    analyzer = ResourceAnalyzer(Mock())
    analyzer._cmdj = Mock(return_value=[0x4D, 0x5A])  # MZ header
    result = {}
    resources = [
        {"name": "res1", "type_name": "RT_RCDATA", "size": 100000, "entropy": 7.8, "offset": 1000},
        {"name": "res2", "type_name": "RT_ICON", "size": 256, "entropy": 7.9, "offset": 2000}
    ]
    
    analyzer._check_suspicious_resources(result, resources)
    
    assert "suspicious_resources" in result


def test_check_resource_entropy():
    """Test _check_resource_entropy method."""
    analyzer = ResourceAnalyzer(Mock())
    
    # High entropy non-icon resource
    res1 = {"name": "test", "type_name": "RT_RCDATA", "entropy": 7.8, "size": 1000}
    result1 = analyzer._check_resource_entropy(res1)
    assert len(result1) == 1
    
    # Icon with high entropy (ignored)
    res2 = {"name": "icon", "type_name": "RT_ICON", "entropy": 7.9, "size": 500}
    result2 = analyzer._check_resource_entropy(res2)
    assert len(result2) == 0


def test_check_resource_size():
    """Test _check_resource_size method."""
    analyzer = ResourceAnalyzer(Mock())
    
    # Large resource
    res1 = {"name": "test", "type_name": "RT_RCDATA", "size": 2 * 1024 * 1024}
    result1 = analyzer._check_resource_size(res1)
    assert len(result1) == 1
    
    # Small resource
    res2 = {"name": "test", "type_name": "RT_ICON", "size": 256}
    result2 = analyzer._check_resource_size(res2)
    assert len(result2) == 0


def test_check_resource_rcdata():
    """Test _check_resource_rcdata method."""
    analyzer = ResourceAnalyzer(Mock())
    
    # Large RCDATA
    res1 = {"name": "test", "type_name": "RT_RCDATA", "size": 20000, "entropy": 6.5}
    result1 = analyzer._check_resource_rcdata(res1)
    assert len(result1) == 1
    
    # Small RCDATA
    res2 = {"name": "test", "type_name": "RT_RCDATA", "size": 100, "entropy": 5.0}
    result2 = analyzer._check_resource_rcdata(res2)
    assert len(result2) == 0


def test_check_resource_embedded_pe():
    """Test _check_resource_embedded_pe method."""
    analyzer = ResourceAnalyzer(Mock())
    analyzer._cmdj = Mock(return_value=[0x4D, 0x5A])  # MZ header
    
    res = {"name": "test", "type_name": "RT_RCDATA", "size": 2000, "offset": 1000}
    result = analyzer._check_resource_embedded_pe(res)
    
    assert len(result) == 1
    assert "embedded PE" in result[0]["reason"]


def test_find_pattern():
    """Test _find_pattern method."""
    analyzer = ResourceAnalyzer(Mock())
    data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    pattern = [3, 4, 5]
    
    result = analyzer._find_pattern(data, pattern)
    
    assert result == 3


def test_find_pattern_not_found():
    """Test _find_pattern when pattern not found."""
    analyzer = ResourceAnalyzer(Mock())
    data = [0, 1, 2, 3, 4, 5]
    pattern = [9, 10]
    
    result = analyzer._find_pattern(data, pattern)
    
    assert result == -1


def test_read_resource_as_string_utf16():
    """Test _read_resource_as_string with UTF-16."""
    analyzer = ResourceAnalyzer(Mock())
    analyzer._cmdj = Mock(return_value=list("Test".encode("utf-16le")))
    
    result = analyzer._read_resource_as_string(1000, 100)
    
    assert result is not None
    assert "Test" in result


def test_read_resource_as_string_utf8():
    """Test _read_resource_as_string with UTF-8."""
    analyzer = ResourceAnalyzer(Mock())
    analyzer._cmdj = Mock(return_value=list("Test".encode("utf-8")))
    
    result = analyzer._read_resource_as_string(1000, 100)
    
    assert result is not None


def test_read_resource_as_string_invalid():
    """Test _read_resource_as_string with invalid offset."""
    analyzer = ResourceAnalyzer(Mock())
    
    result = analyzer._read_resource_as_string(0, 0)
    
    assert result is None


def test_parse_version_info_no_data():
    """Test _parse_version_info with no data."""
    analyzer = ResourceAnalyzer(Mock())
    analyzer._read_version_info_data = Mock(return_value=None)
    
    result = analyzer._parse_version_info(1000, 512)
    
    assert result is None


def test_extract_version_strings():
    """Test _extract_version_strings method."""
    analyzer = ResourceAnalyzer(Mock())
    analyzer._read_version_string_value = Mock(side_effect=lambda data, key: key if key == "CompanyName" else "")
    
    data = [0] * 1000
    result = analyzer._extract_version_strings(data)
    
    assert "CompanyName" in result
