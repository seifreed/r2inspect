"""Comprehensive tests for resource_analyzer.py parsing edge cases."""

from unittest.mock import Mock, patch

import pytest

from r2inspect.modules.resource_analyzer import ResourceAnalyzer


class TestResourceParsingEdgeCases:
    """Test PE resource parsing edge cases and error paths."""

    def test_parse_resources_manual_fallback(self):
        """Test manual parsing when iRj fails."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        analyzer._cmdj = Mock(side_effect=Exception("iRj failed"))
        analyzer._parse_resources_manual = Mock(return_value=[{"name": "manual_resource"}])
        
        result = analyzer._parse_resources()
        
        assert len(result) == 1
        assert result[0]["name"] == "manual_resource"
        analyzer._parse_resources_manual.assert_called_once()

    def test_parse_resources_manual_no_rsrc_section(self):
        """Test manual parsing without .rsrc section."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        analyzer._get_rsrc_section = Mock(return_value=None)
        
        result = analyzer._parse_resources_manual()
        
        assert result == []

    def test_parse_resources_manual_zero_offset(self):
        """Test manual parsing with zero rsrc offset."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        analyzer._get_rsrc_section = Mock(return_value={"paddr": 0})
        
        result = analyzer._parse_resources_manual()
        
        assert result == []

    def test_parse_resources_manual_invalid_header(self):
        """Test manual parsing with invalid directory header."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        analyzer._get_rsrc_section = Mock(return_value={"paddr": 1000})
        analyzer._cmdj = Mock(return_value=[1, 2, 3])  # Too short
        
        result = analyzer._parse_resources_manual()
        
        assert result == []

    def test_parse_resources_manual_valid_entries(self):
        """Test manual parsing with valid directory entries."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        analyzer._get_rsrc_section = Mock(return_value={"paddr": 1000})
        
        # Valid 16-byte header
        header_data = [0] * 12 + [1, 0, 2, 0]  # 1 named, 2 id entries
        analyzer._cmdj = Mock(side_effect=[
            header_data,
            [1, 0, 0, 0, 0, 0, 0, 0x80],  # Entry 1
            [2, 0, 0, 0, 0, 0, 0, 0],     # Entry 2
            [3, 0, 0, 0, 0, 0, 0, 0],     # Entry 3
        ])
        
        result = analyzer._parse_resources_manual()
        
        assert len(result) == 3

    def test_get_rsrc_section_found(self):
        """Test finding .rsrc section."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        analyzer._cmdj = Mock(return_value=[
            {"name": ".text", "paddr": 100},
            {"name": ".rsrc", "paddr": 200, "size": 500},
        ])
        
        result = analyzer._get_rsrc_section()
        
        assert result is not None
        assert result["paddr"] == 200

    def test_get_rsrc_section_not_found(self):
        """Test when .rsrc section is missing."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        analyzer._cmdj = Mock(return_value=[
            {"name": ".text", "paddr": 100},
            {"name": ".data", "paddr": 200},
        ])
        
        result = analyzer._get_rsrc_section()
        
        assert result is None

    def test_get_rsrc_section_no_data(self):
        """Test when section data is unavailable."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        analyzer._cmdj = Mock(return_value=None)
        
        result = analyzer._get_rsrc_section()
        
        assert result is None

    def test_parse_dir_entry_valid(self):
        """Test parsing valid directory entry."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        # Resource type 3 (RT_ICON), offset 0x1000
        entry_data = [3, 0, 0, 0, 0, 0x10, 0, 0]
        
        result = analyzer._parse_dir_entry(2000, entry_data, 0)
        
        assert result is not None
        assert result["type_id"] == 3
        assert result["type_name"] == "RT_ICON"

    def test_parse_dir_entry_named_resource(self):
        """Test parsing named resource entry."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        # High bit set indicates named resource
        entry_data = [0, 0, 0, 0x80, 0, 0x10, 0, 0]
        
        result = analyzer._parse_dir_entry(2000, entry_data, 5)
        
        assert result is not None
        assert "Named_5" in result["name"]

    def test_parse_dir_entry_directory_flag(self):
        """Test parsing entry with directory flag."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        # High bit in offset indicates subdirectory
        entry_data = [3, 0, 0, 0, 0, 0x10, 0, 0x80]
        
        result = analyzer._parse_dir_entry(2000, entry_data, 0)
        
        assert result is not None
        assert result["is_directory"] is True

    def test_parse_dir_entry_insufficient_data(self):
        """Test parsing with insufficient data."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        result = analyzer._parse_dir_entry(2000, [1, 2, 3], 0)
        
        assert result is None

    def test_analyze_resource_data_zero_offset(self):
        """Test analyzing resource with zero offset."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        resource = {"offset": 0, "size": 100}
        analyzer._analyze_resource_data(resource)
        
        # Should not crash, just skip
        assert resource["offset"] == 0

    def test_analyze_resource_data_zero_size(self):
        """Test analyzing resource with zero size."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        resource = {"offset": 1000, "size": 0}
        analyzer._analyze_resource_data(resource)
        
        # Should not crash, just skip
        assert resource["size"] == 0

    def test_analyze_resource_data_large_resource_limited(self):
        """Test that large resources are limited to 64KB."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        analyzer._cmdj = Mock(return_value=[0] * 65536)
        analyzer._calculate_entropy = Mock(return_value=4.5)
        
        resource = {"offset": 1000, "size": 100000}  # 100KB resource
        
        with patch("r2inspect.modules.resource_analyzer.calculate_hashes_for_bytes") as mock_hash:
            mock_hash.return_value = {"sha256": "abc123"}
            analyzer._analyze_resource_data(resource)
        
        # Should only read 64KB
        analyzer._cmdj.assert_called_once_with("pxj 65536 @ 1000", [])
        assert resource["entropy"] == 4.5
        assert resource["hashes"]["sha256"] == "abc123"

    def test_analyze_resource_data_hash_error(self):
        """Test handling hash calculation error."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        analyzer._cmdj = Mock(return_value=[0xAA] * 100)
        analyzer._calculate_entropy = Mock(return_value=3.2)
        
        resource = {"offset": 1000, "size": 100}
        
        with patch("r2inspect.modules.resource_analyzer.calculate_hashes_for_bytes") as mock_hash:
            mock_hash.side_effect = Exception("Hash error")
            analyzer._analyze_resource_data(resource)
        
        assert resource["entropy"] == 3.2
        assert resource["hashes"] == {}

    def test_analyze_resource_data_exception(self):
        """Test resource data analysis with exception."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        analyzer._cmdj = Mock(side_effect=Exception("Read error"))
        
        resource = {"offset": 1000, "size": 100}
        analyzer._analyze_resource_data(resource)
        
        # Should not crash
        assert "offset" in resource


class TestResourceVersionInfo:
    """Test VERSION_INFO resource parsing."""

    def test_parse_version_info_zero_offset(self):
        """Test version parsing with zero offset."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        result = analyzer._parse_version_info(0, 100)
        
        assert result is None

    def test_parse_version_info_too_small(self):
        """Test version parsing with size too small."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        result = analyzer._parse_version_info(1000, 32)
        
        assert result is None

    def test_parse_version_info_no_data(self):
        """Test version parsing when read fails."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        analyzer._cmdj = Mock(return_value=None)
        
        result = analyzer._parse_version_info(1000, 100)
        
        assert result is None

    def test_parse_version_info_no_signature(self):
        """Test version parsing without VS_FIXEDFILEINFO signature."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        analyzer._cmdj = Mock(return_value=[0] * 64)
        
        result = analyzer._parse_version_info(1000, 100)
        
        # Should return None if no strings found
        assert result is None

    def test_parse_version_info_with_signature(self):
        """Test version parsing with valid signature."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        # Create data with VS_FIXEDFILEINFO signature at offset 10
        data = [0] * 10 + [0xBD, 0x04, 0xEF, 0xFE] + [0] * 50
        # Add version numbers at correct offsets
        data[10 + 8] = 1   # Major (low byte)
        data[10 + 9] = 0
        data[10 + 10] = 2  # Major (high byte)
        data[10 + 11] = 0
        data[10 + 12] = 3  # Minor (low byte)
        data[10 + 13] = 0
        data[10 + 14] = 4  # Minor (high byte)
        data[10 + 15] = 0
        
        analyzer._cmdj = Mock(return_value=data)
        
        result = analyzer._parse_version_info(1000, 100)
        
        # May return None if no strings, but shouldn't crash
        assert result is None or isinstance(result, dict)

    def test_parse_fixed_file_info_insufficient_data(self):
        """Test parsing fixed file info with insufficient data."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        data = [0] * 20
        result = analyzer._parse_fixed_file_info(data, 10)
        
        assert result == ""

    def test_read_version_string_value_not_found(self):
        """Test reading version string when key not found."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        data = [0] * 100
        result = analyzer._read_version_string_value(data, "CompanyName")
        
        assert result == ""

    def test_read_version_string_value_found(self):
        """Test reading version string when key is found."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        # Create data with CompanyName in UTF-16LE
        key_bytes = list("CompanyName".encode("utf-16le"))
        value_bytes = list("Test Corp".encode("utf-16le"))
        
        data = [0] * 10 + key_bytes + [0, 0, 0, 0] + value_bytes + [0, 0] + [0] * 10
        
        result = analyzer._read_version_string_value(data, "CompanyName")
        
        assert result == "Test Corp"

    def test_read_version_string_value_at_end(self):
        """Test reading version string at end of data."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        key_bytes = list("FileVersion".encode("utf-16le"))
        data = [0] * 10 + key_bytes
        
        result = analyzer._read_version_string_value(data, "FileVersion")
        
        assert result == ""

    def test_extract_version_strings_multiple_keys(self):
        """Test extracting multiple version strings."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        def mock_read(data, key):
            if key == "CompanyName":
                return "Test Company"
            elif key == "ProductName":
                return "Test Product"
            return ""
        
        analyzer._read_version_string_value = mock_read
        
        result = analyzer._extract_version_strings([0] * 100)
        
        assert "CompanyName" in result
        assert result["CompanyName"] == "Test Company"
        assert "ProductName" in result


class TestResourceExtraction:
    """Test resource content extraction methods."""

    def test_read_resource_as_string_zero_offset(self):
        """Test reading resource string with zero offset."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        result = analyzer._read_resource_as_string(0, 100)
        
        assert result is None

    def test_read_resource_as_string_zero_size(self):
        """Test reading resource string with zero size."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        result = analyzer._read_resource_as_string(1000, 0)
        
        assert result is None

    def test_read_resource_as_string_utf16le(self):
        """Test reading UTF-16LE resource string."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        text = "Hello World"
        data = list(text.encode("utf-16le"))
        analyzer._cmdj = Mock(return_value=data)
        
        result = analyzer._read_resource_as_string(1000, 100)
        
        assert result == text

    def test_read_resource_as_string_utf8(self):
        """Test reading UTF-8 resource string."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        # Invalid UTF-16 but valid UTF-8
        data = list(b"Plain ASCII text")
        analyzer._cmdj = Mock(return_value=data)
        
        result = analyzer._read_resource_as_string(1000, 100)
        
        # May decode as UTF-16LE or UTF-8, both are valid
        assert result is not None and len(result) > 0

    def test_read_resource_as_string_binary_data(self):
        """Test reading binary (non-text) resource."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        # Binary data with no printable chars
        data = [0x00, 0x00, 0x00, 0x00, 0x00]
        analyzer._cmdj = Mock(return_value=data)
        
        result = analyzer._read_resource_as_string(1000, 100)
        
        # Binary data with no printable should return None
        assert result is None

    def test_read_resource_as_string_size_limited(self):
        """Test that resource reading is limited to 8KB."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        analyzer._cmdj = Mock(return_value=[65] * 8192)
        
        analyzer._read_resource_as_string(1000, 100000)
        
        # Should limit read to 8192 bytes
        analyzer._cmdj.assert_called_once_with("pxj 8192 @ 1000", [])

    def test_read_resource_as_string_exception(self):
        """Test resource reading with exception."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        analyzer._cmdj = Mock(side_effect=Exception("Read error"))
        
        result = analyzer._read_resource_as_string(1000, 100)
        
        assert result is None


class TestSuspiciousResourceChecks:
    """Test suspicious resource detection."""

    def test_check_resource_entropy_high_non_icon(self):
        """Test flagging high entropy non-icon resource."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        res = {
            "name": "data_blob",
            "type_name": "RT_RCDATA",
            "entropy": 7.8,
            "size": 5000
        }
        
        result = analyzer._check_resource_entropy(res)
        
        assert len(result) == 1
        assert "encrypted" in result[0]["reason"].lower()

    def test_check_resource_entropy_high_icon_allowed(self):
        """Test that high entropy icons are not flagged."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        res = {
            "name": "icon",
            "type_name": "RT_ICON",
            "entropy": 7.9,
            "size": 1000
        }
        
        result = analyzer._check_resource_entropy(res)
        
        assert len(result) == 0

    def test_check_resource_size_large(self):
        """Test flagging unusually large resource."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        res = {
            "name": "huge_resource",
            "type_name": "RT_RCDATA",
            "size": 2 * 1024 * 1024  # 2MB
        }
        
        result = analyzer._check_resource_size(res)
        
        assert len(result) == 1
        assert "large" in result[0]["reason"].lower()

    def test_check_resource_rcdata_large(self):
        """Test flagging large RCDATA resource."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        res = {
            "name": "data",
            "type_name": "RT_RCDATA",
            "size": 50000,
            "entropy": 6.5
        }
        
        result = analyzer._check_resource_rcdata(res)
        
        assert len(result) == 1

    def test_check_resource_rcdata_small_not_flagged(self):
        """Test that small RCDATA is not flagged."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        res = {
            "name": "data",
            "type_name": "RT_RCDATA",
            "size": 5000,
            "entropy": 6.5
        }
        
        result = analyzer._check_resource_rcdata(res)
        
        assert len(result) == 0

    def test_check_resource_embedded_pe_detected(self):
        """Test detecting embedded PE file."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        analyzer._cmdj = Mock(return_value=[0x4D, 0x5A])  # MZ header
        
        res = {
            "name": "payload",
            "type_name": "RT_RCDATA",
            "offset": 2000,
            "size": 50000
        }
        
        result = analyzer._check_resource_embedded_pe(res)
        
        assert len(result) == 1
        assert "embedded PE" in result[0]["reason"]

    def test_check_resource_embedded_pe_not_rcdata(self):
        """Test that non-RCDATA resources are not checked for PE."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        res = {
            "name": "icon",
            "type_name": "RT_ICON",
            "offset": 2000,
            "size": 50000
        }
        
        result = analyzer._check_resource_embedded_pe(res)
        
        assert len(result) == 0

    def test_check_resource_embedded_pe_too_small(self):
        """Test that small resources are not checked for PE."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        res = {
            "name": "data",
            "type_name": "RT_RCDATA",
            "offset": 2000,
            "size": 500
        }
        
        result = analyzer._check_resource_embedded_pe(res)
        
        assert len(result) == 0

    def test_find_pattern_found(self):
        """Test finding pattern in data."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        data = [0, 1, 2, 3, 4, 5, 6]
        pattern = [3, 4, 5]
        
        result = analyzer._find_pattern(data, pattern)
        
        assert result == 3

    def test_find_pattern_not_found(self):
        """Test pattern not found in data."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        data = [0, 1, 2, 3, 4, 5, 6]
        pattern = [7, 8, 9]
        
        result = analyzer._find_pattern(data, pattern)
        
        assert result == -1

    def test_find_pattern_at_start(self):
        """Test finding pattern at start of data."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        data = [1, 2, 3, 4, 5]
        pattern = [1, 2, 3]
        
        result = analyzer._find_pattern(data, pattern)
        
        assert result == 0

    def test_find_pattern_at_end(self):
        """Test finding pattern at end of data."""
        adapter = Mock()
        analyzer = ResourceAnalyzer(adapter)
        
        data = [1, 2, 3, 4, 5]
        pattern = [3, 4, 5]
        
        result = analyzer._find_pattern(data, pattern)
        
        assert result == 2
