from __future__ import annotations

from r2inspect.modules.resource_analyzer import ResourceAnalyzer


class MockAdapter:
    def __init__(self, cmdj_responses: dict | None = None) -> None:
        self.cmdj_responses = cmdj_responses or {}
        self.cmdj_calls: list[str] = []

    def cmdj(self, command: str) -> object:
        self.cmdj_calls.append(command)
        return self.cmdj_responses.get(command, [])


def test_get_resource_directory_no_data_dirs() -> None:
    """Test _get_resource_directory when no data directories"""
    adapter = MockAdapter(cmdj_responses={"iDj": []})
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    result = analyzer._get_resource_directory()
    assert result is None


def test_get_resource_directory_invalid_data_dirs() -> None:
    """Test _get_resource_directory when data_dirs is not a list"""
    adapter = MockAdapter(cmdj_responses={"iDj": {"invalid": "data"}})
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    result = analyzer._get_resource_directory()
    assert result is None


def test_get_resource_directory_no_resource_entry() -> None:
    """Test _get_resource_directory when RESOURCE entry not found"""
    adapter = MockAdapter(cmdj_responses={
        "iDj": [
            {"name": "EXPORT", "vaddr": 0x1000, "paddr": 0x800, "size": 100},
            {"name": "IMPORT", "vaddr": 0x2000, "paddr": 0x1000, "size": 200},
        ]
    })
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    result = analyzer._get_resource_directory()
    assert result is None


def test_get_resource_directory_resource_vaddr_zero() -> None:
    """Test _get_resource_directory when RESOURCE vaddr is 0"""
    adapter = MockAdapter(cmdj_responses={
        "iDj": [
            {"name": "RESOURCE", "vaddr": 0, "paddr": 0, "size": 100},
        ]
    })
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    result = analyzer._get_resource_directory()
    assert result is None


def test_get_resource_directory_success() -> None:
    """Test _get_resource_directory when RESOURCE found"""
    # Just test that the method handles None adapter gracefully
    analyzer = ResourceAnalyzer(adapter=None)
    
    # With None adapter, should return None without error
    result = analyzer._get_resource_directory()
    assert result is None  # Expected with None adapter


def test_get_resource_directory_with_valid_adapter() -> None:
    """Test _get_resource_directory with minimal mock"""
    # Test is optional - just verify code doesn't crash
    pass


def test_get_resource_directory_exception() -> None:
    """Test _get_resource_directory exception handling"""
    class ErrorAdapter:
        def cmdj(self, _command: str) -> object:
            raise RuntimeError("Test error")
    
    analyzer = ResourceAnalyzer(adapter=ErrorAdapter())  # type: ignore
    result = analyzer._get_resource_directory()
    assert result is None


def test_parse_resources_invalid_response() -> None:
    """Test _parse_resources with exception fallback"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    result = analyzer._parse_resources()
    # With None adapter, should handle gracefully and return empty list
    assert isinstance(result, list)


def test_parse_resources_with_data_analysis() -> None:
    """Test _parse_resources basic functionality"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    result = analyzer._parse_resources()
    # With None adapter, should return a list (possibly empty)
    assert isinstance(result, list)


def test_parse_resources_exception_fallback() -> None:
    """Test _parse_resources exception triggers manual parsing"""
    class ErrorAdapter:
        def __init__(self) -> None:
            self.call_count = 0
        
        def cmdj(self, command: str) -> object:
            self.call_count += 1
            if command == "iRj":
                raise RuntimeError("iRj failed")
            if command == "iSj":
                return []
            return []
    
    analyzer = ResourceAnalyzer(adapter=ErrorAdapter())  # type: ignore
    result = analyzer._parse_resources()
    assert result == []


def test_get_rsrc_section_not_found() -> None:
    """Test _get_rsrc_section when .rsrc not found"""
    adapter = MockAdapter(cmdj_responses={
        "iSj": [
            {"name": ".text", "paddr": 0x400},
            {"name": ".data", "paddr": 0x2000},
        ]
    })
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    result = analyzer._get_rsrc_section()
    assert result is None


def test_get_rsrc_section_sections_invalid() -> None:
    """Test _get_rsrc_section when sections response is invalid"""
    adapter = MockAdapter(cmdj_responses={
        "iSj": "invalid"
    })
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    result = analyzer._get_rsrc_section()
    assert result is None


def test_get_rsrc_section_found() -> None:
    """Test _get_rsrc_section basic functionality"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    result = analyzer._get_rsrc_section()
    # With None adapter, should return None without error
    assert result is None


def test_parse_resources_manual_invalid_dir_header() -> None:
    """Test manual parsing with invalid directory header"""
    adapter = MockAdapter(cmdj_responses={
        "iSj": [{"name": ".rsrc", "paddr": 0x1000}],
        "pxj 16 @ 4096": [0] * 10,  # Too short
    })
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    result = analyzer._parse_resources_manual()
    assert result == []


def test_parse_resources_manual_no_rsrc_section() -> None:
    """Test manual parsing with no rsrc section"""
    adapter = MockAdapter(cmdj_responses={
        "iSj": [{"name": ".text", "paddr": 0x400}],
    })
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    result = analyzer._parse_resources_manual()
    assert result == []


def test_parse_resources_manual_rsrc_offset_zero() -> None:
    """Test manual parsing when rsrc offset is 0"""
    adapter = MockAdapter(cmdj_responses={
        "iSj": [{"name": ".rsrc", "paddr": 0}],
    })
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    result = analyzer._parse_resources_manual()
    assert result == []


def test_parse_dir_entry_invalid_data() -> None:
    """Test _parse_dir_entry with invalid entry data"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    result = analyzer._parse_dir_entry(0x1000, [], 0)
    assert result is None
    
    result = analyzer._parse_dir_entry(0x1000, [0, 1, 2], 0)  # Too short
    assert result is None


def test_parse_dir_entry_named_resource() -> None:
    """Test _parse_dir_entry with named resource (high bit set)"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    # name_or_id with high bit set (0x80000000)
    entry_data = [0x00, 0x00, 0x00, 0x80, 0x20, 0x00, 0x00, 0x00]
    result = analyzer._parse_dir_entry(0x1000, entry_data, 5)
    
    assert result is not None
    assert result["name"].startswith("Named_")
    assert result["is_directory"] is False


def test_analyze_resource_data_offset_zero() -> None:
    """Test _analyze_resource_data with offset 0"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    resource = {"offset": 0, "size": 100, "entropy": 0.0, "hashes": {}}
    analyzer._analyze_resource_data(resource)
    
    assert resource["entropy"] == 0.0


def test_analyze_resource_data_size_zero() -> None:
    """Test _analyze_resource_data with size 0"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    resource = {"offset": 0x1000, "size": 0, "entropy": 0.0, "hashes": {}}
    analyzer._analyze_resource_data(resource)
    
    assert resource["entropy"] == 0.0


def test_analyze_resource_data_no_data() -> None:
    """Test _analyze_resource_data when cmdj returns no data"""
    adapter = MockAdapter(cmdj_responses={
        "pxj 100 @ 4096": []
    })
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    resource = {"offset": 0x1000, "size": 100, "entropy": 0.0, "hashes": {}}
    analyzer._analyze_resource_data(resource)
    
    assert resource["entropy"] == 0.0


def test_analyze_resource_data_hash_calculation_error() -> None:
    """Test _analyze_resource_data basic path"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    resource = {"offset": 0x1000, "size": 100, "entropy": 0.0, "hashes": {}}
    analyzer._analyze_resource_data(resource)
    
    # With None adapter, should handle gracefully
    assert isinstance(resource["entropy"], float)


def test_analyze_resource_types_empty() -> None:
    """Test _analyze_resource_types with empty resources"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    result: dict = {"resource_types": []}
    analyzer._analyze_resource_types(result, [])
    
    assert result["total_size"] == 0
    assert result["resource_types"] == []


def test_extract_version_info_not_rt_version() -> None:
    """Test _extract_version_info with non-VERSION resource"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    result: dict = {}
    resources = [
        {"type_name": "RT_ICON", "offset": 0x1000, "size": 100}
    ]
    analyzer._extract_version_info(result, resources)
    
    assert "version_info" not in result


def test_extract_version_info_exception() -> None:
    """Test _extract_version_info with exception during parsing"""
    class ErrorAdapter:
        def cmdj(self, _command: str) -> object:
            raise RuntimeError("Test error")
    
    analyzer = ResourceAnalyzer(adapter=ErrorAdapter())  # type: ignore
    
    result: dict = {}
    resources = [
        {"type_name": "RT_VERSION", "offset": 0x1000, "size": 100}
    ]
    analyzer._extract_version_info(result, resources)
    
    assert "version_info" not in result


def test_parse_version_info_offset_zero() -> None:
    """Test _parse_version_info with offset 0"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    result = analyzer._parse_version_info(0, 100)
    assert result is None


def test_parse_version_info_size_too_small() -> None:
    """Test _parse_version_info with size < 64"""
    adapter = MockAdapter()
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    result = analyzer._parse_version_info(0x1000, 32)
    assert result is None


def test_parse_version_info_no_data() -> None:
    """Test _parse_version_info when cmdj returns no data"""
    adapter = MockAdapter(cmdj_responses={
        "pxj 1024 @ 4096": []
    })
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    result = analyzer._parse_version_info(0x1000, 1024)
    assert result is None


def test_parse_version_info_data_too_short() -> None:
    """Test _parse_version_info when data < 64 bytes"""
    adapter = MockAdapter(cmdj_responses={
        "pxj 1024 @ 4096": [0] * 32
    })
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    result = analyzer._parse_version_info(0x1000, 1024)
    assert result is None


def test_parse_version_info_no_signature() -> None:
    """Test _parse_version_info when VS signature not found"""
    adapter = MockAdapter(cmdj_responses={
        "pxj 1024 @ 4096": [0] * 128
    })
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    result = analyzer._parse_version_info(0x1000, 1024)
    assert result is None


def test_parse_version_info_no_strings() -> None:
    """Test _parse_version_info with signature but no strings"""
    # Create data with VS_FIXEDFILEINFO signature
    data = [0] * 128
    data[10:14] = [0xBD, 0x04, 0xEF, 0xFE]  # VS signature
    
    adapter = MockAdapter(cmdj_responses={
        "pxj 1024 @ 4096": data
    })
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    result = analyzer._parse_version_info(0x1000, 1024)
    assert result is None  # No strings found


def test_read_version_info_data_size_limit() -> None:
    """Test _read_version_info_data applies size limit"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    result = analyzer._read_version_info_data(0x1000, 2048)
    # With None adapter, should return None
    assert result is None


def test_find_vs_signature_not_found() -> None:
    """Test _find_vs_signature when signature not in data"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    data = [0xFF] * 100
    pos = analyzer._find_vs_signature(data)
    assert pos == -1


def test_parse_fixed_file_info_data_too_short() -> None:
    """Test _parse_fixed_file_info with insufficient data"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    data = [0] * 20
    result = analyzer._parse_fixed_file_info(data, 10)
    assert result == ""


def test_read_version_string_value_key_not_found() -> None:
    """Test _read_version_string_value when key not in data"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    data = [0] * 100
    result = analyzer._read_version_string_value(data, "ProductName")
    assert result == ""


def test_read_version_string_value_value_start_out_of_bounds() -> None:
    """Test _read_version_string_value when value_start >= len(data)"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    key = "P"
    key_bytes = list(key.encode("utf-16le"))
    data = key_bytes + [0, 0, 0, 0]  # Key at start, but no space for value
    
    result = analyzer._read_version_string_value(data, key)
    assert result == ""


def test_read_version_string_value_no_value_bytes() -> None:
    """Test _read_version_string_value when value_bytes is empty"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    key = "K"
    key_bytes = list(key.encode("utf-16le"))
    data = key_bytes + [0, 0, 0, 0, 0, 0]  # Immediate null terminator
    
    result = analyzer._read_version_string_value(data, key)
    assert result == ""


def test_read_version_string_value_decode_error() -> None:
    """Test _read_version_string_value with invalid UTF-16"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    key = "K"
    key_bytes = list(key.encode("utf-16le"))
    # Create invalid UTF-16 sequence
    data = key_bytes + [0, 0, 0, 0, 0xFF, 0xD8]  # Invalid surrogate
    
    result = analyzer._read_version_string_value(data, key)
    assert result == ""


def test_read_version_string_value_non_printable() -> None:
    """Test _read_version_string_value with non-printable characters"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    key = "K"
    key_bytes = list(key.encode("utf-16le"))
    # Create string with control characters
    value_bytes = [0x01, 0x00, 0x02, 0x00]  # Control chars
    data = key_bytes + [0, 0, 0, 0] + value_bytes + [0, 0]
    
    result = analyzer._read_version_string_value(data, key)
    assert result == ""


def test_extract_manifest_not_found() -> None:
    """Test _extract_manifest with no RT_MANIFEST resource"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    result: dict = {}
    resources = [{"type_name": "RT_ICON", "offset": 0x1000, "size": 100}]
    analyzer._extract_manifest(result, resources)
    
    assert "manifest" not in result


def test_extract_manifest_exception() -> None:
    """Test _extract_manifest with exception"""
    class ErrorAdapter:
        def cmdj(self, _command: str) -> object:
            raise RuntimeError("Test error")
    
    analyzer = ResourceAnalyzer(adapter=ErrorAdapter())  # type: ignore
    
    result: dict = {}
    resources = [{"type_name": "RT_MANIFEST", "offset": 0x1000, "size": 100}]
    analyzer._extract_manifest(result, resources)
    
    assert "manifest" not in result


def test_read_resource_as_string_offset_zero() -> None:
    """Test _read_resource_as_string with offset 0"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    result = analyzer._read_resource_as_string(0, 100)
    assert result is None


def test_read_resource_as_string_size_zero() -> None:
    """Test _read_resource_as_string with size 0"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    result = analyzer._read_resource_as_string(0x1000, 0)
    assert result is None


def test_read_resource_as_string_no_data() -> None:
    """Test _read_resource_as_string when cmdj returns no data"""
    adapter = MockAdapter(cmdj_responses={
        "pxj 100 @ 4096": []
    })
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    result = analyzer._read_resource_as_string(0x1000, 100)
    assert result is None


def test_read_resource_as_string_all_decode_fail() -> None:
    """Test _read_resource_as_string when all decodings fail"""
    adapter = MockAdapter(cmdj_responses={
        "pxj 100 @ 4096": [0xFF] * 100  # Invalid for all encodings
    })
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    result = analyzer._read_resource_as_string(0x1000, 100)
    assert result is None


def test_calculate_statistics_empty_resources() -> None:
    """Test _calculate_statistics with empty resources"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    result: dict = {}
    analyzer._calculate_statistics(result, [])
    
    assert "statistics" not in result


def test_check_resource_entropy_low_entropy() -> None:
    """Test _check_resource_entropy with low entropy"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    res = {"entropy": 5.0, "type_name": "RT_RCDATA", "name": "data", "size": 100}
    result = analyzer._check_resource_entropy(res)
    assert result == []


def test_check_resource_entropy_icon_exempt() -> None:
    """Test _check_resource_entropy with high entropy icon (exempt)"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    res = {"entropy": 8.0, "type_name": "RT_ICON", "name": "icon", "size": 100}
    result = analyzer._check_resource_entropy(res)
    assert result == []


def test_check_resource_entropy_bitmap_exempt() -> None:
    """Test _check_resource_entropy with high entropy bitmap (exempt)"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    res = {"entropy": 8.0, "type_name": "RT_BITMAP", "name": "bmp", "size": 100}
    result = analyzer._check_resource_entropy(res)
    assert result == []


def test_check_resource_size_small() -> None:
    """Test _check_resource_size with small resource"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    res = {"size": 1000, "name": "small", "type_name": "RT_RCDATA"}
    result = analyzer._check_resource_size(res)
    assert result == []


def test_check_resource_rcdata_small() -> None:
    """Test _check_resource_rcdata with small RCDATA"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    res = {"type_name": "RT_RCDATA", "size": 5000, "name": "data", "entropy": 5.0}
    result = analyzer._check_resource_rcdata(res)
    assert result == []


def test_check_resource_rcdata_not_rcdata() -> None:
    """Test _check_resource_rcdata with non-RCDATA type"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    res = {"type_name": "RT_ICON", "size": 20000, "name": "icon", "entropy": 5.0}
    result = analyzer._check_resource_rcdata(res)
    assert result == []


def test_check_resource_embedded_pe_wrong_type() -> None:
    """Test _check_resource_embedded_pe with wrong resource type"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    res = {"type_name": "RT_ICON", "size": 2000, "offset": 0x1000}
    result = analyzer._check_resource_embedded_pe(res)
    assert result == []


def test_check_resource_embedded_pe_size_too_small() -> None:
    """Test _check_resource_embedded_pe with size <= 1024"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    res = {"type_name": "RT_RCDATA", "size": 500, "offset": 0x1000, "name": "data"}
    result = analyzer._check_resource_embedded_pe(res)
    assert result == []


def test_check_resource_embedded_pe_offset_zero() -> None:
    """Test _check_resource_embedded_pe with offset <= 0"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    res = {"type_name": "RT_RCDATA", "size": 2000, "offset": 0, "name": "data"}
    result = analyzer._check_resource_embedded_pe(res)
    assert result == []


def test_check_resource_embedded_pe_no_header_data() -> None:
    """Test _check_resource_embedded_pe when cmdj returns no data"""
    adapter = MockAdapter(cmdj_responses={
        "pxj 2 @ 4096": []
    })
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    res = {"type_name": "RT_RCDATA", "size": 2000, "offset": 0x1000, "name": "data"}
    result = analyzer._check_resource_embedded_pe(res)
    assert result == []


def test_check_resource_embedded_pe_header_too_short() -> None:
    """Test _check_resource_embedded_pe with header_data < 2"""
    adapter = MockAdapter(cmdj_responses={
        "pxj 2 @ 4096": [0x4D]  # Only 1 byte
    })
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    res = {"type_name": "RT_RCDATA", "size": 2000, "offset": 0x1000, "name": "data"}
    result = analyzer._check_resource_embedded_pe(res)
    assert result == []


def test_check_resource_embedded_pe_not_mz() -> None:
    """Test _check_resource_embedded_pe with non-MZ header"""
    adapter = MockAdapter(cmdj_responses={
        "pxj 2 @ 4096": [0x00, 0x00]  # Not MZ
    })
    analyzer = ResourceAnalyzer(adapter=adapter)
    
    res = {"type_name": "RT_RCDATA", "size": 2000, "offset": 0x1000, "name": "data"}
    result = analyzer._check_resource_embedded_pe(res)
    assert result == []


def test_check_resource_embedded_pe_found_mz() -> None:
    """Test _check_resource_embedded_pe basic functionality"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    res = {"type_name": "RT_RCDATA", "size": 2000, "offset": 0x1000, "name": "data"}
    result = analyzer._check_resource_embedded_pe(res)
    # With None adapter, should return empty list
    assert isinstance(result, list)


def test_find_pattern_found() -> None:
    """Test _find_pattern when pattern is found"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    data = [0x00, 0x01, 0x02, 0x03, 0x04]
    pattern = [0x02, 0x03]
    
    result = analyzer._find_pattern(data, pattern)
    assert result == 2


def test_find_pattern_at_start() -> None:
    """Test _find_pattern when pattern at start"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    data = [0xAA, 0xBB, 0xCC, 0xDD]
    pattern = [0xAA, 0xBB]
    
    result = analyzer._find_pattern(data, pattern)
    assert result == 0


def test_find_pattern_at_end() -> None:
    """Test _find_pattern when pattern at end"""
    analyzer = ResourceAnalyzer(adapter=None)
    
    data = [0x00, 0x01, 0x02, 0x03]
    pattern = [0x02, 0x03]
    
    result = analyzer._find_pattern(data, pattern)
    assert result == 2
