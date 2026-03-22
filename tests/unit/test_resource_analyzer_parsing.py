"""Comprehensive tests for resource_analyzer.py parsing edge cases.

All tests use FakeR2 + R2PipeAdapter -> real ResourceAnalyzer. No mocks,
no monkeypatch, no @patch.
"""

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.resource_analyzer import ResourceAnalyzer
from r2inspect.testing.fake_r2 import FakeR2


# ---------------------------------------------------------------------------
# FakeR2 helper
# ---------------------------------------------------------------------------


def _hex_for(byte_list):
    """Convert a list of ints (0-255) to a hex string for p8 output."""
    return "".join(f"{b:02x}" for b in byte_list)


def _make_analyzer(cmdj_map=None, cmd_map=None):
    """Build a ResourceAnalyzer backed by FakeR2 + R2PipeAdapter."""
    r2 = FakeR2(cmdj_map=cmdj_map, cmd_map=cmd_map)
    adapter = R2PipeAdapter(r2)
    return ResourceAnalyzer(adapter)


# ====================================================================
# TestResourceParsingEdgeCases
# ====================================================================


class TestResourceParsingEdgeCases:
    """Test PE resource parsing edge cases and error paths."""

    def test_parse_resources_manual_fallback(self):
        """When .rsrc section exists with valid directory header,
        _parse_resources_manual should produce entries."""
        # 16-byte valid directory header: 12 zero bytes, then 1 named + 0 id
        header_bytes = [0] * 12 + [1, 0, 0, 0]
        # One 8-byte entry: type_id=3, offset=0x100 (no directory flag)
        entry_bytes = [3, 0, 0, 0, 0, 1, 0, 0]

        cmdj_map = {
            # iSj returns sections (for _get_rsrc_section)
            "iSj": [
                {"name": ".text", "paddr": 100},
                {"name": ".rsrc", "paddr": 1000, "size": 500},
            ],
        }
        cmd_map = {
            # p8 commands for manual parsing: header + entry
            "p8 16 @ 1000": _hex_for(header_bytes),
            "p8 8 @ 1016": _hex_for(entry_bytes),
        }
        analyzer = _make_analyzer(cmdj_map=cmdj_map, cmd_map=cmd_map)
        result = analyzer._parse_resources_manual()

        assert len(result) == 1
        assert result[0]["type_id"] == 3

    def test_parse_resources_manual_no_rsrc_section(self):
        """Manual parsing without .rsrc section returns empty list."""
        cmdj_map = {
            "iRj": None,
            "iSj": [
                {"name": ".text", "paddr": 100},
                {"name": ".data", "paddr": 200},
            ],
        }
        analyzer = _make_analyzer(cmdj_map=cmdj_map)
        result = analyzer._parse_resources_manual()
        assert result == []

    def test_parse_resources_manual_zero_offset(self):
        """Manual parsing with zero rsrc offset returns empty list."""
        cmdj_map = {
            "iSj": [{"name": ".rsrc", "paddr": 0}],
        }
        analyzer = _make_analyzer(cmdj_map=cmdj_map)
        result = analyzer._parse_resources_manual()
        assert result == []

    def test_parse_resources_manual_invalid_header(self):
        """Manual parsing with invalid (too short) directory header."""
        short_data = [1, 2, 3]
        cmdj_map = {
            "iSj": [{"name": ".rsrc", "paddr": 1000}],
        }
        cmd_map = {
            "p8 16 @ 1000": _hex_for(short_data),
        }
        analyzer = _make_analyzer(cmdj_map=cmdj_map, cmd_map=cmd_map)
        result = analyzer._parse_resources_manual()
        assert result == []

    def test_parse_resources_manual_valid_entries(self):
        """Manual parsing with valid directory entries."""
        # Header: 12 zero bytes, 1 named entry, 2 id entries = 3 total
        header_bytes = [0] * 12 + [1, 0, 2, 0]
        # Entry 1: name_or_id has high bit (named), offset with dir flag
        entry1 = [1, 0, 0, 0x80, 0, 0, 0, 0x80]
        # Entry 2: type_id=2, plain offset
        entry2 = [2, 0, 0, 0, 0, 0, 0, 0]
        # Entry 3: type_id=3, plain offset
        entry3 = [3, 0, 0, 0, 0, 0, 0, 0]

        cmdj_map = {
            "iSj": [{"name": ".rsrc", "paddr": 2000}],
        }
        cmd_map = {
            "p8 16 @ 2000": _hex_for(header_bytes),
            "p8 8 @ 2016": _hex_for(entry1),
            "p8 8 @ 2024": _hex_for(entry2),
            "p8 8 @ 2032": _hex_for(entry3),
        }
        analyzer = _make_analyzer(cmdj_map=cmdj_map, cmd_map=cmd_map)
        result = analyzer._parse_resources_manual()
        assert len(result) == 3

    def test_get_rsrc_section_found(self):
        """Finding .rsrc section returns the section dict."""
        cmdj_map = {
            "iSj": [
                {"name": ".text", "paddr": 100},
                {"name": ".rsrc", "paddr": 200, "size": 500},
            ],
        }
        analyzer = _make_analyzer(cmdj_map=cmdj_map)
        result = analyzer._get_rsrc_section()
        assert result is not None
        assert result["paddr"] == 200

    def test_get_rsrc_section_not_found(self):
        """When .rsrc section is missing, return None."""
        cmdj_map = {
            "iSj": [
                {"name": ".text", "paddr": 100},
                {"name": ".data", "paddr": 200},
            ],
        }
        analyzer = _make_analyzer(cmdj_map=cmdj_map)
        result = analyzer._get_rsrc_section()
        assert result is None

    def test_get_rsrc_section_no_data(self):
        """When section data is unavailable, return None."""
        cmdj_map = {"iSj": None}
        analyzer = _make_analyzer(cmdj_map=cmdj_map)
        result = analyzer._get_rsrc_section()
        assert result is None

    def test_parse_dir_entry_valid(self):
        """Parsing a valid directory entry for RT_ICON (type 3)."""
        analyzer = _make_analyzer()
        entry_data = [3, 0, 0, 0, 0, 0x10, 0, 0]
        result = analyzer._parse_dir_entry(2000, entry_data, 0)
        assert result is not None
        assert result["type_id"] == 3
        assert result["type_name"] == "RT_ICON"

    def test_parse_dir_entry_named_resource(self):
        """Parsing a named resource entry (high bit set in name_or_id)."""
        analyzer = _make_analyzer()
        entry_data = [0, 0, 0, 0x80, 0, 0x10, 0, 0]
        result = analyzer._parse_dir_entry(2000, entry_data, 5)
        assert result is not None
        assert "Named_5" in result["name"]

    def test_parse_dir_entry_directory_flag(self):
        """Parsing an entry with the directory flag set."""
        analyzer = _make_analyzer()
        entry_data = [3, 0, 0, 0, 0, 0x10, 0, 0x80]
        result = analyzer._parse_dir_entry(2000, entry_data, 0)
        assert result is not None
        assert result["is_directory"] is True

    def test_parse_dir_entry_insufficient_data(self):
        """Parsing with insufficient data returns None."""
        analyzer = _make_analyzer()
        result = analyzer._parse_dir_entry(2000, [1, 2, 3], 0)
        assert result is None

    def test_analyze_resource_data_zero_offset(self):
        """Analyzing resource with zero offset skips without crash."""
        analyzer = _make_analyzer()
        resource = {"offset": 0, "size": 100}
        analyzer._analyze_resource_data(resource)
        assert resource["offset"] == 0

    def test_analyze_resource_data_zero_size(self):
        """Analyzing resource with zero size skips without crash."""
        analyzer = _make_analyzer()
        resource = {"offset": 1000, "size": 0}
        analyzer._analyze_resource_data(resource)
        assert resource["size"] == 0

    def test_analyze_resource_data_large_resource_limited(self):
        """Large resources are capped at 64KB for analysis."""
        # 65536 bytes of 0x41
        data_bytes = [0x41] * 65536
        cmd_map = {
            "p8 65536 @ 1000": _hex_for(data_bytes),
        }
        analyzer = _make_analyzer(cmd_map=cmd_map)
        resource = {"offset": 1000, "size": 100000}
        analyzer._analyze_resource_data(resource)

        # Entropy should be computed (all same byte -> ~0.0 entropy)
        assert "entropy" in resource
        assert resource["entropy"] == 0.0
        # Hashes should be present
        assert isinstance(resource.get("hashes"), dict)

    def test_analyze_resource_data_with_varied_bytes(self):
        """Analyzing resource with varied bytes produces non-zero entropy."""
        data_bytes = list(range(256)) * 4  # 1024 varied bytes
        cmd_map = {
            "p8 1024 @ 500": _hex_for(data_bytes),
        }
        analyzer = _make_analyzer(cmd_map=cmd_map)
        resource = {"offset": 500, "size": 1024}
        analyzer._analyze_resource_data(resource)
        assert resource["entropy"] > 0
        assert "sha256" in resource.get("hashes", {})

    def test_analyze_resource_data_read_failure(self):
        """Resource data analysis survives when p8 read returns nothing."""
        # No cmd_map entry means read_bytes returns empty -> no crash
        analyzer = _make_analyzer()
        resource = {"offset": 1000, "size": 100}
        analyzer._analyze_resource_data(resource)
        assert "offset" in resource


# ====================================================================
# TestResourceVersionInfo
# ====================================================================


class TestResourceVersionInfo:
    """Test VERSION_INFO resource parsing."""

    def test_parse_version_info_zero_offset(self):
        """Version parsing with zero offset returns None."""
        analyzer = _make_analyzer()
        result = analyzer._parse_version_info(0, 100)
        assert result is None

    def test_parse_version_info_too_small(self):
        """Version parsing with size < 64 returns None."""
        analyzer = _make_analyzer()
        result = analyzer._parse_version_info(1000, 32)
        assert result is None

    def test_parse_version_info_no_data(self):
        """Version parsing when read returns empty data."""
        # p8 returns empty -> _read_version_info_data returns None
        analyzer = _make_analyzer()
        result = analyzer._parse_version_info(1000, 100)
        assert result is None

    def test_parse_version_info_no_signature(self):
        """Version parsing without VS_FIXEDFILEINFO signature."""
        data = [0] * 100
        cmd_map = {
            "p8 100 @ 1000": _hex_for(data),
        }
        analyzer = _make_analyzer(cmd_map=cmd_map)
        result = analyzer._parse_version_info(1000, 100)
        # No signature and no version strings -> None
        assert result is None

    def test_parse_version_info_with_signature_and_strings(self):
        """Version parsing with valid VS_FIXEDFILEINFO signature and version strings."""
        # Build data with signature at offset 10 and CompanyName string
        data = [0] * 200
        # Place VS_FIXEDFILEINFO signature (0xFEEF04BD) at offset 10
        data[10] = 0xBD
        data[11] = 0x04
        data[12] = 0xEF
        data[13] = 0xFE
        # Version numbers at sig_pos+8..+15
        data[18] = 1  # file_version_ms low
        data[19] = 0
        data[20] = 2  # file_version_ms high
        data[21] = 0
        data[22] = 3  # file_version_ls low
        data[23] = 0
        data[24] = 4  # file_version_ls high
        data[25] = 0
        # Add "CompanyName" in UTF-16LE followed by value "Acme"
        key_bytes = list("CompanyName".encode("utf-16le"))
        value_bytes = list("Acme".encode("utf-16le"))
        start = 80
        for i, b in enumerate(key_bytes):
            data[start + i] = b
        pad = start + len(key_bytes)
        # 4 bytes padding between key and value
        data[pad] = 0
        data[pad + 1] = 0
        data[pad + 2] = 0
        data[pad + 3] = 0
        val_start = pad + 4
        for i, b in enumerate(value_bytes):
            data[val_start + i] = b
        # Null terminator for value
        data[val_start + len(value_bytes)] = 0
        data[val_start + len(value_bytes) + 1] = 0

        cmd_map = {
            "p8 200 @ 1000": _hex_for(data),
        }
        analyzer = _make_analyzer(cmd_map=cmd_map)
        result = analyzer._parse_version_info(1000, 200)
        assert result is not None
        assert isinstance(result, dict)
        assert result["strings"]["CompanyName"] == "Acme"
        assert result["file_version"] != ""

    def test_parse_fixed_file_info_insufficient_data(self):
        """Parsing fixed file info with insufficient data returns empty string."""
        analyzer = _make_analyzer()
        data = [0] * 20
        result = analyzer._parse_fixed_file_info(data, 10)
        assert result == ""

    def test_read_version_string_value_not_found(self):
        """Reading version string when key not found returns empty."""
        analyzer = _make_analyzer()
        data = [0] * 100
        result = analyzer._read_version_string_value(data, "CompanyName")
        assert result == ""

    def test_read_version_string_value_found(self):
        """Reading version string when key is present."""
        analyzer = _make_analyzer()
        key_bytes = list("CompanyName".encode("utf-16le"))
        value_bytes = list("Test Corp".encode("utf-16le"))
        data = [0] * 10 + key_bytes + [0, 0, 0, 0] + value_bytes + [0, 0] + [0] * 10
        result = analyzer._read_version_string_value(data, "CompanyName")
        assert result == "Test Corp"

    def test_read_version_string_value_at_end(self):
        """Reading version string at end of data returns empty."""
        analyzer = _make_analyzer()
        key_bytes = list("FileVersion".encode("utf-16le"))
        data = [0] * 10 + key_bytes
        result = analyzer._read_version_string_value(data, "FileVersion")
        assert result == ""

    def test_extract_version_strings_multiple_keys(self):
        """Extracting multiple version strings from data."""
        analyzer = _make_analyzer()
        # Build data with CompanyName and ProductName
        data = [0] * 10
        for key, value in [("CompanyName", "Test Company"), ("ProductName", "Test Product")]:
            key_bytes = list(key.encode("utf-16le"))
            value_bytes = list(value.encode("utf-16le"))
            data.extend(key_bytes + [0, 0, 0, 0] + value_bytes + [0, 0] + [0] * 10)

        result = analyzer._extract_version_strings(data)
        assert "CompanyName" in result
        assert result["CompanyName"] == "Test Company"
        assert "ProductName" in result


# ====================================================================
# TestResourceExtraction
# ====================================================================


class TestResourceExtraction:
    """Test resource content extraction methods."""

    def test_read_resource_as_string_zero_offset(self):
        """Reading resource string with zero offset returns None."""
        analyzer = _make_analyzer()
        result = analyzer._read_resource_as_string(0, 100)
        assert result is None

    def test_read_resource_as_string_zero_size(self):
        """Reading resource string with zero size returns None."""
        analyzer = _make_analyzer()
        result = analyzer._read_resource_as_string(1000, 0)
        assert result is None

    def test_read_resource_as_string_utf16le(self):
        """Reading UTF-16LE resource string."""
        text = "Hello World"
        data = list(text.encode("utf-16le"))
        cmd_map = {
            f"p8 {len(data)} @ 1000": _hex_for(data),
        }
        analyzer = _make_analyzer(cmd_map=cmd_map)
        result = analyzer._read_resource_as_string(1000, len(data))
        assert result is not None
        assert "Hello World" in result

    def test_read_resource_as_string_utf8(self):
        """Reading plain ASCII resource string."""
        text = b"Plain ASCII text"
        cmd_map = {
            f"p8 {len(text)} @ 1000": _hex_for(list(text)),
        }
        analyzer = _make_analyzer(cmd_map=cmd_map)
        result = analyzer._read_resource_as_string(1000, len(text))
        assert result is not None and len(result) > 0

    def test_read_resource_as_string_binary_data(self):
        """Reading binary (non-text) resource returns None."""
        data = [0x00, 0x00, 0x00, 0x00, 0x00]
        cmd_map = {
            "p8 5 @ 1000": _hex_for(data),
        }
        analyzer = _make_analyzer(cmd_map=cmd_map)
        result = analyzer._read_resource_as_string(1000, 5)
        assert result is None

    def test_read_resource_as_string_size_limited(self):
        """Resource reading is limited to 8KB."""
        # Provide exactly 8192 bytes of 'A' (0x41)
        data = [0x41] * 8192
        cmd_map = {
            "p8 8192 @ 1000": _hex_for(data),
        }
        analyzer = _make_analyzer(cmd_map=cmd_map)
        result = analyzer._read_resource_as_string(1000, 100000)
        # Should have read and decoded the 8192 bytes
        assert result is not None

    def test_read_resource_as_string_read_failure(self):
        """Resource reading with no matching p8 entry returns None."""
        # No cmd_map entry -> read_bytes returns empty -> None
        analyzer = _make_analyzer()
        result = analyzer._read_resource_as_string(1000, 100)
        assert result is None


# ====================================================================
# TestSuspiciousResourceChecks
# ====================================================================


class TestSuspiciousResourceChecks:
    """Test suspicious resource detection."""

    def test_check_resource_entropy_high_non_icon(self):
        """Flagging high entropy non-icon resource."""
        analyzer = _make_analyzer()
        res = {
            "name": "data_blob",
            "type_name": "RT_RCDATA",
            "entropy": 7.8,
            "size": 5000,
        }
        result = analyzer._check_resource_entropy(res)
        assert len(result) == 1
        assert "encrypted" in result[0]["reason"].lower()

    def test_check_resource_entropy_high_icon_allowed(self):
        """High entropy icons are not flagged."""
        analyzer = _make_analyzer()
        res = {
            "name": "icon",
            "type_name": "RT_ICON",
            "entropy": 7.9,
            "size": 1000,
        }
        result = analyzer._check_resource_entropy(res)
        assert len(result) == 0

    def test_check_resource_size_large(self):
        """Flagging unusually large resource."""
        analyzer = _make_analyzer()
        res = {
            "name": "huge_resource",
            "type_name": "RT_RCDATA",
            "size": 2 * 1024 * 1024,
        }
        result = analyzer._check_resource_size(res)
        assert len(result) == 1
        assert "large" in result[0]["reason"].lower()

    def test_check_resource_rcdata_large(self):
        """Flagging large RCDATA resource."""
        analyzer = _make_analyzer()
        res = {
            "name": "data",
            "type_name": "RT_RCDATA",
            "size": 50000,
            "entropy": 6.5,
        }
        result = analyzer._check_resource_rcdata(res)
        assert len(result) == 1

    def test_check_resource_rcdata_small_not_flagged(self):
        """Small RCDATA is not flagged."""
        analyzer = _make_analyzer()
        res = {
            "name": "data",
            "type_name": "RT_RCDATA",
            "size": 5000,
            "entropy": 6.5,
        }
        result = analyzer._check_resource_rcdata(res)
        assert len(result) == 0

    def test_check_resource_embedded_pe_detected(self):
        """Detecting embedded PE file via MZ header."""
        mz_bytes = [0x4D, 0x5A]
        cmd_map = {
            "p8 2 @ 2000": _hex_for(mz_bytes),
        }
        analyzer = _make_analyzer(cmd_map=cmd_map)
        res = {
            "name": "payload",
            "type_name": "RT_RCDATA",
            "offset": 2000,
            "size": 50000,
        }
        result = analyzer._check_resource_embedded_pe(res)
        assert len(result) == 1
        assert "embedded PE" in result[0]["reason"]

    def test_check_resource_embedded_pe_not_rcdata(self):
        """Non-RCDATA resources are not checked for embedded PE."""
        analyzer = _make_analyzer()
        res = {
            "name": "icon",
            "type_name": "RT_ICON",
            "offset": 2000,
            "size": 50000,
        }
        result = analyzer._check_resource_embedded_pe(res)
        assert len(result) == 0

    def test_check_resource_embedded_pe_too_small(self):
        """Small resources are not checked for embedded PE."""
        analyzer = _make_analyzer()
        res = {
            "name": "data",
            "type_name": "RT_RCDATA",
            "offset": 2000,
            "size": 500,
        }
        result = analyzer._check_resource_embedded_pe(res)
        assert len(result) == 0

    def test_find_pattern_found(self):
        """Finding pattern in data."""
        analyzer = _make_analyzer()
        data = [0, 1, 2, 3, 4, 5, 6]
        pattern = [3, 4, 5]
        result = analyzer._find_pattern(data, pattern)
        assert result == 3

    def test_find_pattern_not_found(self):
        """Pattern not found in data."""
        analyzer = _make_analyzer()
        data = [0, 1, 2, 3, 4, 5, 6]
        pattern = [7, 8, 9]
        result = analyzer._find_pattern(data, pattern)
        assert result == -1

    def test_find_pattern_at_start(self):
        """Finding pattern at start of data."""
        analyzer = _make_analyzer()
        data = [1, 2, 3, 4, 5]
        pattern = [1, 2, 3]
        result = analyzer._find_pattern(data, pattern)
        assert result == 0

    def test_find_pattern_at_end(self):
        """Finding pattern at end of data."""
        analyzer = _make_analyzer()
        data = [1, 2, 3, 4, 5]
        pattern = [3, 4, 5]
        result = analyzer._find_pattern(data, pattern)
        assert result == 2
