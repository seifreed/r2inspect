"""Comprehensive tests for resource_analyzer.py - 100% coverage target.

Uses FakeR2 + R2PipeAdapter exclusively. NO mocks, NO monkeypatch, NO @patch.
"""

from __future__ import annotations

from typing import Any

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.resource_analyzer import ResourceAnalyzer, run_resource_analysis


class FakeR2:
    """Fake r2pipe instance returning predetermined responses by command.

    - cmdj_map: responses for FakeR2.cmdj(command) -- JSON commands like iDj, iRj, iSj
    - cmd_map: responses for FakeR2.cmd(command) -- text commands like p8
    """

    def __init__(
        self,
        cmdj_map: dict[str, Any] | None = None,
        cmd_map: dict[str, str] | None = None,
    ):
        self.cmdj_map: dict[str, Any] = cmdj_map or {}
        self.cmd_map: dict[str, str] = cmd_map or {}

    def cmdj(self, command: str) -> Any:
        if command in self.cmdj_map:
            value = self.cmdj_map[command]
            if isinstance(value, Exception):
                raise value
            return value
        return None

    def cmd(self, command: str) -> str:
        if command in self.cmd_map:
            value = self.cmd_map[command]
            if isinstance(value, Exception):
                raise value
            return value
        # Prefix matching for p8 commands with addresses
        for key, value in self.cmd_map.items():
            if key in command:
                if isinstance(value, Exception):
                    raise value
                return value
        return ""


def _bytes_to_hex(data: list[int]) -> str:
    """Convert a list of ints to a hex string (p8 output format)."""
    return "".join(f"{b:02x}" for b in data)


def _make_analyzer(
    cmdj_map: dict[str, Any] | None = None,
    cmd_map: dict[str, str] | None = None,
) -> ResourceAnalyzer:
    """Create a ResourceAnalyzer backed by FakeR2 + R2PipeAdapter."""
    fake_r2 = FakeR2(cmdj_map=cmdj_map, cmd_map=cmd_map)
    adapter = R2PipeAdapter(fake_r2)
    return ResourceAnalyzer(adapter=adapter)


# ---------------------------------------------------------------------------
# Init
# ---------------------------------------------------------------------------


def test_resource_analyzer_init():
    """Test ResourceAnalyzer initialization."""
    analyzer = _make_analyzer()
    assert analyzer.adapter is not None


# ---------------------------------------------------------------------------
# analyze() -> run_resource_analysis
# ---------------------------------------------------------------------------


def test_analyze_basic():
    """Test basic analyze returns result dict when no resource dir."""
    analyzer = _make_analyzer(cmdj_map={"iDj": []})
    result = analyzer.analyze()

    assert isinstance(result, dict)
    assert result["available"] is True
    assert result["has_resources"] is False


def test_analyze_with_resources():
    """Full analyze with resource directory and one resource entry."""
    resource_bytes = list(range(256))
    cmdj_map: dict[str, Any] = {
        "iDj": [{"name": "RESOURCE", "vaddr": 0x1000, "paddr": 0x800, "size": 500}],
        "iRj": [
            {
                "name": "RT_ICON",
                "type": "ICON",
                "type_id": 3,
                "lang": "en-US",
                "paddr": 1000,
                "size": 256,
                "vaddr": 2000,
            }
        ],
    }
    # read_bytes uses p8 text command
    cmd_map = {
        "p8 256 @ 1000": _bytes_to_hex(resource_bytes),
    }

    analyzer = _make_analyzer(cmdj_map=cmdj_map, cmd_map=cmd_map)
    result = analyzer.analyze()

    assert result["available"] is True
    assert result["has_resources"] is True
    assert result["total_resources"] == 1
    assert len(result["resources"]) == 1


# ---------------------------------------------------------------------------
# _get_resource_directory
# ---------------------------------------------------------------------------


def test_get_resource_directory_success():
    """Test _get_resource_directory with valid data."""
    analyzer = _make_analyzer(
        cmdj_map={
            "iDj": [
                {"name": "EXPORT", "vaddr": 100, "paddr": 50, "size": 100},
                {"name": "RESOURCE", "vaddr": 200, "paddr": 150, "size": 500},
            ]
        }
    )

    result = analyzer._get_resource_directory()

    assert result is not None
    assert result["offset"] == 150
    assert result["size"] == 500
    assert result["virtual_address"] == 200


def test_get_resource_directory_no_data():
    """Test _get_resource_directory with no data."""
    analyzer = _make_analyzer(cmdj_map={"iDj": []})

    result = analyzer._get_resource_directory()

    assert result is None


def test_get_resource_directory_exception():
    """Test _get_resource_directory with exception."""
    analyzer = _make_analyzer(cmdj_map={"iDj": Exception("Test error")})

    result = analyzer._get_resource_directory()

    assert result is None


# ---------------------------------------------------------------------------
# _parse_resources
# ---------------------------------------------------------------------------


def test_parse_resources_success():
    """Test _parse_resources with valid resources."""
    resource_bytes = list(range(256))
    cmdj_map: dict[str, Any] = {
        "iRj": [
            {
                "name": "RT_ICON",
                "type": "ICON",
                "type_id": 3,
                "lang": "en-US",
                "paddr": 1000,
                "size": 256,
                "vaddr": 2000,
            }
        ],
    }
    cmd_map = {"p8 256 @ 1000": _bytes_to_hex(resource_bytes)}

    analyzer = _make_analyzer(cmdj_map=cmdj_map, cmd_map=cmd_map)
    result = analyzer._parse_resources()

    assert len(result) == 1
    assert result[0]["name"] == "RT_ICON"
    assert result[0]["size"] == 256


def test_parse_resources_no_data():
    """Test _parse_resources with no resources falls back to manual."""
    cmdj_map: dict[str, Any] = {
        "iRj": None,
        "iSj": [],  # no .rsrc section for manual parse
    }
    analyzer = _make_analyzer(cmdj_map=cmdj_map)

    result = analyzer._parse_resources()

    assert result == []


def test_parse_resources_exception():
    """Test _parse_resources with exception falls back to manual."""
    cmdj_map: dict[str, Any] = {
        "iRj": Exception("Parse error"),
        "iSj": [],  # no .rsrc section for manual fallback
    }
    analyzer = _make_analyzer(cmdj_map=cmdj_map)

    result = analyzer._parse_resources()

    assert result == []


# ---------------------------------------------------------------------------
# _get_rsrc_section
# ---------------------------------------------------------------------------


def test_get_rsrc_section_found():
    """Test _get_rsrc_section when section exists."""
    analyzer = _make_analyzer(
        cmdj_map={
            "iSj": [
                {"name": ".text", "paddr": 100},
                {"name": ".rsrc", "paddr": 2000, "size": 5000},
            ]
        }
    )

    result = analyzer._get_rsrc_section()

    assert result is not None
    assert result["name"] == ".rsrc"
    assert result["paddr"] == 2000


def test_get_rsrc_section_not_found():
    """Test _get_rsrc_section when section not found."""
    analyzer = _make_analyzer(cmdj_map={"iSj": [{"name": ".text", "paddr": 100}]})

    result = analyzer._get_rsrc_section()

    assert result is None


# ---------------------------------------------------------------------------
# _is_valid_dir_header / _get_dir_total_entries
# ---------------------------------------------------------------------------


def test_is_valid_dir_header_valid():
    """Test _is_valid_dir_header with valid data."""
    analyzer = _make_analyzer()
    data = [0] * 16

    assert analyzer._is_valid_dir_header(data) is True


def test_is_valid_dir_header_invalid():
    """Test _is_valid_dir_header with invalid data."""
    analyzer = _make_analyzer()

    assert analyzer._is_valid_dir_header(None) is False
    assert analyzer._is_valid_dir_header([0] * 10) is False


def test_get_dir_total_entries():
    """Test _get_dir_total_entries calculation."""
    analyzer = _make_analyzer()
    data = [0] * 16
    data[12] = 2  # named entries
    data[13] = 0
    data[14] = 3  # id entries
    data[15] = 0

    result = analyzer._get_dir_total_entries(data)

    assert result == 5


# ---------------------------------------------------------------------------
# _analyze_resource_types
# ---------------------------------------------------------------------------


def test_analyze_resource_types():
    """Test _analyze_resource_types."""
    analyzer = _make_analyzer()
    result: dict[str, Any] = {}
    resources = [
        {"type_name": "RT_ICON", "size": 100},
        {"type_name": "RT_ICON", "size": 200},
        {"type_name": "RT_VERSION", "size": 300},
    ]

    analyzer._analyze_resource_types(result, resources)

    assert "resource_types" in result
    assert len(result["resource_types"]) == 2
    assert result["total_size"] == 600


# ---------------------------------------------------------------------------
# _calculate_entropy
# ---------------------------------------------------------------------------


def test_calculate_entropy():
    """Test _calculate_entropy method."""
    analyzer = _make_analyzer()
    data = [0, 1, 2, 3, 4, 5, 6, 7] * 10

    result = analyzer._calculate_entropy(data)

    assert isinstance(result, float)
    assert 0 <= result <= 8


# ---------------------------------------------------------------------------
# _extract_version_info
# ---------------------------------------------------------------------------


def test_extract_version_info():
    """Test _extract_version_info with a version resource."""
    # Build version data with VS_FIXEDFILEINFO signature and version strings
    vs_sig = [0xBD, 0x04, 0xEF, 0xFE]
    data = [0] * 300
    sig_pos = 40
    data[sig_pos : sig_pos + 4] = vs_sig
    # file_version_ms = 1.2
    data[sig_pos + 8] = 0x02
    data[sig_pos + 9] = 0x00
    data[sig_pos + 10] = 0x01
    data[sig_pos + 11] = 0x00
    # file_version_ls = 3.4
    data[sig_pos + 12] = 0x04
    data[sig_pos + 13] = 0x00
    data[sig_pos + 14] = 0x03
    data[sig_pos + 15] = 0x00

    # Embed CompanyName key + value in UTF-16LE
    company_key = list("CompanyName".encode("utf-16le"))
    company_val = list("TestCo".encode("utf-16le"))
    key_pos = 100
    data[key_pos : key_pos + len(company_key)] = company_key
    val_pos = key_pos + len(company_key) + 4
    data[val_pos : val_pos + len(company_val)] = company_val
    data[val_pos + len(company_val)] = 0
    data[val_pos + len(company_val) + 1] = 0

    # _read_version_info_data reads via p8 (min(size,1024) bytes)
    cmd_map = {
        "p8 512 @ 1000": _bytes_to_hex(data[:512]),
    }

    analyzer = _make_analyzer(cmd_map=cmd_map)
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_VERSION", "offset": 1000, "size": 512}]

    analyzer._extract_version_info(result, resources)

    assert "version_info" in result
    assert result["version_info"]["file_version"] == "1.2.3.4"
    assert "CompanyName" in result["version_info"]["strings"]


def test_extract_version_info_no_version_resource():
    """Test _extract_version_info with no RT_VERSION resource."""
    analyzer = _make_analyzer()
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_ICON", "offset": 1000, "size": 256}]

    analyzer._extract_version_info(result, resources)

    assert "version_info" not in result


def test_extract_version_info_exception():
    """Test _extract_version_info when reading data fails."""
    cmd_map = {
        "p8 512 @ 1000": Exception("Parse error"),
    }
    analyzer = _make_analyzer(cmd_map=cmd_map)
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_VERSION", "offset": 1000, "size": 512}]

    analyzer._extract_version_info(result, resources)

    assert "version_info" not in result


# ---------------------------------------------------------------------------
# _find_vs_signature
# ---------------------------------------------------------------------------


def test_find_vs_signature():
    """Test _find_vs_signature method."""
    analyzer = _make_analyzer()
    data = [0] * 100
    data[50:54] = [0xBD, 0x04, 0xEF, 0xFE]

    result = analyzer._find_vs_signature(data)

    assert result == 50


def test_find_vs_signature_not_found():
    """Test _find_vs_signature when not found."""
    analyzer = _make_analyzer()
    data = [0] * 100

    result = analyzer._find_vs_signature(data)

    assert result == -1


# ---------------------------------------------------------------------------
# _extract_manifest
# ---------------------------------------------------------------------------


def test_extract_manifest():
    """Test _extract_manifest method."""
    manifest_content = '<?xml version="1.0"?><assembly><requestedExecutionLevel level="requireAdministrator"/></assembly>'
    manifest_bytes = list(manifest_content.encode("utf-8"))

    # _read_resource_as_string reads via p8 (min(size,8192) bytes)
    read_size = min(512, 8192)
    cmd_map = {
        f"p8 {read_size} @ 1000": _bytes_to_hex(manifest_bytes),
    }
    analyzer = _make_analyzer(cmd_map=cmd_map)
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_MANIFEST", "offset": 1000, "size": 512}]

    analyzer._extract_manifest(result, resources)

    assert "manifest" in result
    assert result["manifest"]["requires_admin"] is True


def test_extract_manifest_no_manifest_resource():
    """Test _extract_manifest when no RT_MANIFEST resource."""
    analyzer = _make_analyzer()
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_ICON", "offset": 1000, "size": 256}]

    analyzer._extract_manifest(result, resources)

    assert result.get("manifest") is None


# ---------------------------------------------------------------------------
# _extract_icons
# ---------------------------------------------------------------------------


def test_extract_icons():
    """Test _extract_icons method."""
    analyzer = _make_analyzer()
    result: dict[str, Any] = {}
    resources = [
        {"type_name": "RT_ICON", "name": "icon1", "size": 256, "offset": 1000, "entropy": 5.5},
        {"type_name": "RT_GROUP_ICON", "name": "grp1", "size": 128, "offset": 2000, "entropy": 7.8},
    ]

    analyzer._extract_icons(result, resources)

    assert "icons" in result
    assert len(result["icons"]) == 2
    assert result["icons"][1]["suspicious"] == "High entropy (possibly encrypted)"


# ---------------------------------------------------------------------------
# _extract_strings
# ---------------------------------------------------------------------------


def test_extract_strings():
    """Test _extract_strings method."""
    # Use UTF-16LE encoding since decode_resource_text prefers it when nulls present
    string_data = "string_one\0string_two\0ab\0"
    string_bytes_utf16 = list(string_data.encode("utf-16le"))

    read_size = min(256, 8192)
    cmd_map = {
        f"p8 {read_size} @ 1000": _bytes_to_hex(string_bytes_utf16),
    }
    analyzer = _make_analyzer(cmd_map=cmd_map)
    result: dict[str, Any] = {}
    resources = [{"type_name": "RT_STRING", "offset": 1000, "size": 256}]

    analyzer._extract_strings(result, resources)

    assert "strings" in result
    # The decoded text should contain these strings after null-split
    found = result["strings"]
    assert len(found) >= 1


# ---------------------------------------------------------------------------
# _calculate_statistics
# ---------------------------------------------------------------------------


def test_calculate_statistics():
    """Test _calculate_statistics method."""
    analyzer = _make_analyzer()
    result: dict[str, Any] = {}
    resources = [
        {"size": 100, "entropy": 5.5, "type_name": "RT_ICON"},
        {"size": 200, "entropy": 6.0, "type_name": "RT_VERSION"},
        {"size": 0, "entropy": 0, "type_name": "RT_MANIFEST"},
    ]

    analyzer._calculate_statistics(result, resources)

    assert "statistics" in result
    stats = result["statistics"]
    assert stats["total_resources"] == 3
    assert stats["total_size"] == 300
    assert stats["unique_types"] == 3


# ---------------------------------------------------------------------------
# _check_suspicious_resources
# ---------------------------------------------------------------------------


def test_check_suspicious_resources():
    """Test _check_suspicious_resources method."""
    # Embedded PE detection reads 2 bytes via p8 at the resource offset
    cmd_map = {
        "p8 2 @ 1000": _bytes_to_hex([0x4D, 0x5A]),  # MZ header
    }
    analyzer = _make_analyzer(cmd_map=cmd_map)
    result: dict[str, Any] = {}
    resources = [
        {"name": "res1", "type_name": "RT_RCDATA", "size": 100000, "entropy": 7.8, "offset": 1000},
        {"name": "res2", "type_name": "RT_ICON", "size": 256, "entropy": 7.9, "offset": 2000},
    ]

    analyzer._check_suspicious_resources(result, resources)

    assert "suspicious_resources" in result
    assert len(result["suspicious_resources"]) > 0


# ---------------------------------------------------------------------------
# _check_resource_entropy
# ---------------------------------------------------------------------------


def test_check_resource_entropy():
    """Test _check_resource_entropy method."""
    analyzer = _make_analyzer()

    # High entropy non-icon resource
    res1 = {"name": "test", "type_name": "RT_RCDATA", "entropy": 7.8, "size": 1000}
    result1 = analyzer._check_resource_entropy(res1)
    assert len(result1) == 1

    # Icon with high entropy (ignored)
    res2 = {"name": "icon", "type_name": "RT_ICON", "entropy": 7.9, "size": 500}
    result2 = analyzer._check_resource_entropy(res2)
    assert len(result2) == 0


# ---------------------------------------------------------------------------
# _check_resource_size
# ---------------------------------------------------------------------------


def test_check_resource_size():
    """Test _check_resource_size method."""
    analyzer = _make_analyzer()

    # Large resource (> 1 MB)
    res1 = {"name": "test", "type_name": "RT_RCDATA", "size": 2 * 1024 * 1024}
    result1 = analyzer._check_resource_size(res1)
    assert len(result1) == 1

    # Small resource
    res2 = {"name": "test", "type_name": "RT_ICON", "size": 256}
    result2 = analyzer._check_resource_size(res2)
    assert len(result2) == 0


# ---------------------------------------------------------------------------
# _check_resource_rcdata
# ---------------------------------------------------------------------------


def test_check_resource_rcdata():
    """Test _check_resource_rcdata method."""
    analyzer = _make_analyzer()

    # Large RCDATA (> 10240)
    res1 = {"name": "test", "type_name": "RT_RCDATA", "size": 20000, "entropy": 6.5}
    result1 = analyzer._check_resource_rcdata(res1)
    assert len(result1) == 1

    # Small RCDATA
    res2 = {"name": "test", "type_name": "RT_RCDATA", "size": 100, "entropy": 5.0}
    result2 = analyzer._check_resource_rcdata(res2)
    assert len(result2) == 0


# ---------------------------------------------------------------------------
# _check_resource_embedded_pe
# ---------------------------------------------------------------------------


def test_check_resource_embedded_pe():
    """Test _check_resource_embedded_pe method."""
    cmd_map = {
        "p8 2 @ 1000": _bytes_to_hex([0x4D, 0x5A]),  # MZ header
    }
    analyzer = _make_analyzer(cmd_map=cmd_map)

    res = {"name": "test", "type_name": "RT_RCDATA", "size": 2000, "offset": 1000}
    result = analyzer._check_resource_embedded_pe(res)

    assert len(result) == 1
    assert "embedded PE" in result[0]["reason"]


def test_check_resource_embedded_pe_not_rcdata():
    """Test _check_resource_embedded_pe with non-RCDATA type."""
    analyzer = _make_analyzer()

    res = {"name": "icon", "type_name": "RT_ICON", "size": 2000, "offset": 1000}
    result = analyzer._check_resource_embedded_pe(res)

    assert result == []


def test_check_resource_embedded_pe_small_size():
    """Test _check_resource_embedded_pe with resource too small."""
    analyzer = _make_analyzer()

    res = {"name": "test", "type_name": "RT_RCDATA", "size": 100, "offset": 1000}
    result = analyzer._check_resource_embedded_pe(res)

    assert result == []


# ---------------------------------------------------------------------------
# _find_pattern
# ---------------------------------------------------------------------------


def test_find_pattern():
    """Test _find_pattern method."""
    analyzer = _make_analyzer()
    data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    pattern = [3, 4, 5]

    result = analyzer._find_pattern(data, pattern)

    assert result == 3


def test_find_pattern_not_found():
    """Test _find_pattern when pattern not found."""
    analyzer = _make_analyzer()
    data = [0, 1, 2, 3, 4, 5]
    pattern = [9, 10]

    result = analyzer._find_pattern(data, pattern)

    assert result == -1


# ---------------------------------------------------------------------------
# _read_resource_as_string
# ---------------------------------------------------------------------------


def test_read_resource_as_string_utf16():
    """Test _read_resource_as_string with UTF-16."""
    utf16_bytes = list("Test".encode("utf-16le"))
    cmd_map = {
        "p8 100 @ 1000": _bytes_to_hex(utf16_bytes),
    }
    analyzer = _make_analyzer(cmd_map=cmd_map)

    result = analyzer._read_resource_as_string(1000, 100)

    assert result is not None
    assert "Test" in result


def test_read_resource_as_string_utf8():
    """Test _read_resource_as_string with UTF-8."""
    utf8_bytes = list(b"Hello World Test")
    size = len(utf8_bytes)
    cmd_map = {
        f"p8 {size} @ 1000": _bytes_to_hex(utf8_bytes),
    }
    analyzer = _make_analyzer(cmd_map=cmd_map)

    result = analyzer._read_resource_as_string(1000, size)

    assert result is not None
    assert "Hello" in result


def test_read_resource_as_string_invalid():
    """Test _read_resource_as_string with invalid offset."""
    analyzer = _make_analyzer()

    result = analyzer._read_resource_as_string(0, 0)

    assert result is None


# ---------------------------------------------------------------------------
# _parse_version_info
# ---------------------------------------------------------------------------


def test_parse_version_info_no_data():
    """Test _parse_version_info with no data (size too small)."""
    analyzer = _make_analyzer()

    result = analyzer._parse_version_info(1000, 10)  # size < 64

    assert result is None


def test_parse_version_info_empty_read():
    """Test _parse_version_info when data read returns too little."""
    # 30 bytes of zeros -> hex string of 30 bytes
    small_data = [0] * 30
    cmd_map = {
        "p8 512 @ 1000": _bytes_to_hex(small_data),
    }
    analyzer = _make_analyzer(cmd_map=cmd_map)

    result = analyzer._parse_version_info(1000, 512)

    assert result is None


# ---------------------------------------------------------------------------
# _extract_version_strings
# ---------------------------------------------------------------------------


def test_extract_version_strings():
    """Test _extract_version_strings method with real data."""
    analyzer = _make_analyzer()

    # Build data containing CompanyName key in UTF-16LE followed by value
    data = [0] * 500
    company_key = list("CompanyName".encode("utf-16le"))
    company_val = list("ACME Corp".encode("utf-16le"))
    pos = 50
    data[pos : pos + len(company_key)] = company_key
    val_pos = pos + len(company_key) + 4
    data[val_pos : val_pos + len(company_val)] = company_val
    data[val_pos + len(company_val)] = 0
    data[val_pos + len(company_val) + 1] = 0

    result = analyzer._extract_version_strings(data)

    assert "CompanyName" in result
    assert "ACME Corp" in result["CompanyName"]


def test_extract_version_strings_no_keys_found():
    """Test _extract_version_strings with data that has no version keys."""
    analyzer = _make_analyzer()
    data = [0] * 100

    result = analyzer._extract_version_strings(data)

    assert result == {}


# ---------------------------------------------------------------------------
# run_resource_analysis top-level function
# ---------------------------------------------------------------------------


def test_run_resource_analysis_no_resource_dir():
    """Test run_resource_analysis when no resource directory."""
    analyzer = _make_analyzer(cmdj_map={"iDj": []})
    result = run_resource_analysis(analyzer, __import__("logging").getLogger("test"))

    assert result["available"] is True
    assert result["has_resources"] is False


def test_run_resource_analysis_with_empty_resources():
    """Test run_resource_analysis with dir but no parseable resources."""
    cmdj_map: dict[str, Any] = {
        "iDj": [{"name": "RESOURCE", "vaddr": 0x1000, "paddr": 0x800, "size": 500}],
        "iRj": [],
    }
    analyzer = _make_analyzer(cmdj_map=cmdj_map)
    result = run_resource_analysis(analyzer, __import__("logging").getLogger("test"))

    assert result["available"] is True
    assert result["has_resources"] is True
    assert result["total_resources"] == 0


# ---------------------------------------------------------------------------
# _parse_resources_manual (fallback path)
# ---------------------------------------------------------------------------


def test_parse_resources_manual_with_rsrc_section():
    """Test manual resource parsing with .rsrc section."""
    dir_data = [0] * 16
    dir_data[12] = 1  # 1 named entry
    dir_data[14] = 0  # 0 id entries

    # Entry data: type_id=3 (RT_ICON), offset to data
    entry_data = [3, 0, 0, 0, 0x10, 0, 0, 0]

    cmdj_map: dict[str, Any] = {
        "iSj": [{"name": ".rsrc", "paddr": 0x5000, "size": 0x1000}],
    }
    cmd_map = {
        "p8 16 @ 20480": _bytes_to_hex(dir_data),  # 0x5000 = 20480
        "p8 8 @ 20496": _bytes_to_hex(entry_data),  # 0x5000 + 16 = 20496
    }
    analyzer = _make_analyzer(cmdj_map=cmdj_map, cmd_map=cmd_map)

    result = analyzer._parse_resources_manual()

    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["type_id"] == 3


def test_parse_resources_manual_no_rsrc_section():
    """Test manual resource parsing without .rsrc section."""
    cmdj_map: dict[str, Any] = {
        "iSj": [{"name": ".text", "paddr": 0x1000}],
    }
    analyzer = _make_analyzer(cmdj_map=cmdj_map)

    result = analyzer._parse_resources_manual()

    assert result == []


# ---------------------------------------------------------------------------
# _analyze_resource_data
# ---------------------------------------------------------------------------


def test_analyze_resource_data_with_valid_data():
    """Test _analyze_resource_data with real byte data."""
    byte_data = list(range(256))
    cmd_map = {
        "p8 256 @ 500": _bytes_to_hex(byte_data),
    }
    analyzer = _make_analyzer(cmd_map=cmd_map)
    resource: dict[str, Any] = {"name": "test", "offset": 500, "size": 256}

    analyzer._analyze_resource_data(resource)

    assert "entropy" in resource
    assert resource["entropy"] > 0
    assert "hashes" in resource


def test_analyze_resource_data_zero_offset():
    """Test _analyze_resource_data skips when offset is 0."""
    analyzer = _make_analyzer()
    resource: dict[str, Any] = {"name": "test", "offset": 0, "size": 100}

    analyzer._analyze_resource_data(resource)

    assert resource.get("entropy", 0.0) == 0.0


def test_analyze_resource_data_zero_size():
    """Test _analyze_resource_data skips when size is 0."""
    analyzer = _make_analyzer()
    resource: dict[str, Any] = {"name": "test", "offset": 500, "size": 0}

    analyzer._analyze_resource_data(resource)

    assert resource.get("entropy", 0.0) == 0.0


# ---------------------------------------------------------------------------
# _parse_fixed_file_info
# ---------------------------------------------------------------------------


def test_parse_fixed_file_info():
    """Test _parse_fixed_file_info version string extraction."""
    analyzer = _make_analyzer()
    data = [0] * 100
    sig_pos = 10
    # file_version_ms: major=2, minor=5
    data[sig_pos + 8] = 0x05
    data[sig_pos + 9] = 0x00
    data[sig_pos + 10] = 0x02
    data[sig_pos + 11] = 0x00
    # file_version_ls: build=7, rev=1
    data[sig_pos + 12] = 0x01
    data[sig_pos + 13] = 0x00
    data[sig_pos + 14] = 0x07
    data[sig_pos + 15] = 0x00

    result = analyzer._parse_fixed_file_info(data, sig_pos)

    assert result == "2.5.7.1"


def test_parse_fixed_file_info_data_too_short():
    """Test _parse_fixed_file_info when data is too short."""
    analyzer = _make_analyzer()
    data = [0] * 20

    result = analyzer._parse_fixed_file_info(data, 10)  # sig_pos + 52 > 20

    assert result == ""


# ---------------------------------------------------------------------------
# _get_resource_type_name
# ---------------------------------------------------------------------------


def test_get_resource_type_name_known():
    """Test known resource type ID mapping."""
    analyzer = _make_analyzer()
    # RT_ICON is type_id 3
    assert analyzer._get_resource_type_name(3) == "RT_ICON"


def test_get_resource_type_name_unknown():
    """Test unknown resource type ID falls back."""
    analyzer = _make_analyzer()
    result = analyzer._get_resource_type_name(9999)
    assert result.startswith("UNKNOWN_")
