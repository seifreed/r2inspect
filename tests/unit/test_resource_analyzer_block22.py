from __future__ import annotations

from r2inspect.modules.resource_analyzer import ResourceAnalyzer


def test_resource_type_and_dir_entry_helpers():
    analyzer = ResourceAnalyzer(adapter=None)
    assert analyzer._get_resource_type_name(3) == "RT_ICON"
    assert analyzer._get_resource_type_name(999) == "UNKNOWN_999"

    entry_named = [0x00, 0x00, 0x00, 0x80, 0x10, 0x00, 0x00, 0x80]
    res_named = analyzer._parse_dir_entry(0x1000, entry_named, 1)
    assert res_named["name"].startswith("Named_")
    assert res_named["is_directory"] is True

    entry_id = [0x03, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00]
    res_id = analyzer._parse_dir_entry(0x2000, entry_id, 0)
    assert res_id["type_name"] == "RT_ICON"
    assert res_id["offset"] == 0x2000 + 0x20


def test_dir_header_and_entries_count():
    analyzer = ResourceAnalyzer(adapter=None)
    assert analyzer._is_valid_dir_header(None) is False
    assert analyzer._is_valid_dir_header([0] * 15) is False
    assert analyzer._is_valid_dir_header([0] * 16) is True

    data = [0] * 16
    data[12] = 2
    data[14] = 3
    assert analyzer._get_dir_total_entries(data) == 5


def test_entropy_and_pattern():
    analyzer = ResourceAnalyzer(adapter=None)
    assert analyzer._calculate_entropy([]) == 0.0
    assert analyzer._find_pattern([1, 2, 3, 4], [2, 3]) == 1
    assert analyzer._find_pattern([1, 2, 3, 4], [5]) == -1


def test_version_parsing_helpers():
    analyzer = ResourceAnalyzer(adapter=None)
    data = [0] * 64
    sig_pos = 0
    # file_version_ms = 0x00020001, ls = 0x00040003
    data[8] = 0x01
    data[9] = 0x00
    data[10] = 0x02
    data[11] = 0x00
    data[12] = 0x03
    data[13] = 0x00
    data[14] = 0x04
    data[15] = 0x00
    version = analyzer._parse_fixed_file_info(data, sig_pos)
    assert version == "2.1.4.3"

    # too short should return empty string
    assert analyzer._parse_fixed_file_info([0] * 10, 0) == ""


def test_version_string_extraction():
    analyzer = ResourceAnalyzer(adapter=None)
    key = "ProductName"
    value = "Example"
    key_bytes = list(key.encode("utf-16le"))
    value_bytes = list(value.encode("utf-16le"))

    data = [0] * 10 + key_bytes + [0, 0, 0, 0] + value_bytes + [0, 0]
    assert analyzer._read_version_string_value(data, key) == value

    missing = analyzer._read_version_string_value([0] * 20, "Nope")
    assert missing == ""


def test_statistics_and_suspicious_checks():
    analyzer = ResourceAnalyzer(adapter=None)
    resources = [
        {
            "type_name": "RT_ICON",
            "size": 2000,
            "entropy": 8.0,
            "name": "icon",
            "offset": 0,
        },
        {
            "type_name": "RT_RCDATA",
            "size": 20000,
            "entropy": 7.8,
            "name": "blob",
            "offset": 0,
        },
    ]

    result = {"resource_types": [], "statistics": {}, "suspicious_resources": []}
    analyzer._analyze_resource_types(result, resources)
    assert result["total_size"] == 22000
    assert any(item["type"] == "RT_ICON" for item in result["resource_types"])

    analyzer._calculate_statistics(result, resources)
    stats = result["statistics"]
    assert stats["total_resources"] == 2
    assert stats["max_size"] == 20000

    analyzer._check_suspicious_resources(result, resources)
    reasons = [s["reason"] for s in result["suspicious_resources"]]
    assert "High entropy (possibly encrypted/packed)" in reasons
    assert "Large RCDATA resource (may contain embedded data)" in reasons
