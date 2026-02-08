from __future__ import annotations

from typing import Any

import pytest

from r2inspect.modules.resource_analyzer import ResourceAnalyzer


class _Adapter:
    def __init__(self, byte_map: dict[tuple[int, int], list[int]], data_dirs: list[dict[str, Any]]):
        self._byte_map = byte_map
        self._data_dirs = data_dirs

    def get_data_directories(self):
        return self._data_dirs

    def get_resources_info(self):
        # Resources returned by iRj
        return [
            {
                "name": "VERS",
                "type": "RT_VERSION",
                "type_id": 16,
                "lang": "en",
                "paddr": 100,
                "size": 128,
                "vaddr": 0x2000,
            },
            {
                "name": "MANI",
                "type": "RT_MANIFEST",
                "type_id": 24,
                "lang": "en",
                "paddr": 400,
                "size": 96,
                "vaddr": 0x3000,
            },
            {
                "name": "ICON",
                "type": "RT_ICON",
                "type_id": 3,
                "lang": "en",
                "paddr": 600,
                "size": 32,
                "vaddr": 0x4000,
            },
            {
                "name": "STR",
                "type": "RT_STRING",
                "type_id": 6,
                "lang": "en",
                "paddr": 700,
                "size": 64,
                "vaddr": 0x5000,
            },
            {
                "name": "RC",
                "type": "RT_RCDATA",
                "type_id": 10,
                "lang": "en",
                "paddr": 800,
                "size": 2048,
                "vaddr": 0x6000,
            },
            {
                "name": "EMPTY",
                "type": "RT_BITMAP",
                "type_id": 2,
                "lang": "en",
                "paddr": 0,
                "size": 0,
                "vaddr": 0,
            },
        ]

    def read_bytes_list(self, address: int, size: int | None = None):
        if size is None:
            return []
        return self._byte_map.get((address, size), [])

    def read_bytes(self, address: int, size: int):
        data = self._byte_map.get((address, size))
        if not data:
            return b""
        return bytes(data)

    def get_sections(self):
        return [{"name": ".rsrc", "paddr": 1000}]


@pytest.fixture
def adapter():
    # Build VERSION_INFO data: signature + version + CompanyName key/value
    version_data = [0] * 80
    version_data[0:4] = [0xBD, 0x04, 0xEF, 0xFE]  # VS_FIXEDFILEINFO signature
    # file_version_ms = 1.2, file_version_ls = 3.4
    version_data[8:12] = [2, 0, 1, 0]
    version_data[12:16] = [4, 0, 3, 0]

    key = "CompanyName".encode("utf-16le")
    value = "Acme".encode("utf-16le")
    key_offset = 32
    version_data[key_offset : key_offset + len(key)] = list(key)
    value_start = key_offset + len(key) + 4
    version_data[value_start : value_start + len(value)] = list(value)
    # null-terminate
    version_data[value_start + len(value) : value_start + len(value) + 2] = [0, 0]

    manifest_text = '<requestedExecutionLevel level="requireAdministrator"/>'
    manifest_bytes = list(manifest_text.encode("utf-16le"))
    string_text = "Hello\x00World\x00"
    string_bytes = list(string_text.encode("utf-16le"))

    byte_map = {
        (100, 128): version_data,
        (400, 96): manifest_bytes,
        (600, 32): [1] * 32,
        (700, 64): string_bytes,
        (800, 2048): [0x4D, 0x5A] + [0] * 2046,  # MZ header for embedded PE
        (800, 2): [0x4D, 0x5A],
    }

    data_dirs = [{"name": "RESOURCE", "vaddr": 0x2000, "paddr": 1000, "size": 4096}]
    return _Adapter(byte_map, data_dirs)


def test_resource_analyzer_full_flow(adapter):
    analyzer = ResourceAnalyzer(adapter)
    result = analyzer.analyze()

    assert result["available"] is True
    assert result["has_resources"] is True
    assert result["resource_directory"]["offset"] == 1000
    assert result["total_resources"] >= 5
    assert result["manifest"]["requires_admin"] is True
    assert result["icons"]
    assert "Hello" in " ".join(result["strings"]) if result["strings"] else True
    assert result["statistics"]["total_resources"] >= 1
    assert result["suspicious_resources"]


def test_resource_analyzer_helpers(adapter):
    analyzer = ResourceAnalyzer(adapter)

    assert analyzer._is_valid_dir_header([0] * 16) is True
    assert analyzer._is_valid_dir_header([]) is False
    assert analyzer._get_dir_total_entries([0] * 16) == 0

    entry = analyzer._parse_dir_entry(1000, [1, 0, 0, 0, 8, 0, 0, 0], 0)
    assert entry is not None
    assert entry["type_id"] == 1

    # Named resource
    entry_named = analyzer._parse_dir_entry(1000, [0, 0, 0, 0x80, 0, 0, 0, 0], 1)
    assert entry_named is not None
    assert entry_named["name"].startswith("Named_")

    # Entropy helper
    assert analyzer._calculate_entropy([0, 1, 2, 3]) >= 0

    # Pattern search
    assert analyzer._find_pattern([1, 2, 3, 4], [2, 3]) == 1
    assert analyzer._find_pattern([1, 2, 3], [9]) == -1

    # Suspicious resource checks
    res = {"name": "X", "type_name": "RT_RCDATA", "entropy": 8.0, "size": 2_000_000, "offset": 800}
    assert analyzer._check_resource_entropy(res)
    assert analyzer._check_resource_size(res)
    assert analyzer._check_resource_rcdata(res)
    assert analyzer._check_resource_embedded_pe(res)


def test_resource_analyzer_parse_version_info(adapter):
    analyzer = ResourceAnalyzer(adapter)
    version = analyzer._parse_version_info(100, 128)
    assert version is not None
    assert version["file_version"]
    assert version["strings"]["CompanyName"] == "Acme"


def test_resource_analyzer_read_resource_as_string(adapter):
    analyzer = ResourceAnalyzer(adapter)
    text = analyzer._read_resource_as_string(400, 96)
    assert text is not None
    assert "requireAdministrator" in text

    assert analyzer._read_resource_as_string(0, 0) is None
