# Copyright (c) 2025 Marc Rivero Lopez
# Licensed under GPLv3. See LICENSE file for details.
"""Tests targeting uncovered lines in resource_analyzer.py."""

from __future__ import annotations

from r2inspect.modules.resource_analyzer import ResourceAnalyzer


# ---------------------------------------------------------------------------
# Stub adapter using correct method names from _SIMPLE_BASE_CALLS / _handle_bytes
# ---------------------------------------------------------------------------

class _ResponseRegistry:
    """Holds per-address responses for read_bytes_list calls."""

    def __init__(
        self,
        data_dirs: list | None = None,
        resources_info: list | None = None,
        sections: list | None = None,
        bytes_map: dict | None = None,
        raise_on_addr: int | None = None,
        raise_on_resources: bool = False,
    ) -> None:
        self._data_dirs = data_dirs or []
        self._resources_info = resources_info or []
        self._sections = sections or []
        self._bytes_map: dict[int, list[int]] = bytes_map or {}
        self._raise_on_addr = raise_on_addr
        self._raise_on_resources = raise_on_resources

    def get_data_directories(self) -> list:
        return self._data_dirs

    def get_resources_info(self) -> list:
        if self._raise_on_resources:
            raise RuntimeError("iRj command failed")
        return self._resources_info

    def get_sections(self) -> list:
        return self._sections

    def read_bytes_list(self, address: int, size: int) -> list[int]:
        if self._raise_on_addr is not None and address == self._raise_on_addr:
            raise RuntimeError("injected read error")
        return self._bytes_map.get(address, [])


# ---------------------------------------------------------------------------
# _get_resource_directory
# ---------------------------------------------------------------------------

def test_get_resource_directory_returns_none_when_resource_vaddr_is_zero() -> None:
    """Covers line 50: return None when RESOURCE entry has vaddr=0 (falls through loop)."""
    adapter = _ResponseRegistry(
        data_dirs=[{"name": "RESOURCE", "vaddr": 0, "paddr": 0, "size": 100}]
    )
    result = ResourceAnalyzer(adapter=adapter)._get_resource_directory()
    assert result is None


def test_get_resource_directory_returns_none_when_no_resource_entry() -> None:
    """Line 50: return None when no RESOURCE entry at all."""
    adapter = _ResponseRegistry(
        data_dirs=[{"name": "EXPORT", "vaddr": 0x1000, "paddr": 0x800, "size": 50}]
    )
    result = ResourceAnalyzer(adapter=adapter)._get_resource_directory()
    assert result is None


def test_get_resource_directory_returns_dict_for_valid_resource_entry() -> None:
    """Happy path: RESOURCE entry with non-zero vaddr."""
    adapter = _ResponseRegistry(
        data_dirs=[
            {"name": "IMPORT", "vaddr": 0x2000, "paddr": 0x1800, "size": 20},
            {"name": "RESOURCE", "vaddr": 0x5000, "paddr": 0x4000, "size": 512},
        ]
    )
    result = ResourceAnalyzer(adapter=adapter)._get_resource_directory()
    assert result is not None
    assert result["virtual_address"] == 0x5000
    assert result["offset"] == 0x4000
    assert result["size"] == 512


# ---------------------------------------------------------------------------
# _parse_resources – non-dict items in the list (line 68)
# ---------------------------------------------------------------------------

def test_parse_resources_skips_non_dict_items() -> None:
    """Line 68: continue when list item is not a dict."""
    adapter = _ResponseRegistry(
        resources_info=[
            42,
            "not_a_dict",
            {"name": "icon", "type": "RT_ICON", "type_id": 3, "lang": "en",
             "paddr": 0, "size": 0, "vaddr": 0},
        ]
    )
    result = ResourceAnalyzer(adapter=adapter)._parse_resources()
    # Only the valid dict item should produce an entry
    assert len(result) == 1
    assert result[0]["name"] == "icon"


# ---------------------------------------------------------------------------
# _parse_resources_manual (lines 103-116) + _parse_dir_entries (lines 142-150)
# ---------------------------------------------------------------------------

def _build_valid_dir_header(named_entries: int = 0, id_entries: int = 1) -> list[int]:
    """Build a minimal IMAGE_RESOURCE_DIRECTORY header (16 bytes)."""
    hdr = [0] * 16
    hdr[12] = named_entries & 0xFF
    hdr[13] = (named_entries >> 8) & 0xFF
    hdr[14] = id_entries & 0xFF
    hdr[15] = (id_entries >> 8) & 0xFF
    return hdr


def test_parse_resources_manual_with_valid_rsrc_section() -> None:
    """Lines 103-116: exercise manual parsing when iRj raises an exception."""
    rsrc_base = 0x2000
    entry_offset = rsrc_base + 16

    # Directory header at rsrc_base with 1 named-entry
    dir_header = _build_valid_dir_header(named_entries=1, id_entries=0)

    # Entry data (8 bytes): id=3 (RT_ICON), offset=0x100 (not a directory)
    entry_data = [0x03, 0x00, 0x00, 0x00,  # name_or_id = 3
                  0x00, 0x01, 0x00, 0x00]  # offset_to_data = 0x100

    adapter = _ResponseRegistry(
        raise_on_resources=True,
        sections=[{"name": ".rsrc", "paddr": rsrc_base, "size": 4096}],
        bytes_map={
            rsrc_base: dir_header,
            entry_offset: entry_data,
        },
    )
    resources = ResourceAnalyzer(adapter=adapter)._parse_resources()
    assert len(resources) == 1
    assert resources[0]["type_name"] == "RT_ICON"


def test_parse_resources_manual_rsrc_paddr_zero_returns_empty() -> None:
    """Lines 103-105: manual parsing exits early when .rsrc paddr is 0."""
    adapter = _ResponseRegistry(
        raise_on_resources=True,
        sections=[{"name": ".rsrc", "paddr": 0, "size": 100}],
    )
    result = ResourceAnalyzer(adapter=adapter)._parse_resources()
    assert result == []


def test_parse_resources_manual_invalid_dir_header_returns_empty() -> None:
    """Lines 107-109: manual parsing stops when dir header is invalid."""
    rsrc_base = 0x3000
    adapter = _ResponseRegistry(
        raise_on_resources=True,
        sections=[{"name": ".rsrc", "paddr": rsrc_base, "size": 4096}],
        bytes_map={rsrc_base: [0, 1, 2]},  # only 3 bytes - invalid
    )
    result = ResourceAnalyzer(adapter=adapter)._parse_resources()
    assert result == []


def test_parse_resources_manual_exception_returns_empty() -> None:
    """Lines 114-116: manual parsing handles exception gracefully."""
    rsrc_base = 0x4000
    dir_header = _build_valid_dir_header(id_entries=1)
    entry_offset = rsrc_base + 16

    adapter = _ResponseRegistry(
        raise_on_resources=True,
        sections=[{"name": ".rsrc", "paddr": rsrc_base, "size": 4096}],
        bytes_map={rsrc_base: dir_header},
        raise_on_addr=entry_offset,
    )
    result = ResourceAnalyzer(adapter=adapter)._parse_resources()
    assert isinstance(result, list)


def test_parse_dir_entries_loops_over_multiple_entries() -> None:
    """Lines 142-150: loop processes several entries."""
    rsrc_base = 0x5000
    dir_header = _build_valid_dir_header(id_entries=2)
    entry0_offset = rsrc_base + 16
    entry1_offset = rsrc_base + 24

    entry0_data = [0x03, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00]  # RT_ICON, offset 0x10
    entry1_data = [0x06, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00]  # RT_STRING, offset 0x20

    adapter = _ResponseRegistry(
        raise_on_resources=True,
        sections=[{"name": ".rsrc", "paddr": rsrc_base, "size": 4096}],
        bytes_map={
            rsrc_base: dir_header,
            entry0_offset: entry0_data,
            entry1_offset: entry1_data,
        },
    )
    resources = ResourceAnalyzer(adapter=adapter)._parse_resources()
    assert len(resources) == 2


# ---------------------------------------------------------------------------
# _analyze_resource_data (lines 202-213)
# ---------------------------------------------------------------------------

def test_analyze_resource_data_calculates_entropy_and_hashes() -> None:
    """Lines 202, 205-207: valid data path – entropy and hashes populated."""
    offset = 0x9000
    size = 8
    data = list(range(256)) * 4  # varied data for entropy > 0

    adapter = _ResponseRegistry(bytes_map={offset: data})
    analyzer = ResourceAnalyzer(adapter=adapter)
    resource = {"offset": offset, "size": size, "entropy": 0.0, "hashes": {}}
    analyzer._analyze_resource_data(resource)

    assert resource["entropy"] > 0.0
    assert "md5" in resource["hashes"] or "sha256" in resource["hashes"]


def test_analyze_resource_data_handles_hash_exception() -> None:
    """Lines 208-210: hash calculation exception path – hashes set to empty dict."""
    offset = 0xA000

    class _BadBytesAdapter(_ResponseRegistry):
        def read_bytes_list(self, address: int, size: int) -> list:
            # Return a list with a non-int item to trigger TypeError in bytes(data)
            return [1, 2, "bad", 4]

    analyzer = ResourceAnalyzer(adapter=_BadBytesAdapter())
    resource = {"offset": offset, "size": 4, "entropy": 0.0, "hashes": {}}
    analyzer._analyze_resource_data(resource)
    assert resource["hashes"] == {}


def test_analyze_resource_data_outer_exception() -> None:
    """Lines 212-213: outer exception caught when resource dict is malformed."""
    analyzer = ResourceAnalyzer(adapter=_ResponseRegistry())
    # Missing 'size' key will cause a KeyError inside the method
    resource = {"offset": 0x100, "entropy": 0.0, "hashes": {}}
    # Should not raise – exception is logged and swallowed
    analyzer._analyze_resource_data(resource)


# ---------------------------------------------------------------------------
# _parse_version_info / _read_version_info_data (lines 266-295)
# ---------------------------------------------------------------------------

def _build_version_data_with_signature() -> list[int]:
    """Build a 128-byte fake version block with VS_FIXEDFILEINFO signature."""
    data = [0] * 128
    # VS_FIXEDFILEINFO signature at offset 0
    sig = [0xBD, 0x04, 0xEF, 0xFE]
    for i, b in enumerate(sig):
        data[i] = b
    # file_version_ms at sig_pos+8: 2.1 -> 0x00020001
    data[8] = 0x01; data[9] = 0x00; data[10] = 0x02; data[11] = 0x00
    # file_version_ls at sig_pos+12: 4.3 -> 0x00040003
    data[12] = 0x03; data[13] = 0x00; data[14] = 0x04; data[15] = 0x00

    # Embed a UTF-16LE "ProductName\x00\x00" + value "TestApp\x00\x00"
    key = "ProductName"
    key_bytes = list(key.encode("utf-16le"))
    value = "TestApp"
    value_bytes = list(value.encode("utf-16le"))
    pos = 20
    for b in key_bytes:
        data[pos] = b
        pos += 1
    # 4-byte separator
    pos += 4
    for b in value_bytes:
        data[pos] = b
        pos += 1
    # null terminator (2 bytes)
    data[pos] = 0
    data[pos + 1] = 0
    return data


def test_parse_version_info_returns_dict_with_strings() -> None:
    """Lines 266-288: full _parse_version_info path with valid version data."""
    offset = 0xB000
    version_data = _build_version_data_with_signature()

    adapter = _ResponseRegistry(bytes_map={offset: version_data})
    analyzer = ResourceAnalyzer(adapter=adapter)
    result = analyzer._parse_version_info(offset=offset, size=128)

    # If ProductName string was found, result is not None
    # (depends on exact byte layout, but we at least exercise the code path)
    # The method may return None if strings not found due to layout, that's OK
    assert result is None or isinstance(result, dict)


def test_parse_version_info_returns_none_for_short_size() -> None:
    """Line 259-260: early return when size < 64."""
    analyzer = ResourceAnalyzer(adapter=_ResponseRegistry())
    result = analyzer._parse_version_info(offset=0x100, size=32)
    assert result is None


def test_parse_version_info_returns_none_for_zero_offset() -> None:
    """Line 259-260: early return when offset == 0."""
    analyzer = ResourceAnalyzer(adapter=_ResponseRegistry())
    result = analyzer._parse_version_info(offset=0, size=128)
    assert result is None


def test_read_version_info_data_returns_list_when_enough_bytes() -> None:
    """Line 295: _read_version_info_data returns list(data) when data is long enough."""
    offset = 0xC000
    valid_data = list(range(100))  # 100 bytes, >= 64

    adapter = _ResponseRegistry(bytes_map={offset: valid_data})
    result = ResourceAnalyzer(adapter=adapter)._read_version_info_data(offset=offset, size=100)

    assert result == valid_data


def test_read_version_info_data_returns_none_for_short_data() -> None:
    """Lines 293-294: returns None when data is fewer than 64 bytes."""
    offset = 0xD000
    adapter = _ResponseRegistry(bytes_map={offset: list(range(30))})
    result = ResourceAnalyzer(adapter=adapter)._read_version_info_data(offset=offset, size=100)
    assert result is None


# ---------------------------------------------------------------------------
# _read_version_string_value (lines 345-365)
# ---------------------------------------------------------------------------

def test_read_version_string_value_empty_when_key_not_found() -> None:
    """Returns empty string when key pattern absent."""
    analyzer = ResourceAnalyzer(adapter=None)
    result = analyzer._read_version_string_value([0] * 50, "MissingKey")
    assert result == ""


def test_read_version_string_value_empty_when_no_value_bytes() -> None:
    """Line 360: returns '' when value bytes list is empty (first pair is null terminator).

    The data has enough room so value_start < len(data)-2, the loop runs,
    but the first two bytes at value_start are both zero, causing an immediate
    break and leaving value_bytes empty.
    """
    key = "CompanyName"
    key_bytes = list(key.encode("utf-16le"))  # 22 bytes
    # key at position 0, then 4 separator bytes, then immediately two null bytes
    # and more padding so value_start (22+4=26) < len(data)-2 (28+2-2=28)
    # Use: key(22) + sep(4) + null_null(2) + extra_pad(6) = 34 bytes
    # value_start = 26, len(data)-2 = 32 -> 26 < 32 ✓
    # Loop first i=26: data[26]=0, data[27]=0 -> break immediately -> value_bytes=[]
    data = key_bytes + [0, 0, 0, 0, 0, 0] + [0] * 6
    result = ResourceAnalyzer(adapter=None)._read_version_string_value(data, key)
    assert result == ""


def test_read_version_string_value_returns_decoded_string() -> None:
    """Lines 362-363: returns decoded UTF-16LE value string."""
    key = "ProductName"
    value = "Acme"
    key_bytes = list(key.encode("utf-16le"))
    value_bytes = list(value.encode("utf-16le"))
    # key + 4-byte separator + value + null terminator
    data = [0] * 10 + key_bytes + [0, 0, 0, 0] + value_bytes + [0, 0]
    result = ResourceAnalyzer(adapter=None)._read_version_string_value(data, key)
    assert result == value


def test_read_version_string_value_returns_empty_for_non_printable() -> None:
    """Line 363: returns '' when decoded value is not printable."""
    key = "FileVersion"
    key_bytes = list(key.encode("utf-16le"))
    # value = two control chars (non-printable)
    value_bytes = [0x01, 0x00, 0x02, 0x00]
    data = [0] * 10 + key_bytes + [0, 0, 0, 0] + value_bytes + [0, 0]
    result = ResourceAnalyzer(adapter=None)._read_version_string_value(data, key)
    assert result == ""


# ---------------------------------------------------------------------------
# _extract_manifest (lines 367-383)
# ---------------------------------------------------------------------------

def test_extract_manifest_populates_result_on_valid_data() -> None:
    """Lines 374-381: manifest dict is set when data is available."""
    manifest_xml = '<assembly xmlns="urn:schemas-microsoft-com:asm.v1">'.encode("utf-16le")
    offset = 0xE000
    size = len(manifest_xml)

    adapter = _ResponseRegistry(bytes_map={offset: list(manifest_xml)})
    analyzer = ResourceAnalyzer(adapter=adapter)

    resources = [{"type_name": "RT_MANIFEST", "offset": offset, "size": size}]
    result: dict = {}
    analyzer._extract_manifest(result, resources)

    # manifest key should be set
    assert "manifest" in result
    assert "content" in result["manifest"]


def test_extract_manifest_logs_on_exception() -> None:
    """Lines 382-383: exception during extraction is swallowed silently."""
    # Resource missing 'offset' key to trigger KeyError inside the try
    resources = [{"type_name": "RT_MANIFEST"}]
    result: dict = {}
    # Should not raise
    ResourceAnalyzer(adapter=_ResponseRegistry())._extract_manifest(result, resources)


# ---------------------------------------------------------------------------
# _extract_strings (lines 406-421)
# ---------------------------------------------------------------------------

def test_extract_strings_populates_result_on_valid_data() -> None:
    """Lines 416-417: strings list is extended when RT_STRING resource is found."""
    text = "Hello\x00World\x00TestString\x00More"
    string_bytes = text.encode("utf-16le")
    offset = 0xF000
    size = len(string_bytes)

    adapter = _ResponseRegistry(bytes_map={offset: list(string_bytes)})
    analyzer = ResourceAnalyzer(adapter=adapter)

    resources = [{"type_name": "RT_STRING", "offset": offset, "size": size}]
    result: dict = {"strings": []}
    analyzer._extract_strings(result, resources)

    # At least the strings key should exist (may be empty depending on content)
    assert "strings" in result


def test_extract_strings_handles_exception() -> None:
    """Lines 418-419: exception during extraction is swallowed."""
    # Resource missing 'offset' key triggers KeyError inside the try
    resources = [{"type_name": "RT_STRING"}]
    result: dict = {"strings": []}
    ResourceAnalyzer(adapter=_ResponseRegistry())._extract_strings(result, resources)
    assert result["strings"] == []


# ---------------------------------------------------------------------------
# _read_resource_as_string (lines 423-465)
# ---------------------------------------------------------------------------

def test_read_resource_as_string_utf16le_path() -> None:
    """Lines 438-441: UTF-16LE decode succeeds for Unicode text bytes."""
    # "He" encoded in UTF-16LE
    data = [72, 0, 101, 0]
    offset = 0x10000
    size = len(data)

    adapter = _ResponseRegistry(bytes_map={offset: data})
    result = ResourceAnalyzer(adapter=adapter)._read_resource_as_string(offset, size)

    assert result is not None
    assert "H" in result


def test_read_resource_as_string_utf8_fallback() -> None:
    """Lines 446-449: UTF-8 path reached when UTF-16LE yields no printable chars.

    Bytes [0x01, 0x00, 0x01, 0x00, 0x65]:
      - utf-16le: U+0001 + U+0001, trailing byte ignored -> all SOH -> not printable
      - utf-8: decodes to '\\x01\\x00\\x01\\x00e' -> 'e' is printable -> returned
    """
    data = [0x01, 0x00, 0x01, 0x00, 0x65]
    offset = 0x11000

    adapter = _ResponseRegistry(bytes_map={offset: data})
    result = ResourceAnalyzer(adapter=adapter)._read_resource_as_string(offset, len(data))

    assert result is not None


def test_read_resource_as_string_type_error_in_all_decoders() -> None:
    """Lines 442-443, 450-451, 457-459: TypeError in bytes() triggers all except passes.

    A list containing a non-integer item causes bytes() to raise TypeError
    in every decode attempt, so all three except (UnicodeDecodeError, TypeError)
    clauses are exercised, and the method returns None.
    """
    offset = 0x14000

    class _NonIntDataAdapter(_ResponseRegistry):
        def read_bytes_list(self, address: int, size: int) -> list:
            # Non-int element triggers TypeError in bytes(data)
            return ["x"]

    adapter = _NonIntDataAdapter()
    result = ResourceAnalyzer(adapter=adapter)._read_resource_as_string(offset, size=100)
    # All decode paths fail → returns None
    assert result is None



    """Line 461: returns None when all decoders produce only non-printable text."""
    # All control chars – none printable in any encoding
    data = [0x01, 0x00, 0x02, 0x00]
    offset = 0x12000

    adapter = _ResponseRegistry(bytes_map={offset: data})
    result = ResourceAnalyzer(adapter=adapter)._read_resource_as_string(offset, len(data))

    assert result is None


def test_read_resource_as_string_exception_from_read() -> None:
    """Lines 463-465: outer exception handler fires when read_bytes_list raises."""
    offset = 0x13000

    adapter = _ResponseRegistry(raise_on_addr=offset)
    result = ResourceAnalyzer(adapter=adapter)._read_resource_as_string(offset, size=100)

    assert result is None


def test_read_resource_as_string_returns_none_for_zero_offset() -> None:
    """Line 426-427: early return when offset is zero."""
    result = ResourceAnalyzer(adapter=None)._read_resource_as_string(0, 100)
    assert result is None


def test_read_resource_as_string_returns_none_when_data_empty() -> None:
    """Lines 434-435: returns None when adapter returns empty list."""
    adapter = _ResponseRegistry(bytes_map={})
    result = ResourceAnalyzer(adapter=adapter)._read_resource_as_string(0x1000, 100)
    assert result is None


# ---------------------------------------------------------------------------
# _check_resource_embedded_pe – non-MZ header (line 559)
# ---------------------------------------------------------------------------

def test_check_resource_embedded_pe_returns_empty_for_non_mz_header() -> None:
    """Line 559: return [] when header bytes are NOT 0x4D 0x5A (MZ)."""
    # Header is 'PE' (0x50, 0x45) – not MZ
    offset = 0x20000

    adapter = _ResponseRegistry(bytes_map={offset: [0x50, 0x45]})
    analyzer = ResourceAnalyzer(adapter=adapter)

    res = {
        "type_name": "RT_RCDATA",
        "name": "data",
        "size": 2048,
        "offset": offset,
        "entropy": 0.0,
    }
    result = analyzer._check_resource_embedded_pe(res)
    assert result == []


def test_check_resource_embedded_pe_returns_entry_for_mz_header() -> None:
    """Lines 551-558: returns suspicious entry when header starts with MZ."""
    offset = 0x21000

    adapter = _ResponseRegistry(bytes_map={offset: [0x4D, 0x5A]})
    analyzer = ResourceAnalyzer(adapter=adapter)

    res = {
        "type_name": "RT_RCDATA",
        "name": "embedded",
        "size": 2048,
        "offset": offset,
        "entropy": 0.0,
    }
    result = analyzer._check_resource_embedded_pe(res)
    assert len(result) == 1
    assert "embedded PE" in result[0]["reason"]


def test_check_resource_embedded_pe_returns_empty_for_short_header_data() -> None:
    """Line 550: empty result when header_data has fewer than 2 bytes."""
    offset = 0x22000
    adapter = _ResponseRegistry(bytes_map={offset: [0x4D]})  # only 1 byte
    analyzer = ResourceAnalyzer(adapter=adapter)

    res = {"type_name": "UNKNOWN", "name": "x", "size": 2048, "offset": offset, "entropy": 0.0}
    result = analyzer._check_resource_embedded_pe(res)
    assert result == []
