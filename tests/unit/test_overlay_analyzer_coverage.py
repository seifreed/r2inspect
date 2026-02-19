"""Comprehensive tests for overlay_analyzer.py - achieving 100% coverage."""

import pytest
from unittest.mock import MagicMock, patch
from r2inspect.modules.overlay_analyzer import OverlayAnalyzer


def test_initialization():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)
    assert analyzer.adapter == adapter


def test_analyze_no_file_size():
    adapter = MagicMock()
    adapter.cmdj.return_value = {}

    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()

    assert result["available"] is True
    assert result["has_overlay"] is False


def test_analyze_no_pe_end():
    adapter = MagicMock()
    adapter.cmdj.side_effect = [
        {"core": {"size": 10000}},
        [],
    ]

    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()

    assert result["has_overlay"] is False


def test_analyze_overlay_size_zero():
    adapter = MagicMock()
    adapter.cmdj.side_effect = [
        {"core": {"size": 1000}},
        [{"name": ".text", "paddr": 0, "size": 1000}],
    ]

    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()

    assert result["has_overlay"] is False


def test_analyze_with_overlay():
    adapter = MagicMock()
    overlay_data = [0x4D, 0x5A] + [0] * 100
    adapter.cmdj.side_effect = [
        {"core": {"size": 10000}},
        [{"name": ".text", "paddr": 0, "size": 5000}],
        [],
        overlay_data,
    ]

    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()

    assert result["has_overlay"] is True
    assert result["overlay_offset"] == 5000
    assert result["overlay_size"] == 5000
    assert result["file_size"] == 10000
    assert result["pe_end"] == 5000


def test_analyze_exception():
    adapter = MagicMock()
    adapter.cmdj.side_effect = Exception("Test error")

    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()

    assert result["available"] is False
    assert result["has_overlay"] is False
    assert "error" in result


def test_get_file_size_valid():
    adapter = MagicMock()
    adapter.cmdj.return_value = {"core": {"size": 12345}}

    analyzer = OverlayAnalyzer(adapter)
    size = analyzer._get_file_size()

    assert size == 12345


def test_get_file_size_invalid_dict():
    adapter = MagicMock()
    adapter.cmdj.return_value = "invalid"

    analyzer = OverlayAnalyzer(adapter)
    size = analyzer._get_file_size()

    assert size is None


def test_get_file_size_missing_size():
    adapter = MagicMock()
    adapter.cmdj.return_value = {"core": {}}

    analyzer = OverlayAnalyzer(adapter)
    size = analyzer._get_file_size()

    assert size is None


def test_get_file_size_invalid_value():
    adapter = MagicMock()
    adapter.cmdj.return_value = {"core": {"size": "invalid"}}

    analyzer = OverlayAnalyzer(adapter)
    size = analyzer._get_file_size()

    assert size is None


def test_get_valid_pe_end_success():
    adapter = MagicMock()
    adapter.cmdj.return_value = [{"name": ".text", "paddr": 0, "size": 1000}]

    analyzer = OverlayAnalyzer(adapter)
    pe_end = analyzer._get_valid_pe_end(5000)

    assert pe_end == 1000


def test_get_valid_pe_end_zero():
    adapter = MagicMock()
    adapter.cmdj.return_value = []

    analyzer = OverlayAnalyzer(adapter)
    pe_end = analyzer._get_valid_pe_end(5000)

    assert pe_end is None


def test_get_valid_pe_end_exceeds_file_size():
    adapter = MagicMock()
    adapter.cmdj.return_value = [{"name": ".text", "paddr": 0, "size": 10000}]

    analyzer = OverlayAnalyzer(adapter)
    pe_end = analyzer._get_valid_pe_end(5000)

    assert pe_end is None


def test_get_valid_pe_end_invalid_type():
    adapter = MagicMock()
    adapter.cmdj.return_value = [{"name": ".text", "paddr": 0, "size": "invalid"}]

    analyzer = OverlayAnalyzer(adapter)
    pe_end = analyzer._get_valid_pe_end(5000)

    assert pe_end is None


def test_populate_overlay_metadata():
    result = {
        "has_overlay": False,
        "overlay_offset": 0,
        "overlay_size": 0,
        "file_size": 0,
        "pe_end": 0,
    }

    OverlayAnalyzer._populate_overlay_metadata(result, 10000, 5000, 5000)

    assert result["has_overlay"] is True
    assert result["overlay_offset"] == 5000
    assert result["overlay_size"] == 5000
    assert result["file_size"] == 10000
    assert result["pe_end"] == 5000


def test_calculate_pe_end():
    adapter = MagicMock()
    adapter.cmdj.side_effect = [
        [{"name": ".text", "paddr": 100, "size": 500}],
        [],
    ]

    analyzer = OverlayAnalyzer(adapter)
    pe_end = analyzer._calculate_pe_end()

    assert pe_end == 600


def test_calculate_pe_end_exception():
    adapter = MagicMock()
    adapter.cmdj.side_effect = Exception("Error")

    analyzer = OverlayAnalyzer(adapter)
    pe_end = analyzer._calculate_pe_end()

    assert pe_end == 0


def test_get_sections_valid():
    adapter = MagicMock()
    adapter.cmdj.return_value = [
        {"name": ".text", "paddr": 0, "size": 100},
        {"name": ".data", "paddr": 100, "size": 50},
    ]

    analyzer = OverlayAnalyzer(adapter)
    sections = analyzer._get_sections()

    assert len(sections) == 2


def test_get_sections_invalid():
    adapter = MagicMock()
    adapter.cmdj.return_value = "invalid"

    analyzer = OverlayAnalyzer(adapter)
    sections = analyzer._get_sections()

    assert sections == []


def test_get_sections_mixed():
    adapter = MagicMock()
    adapter.cmdj.return_value = [
        {"name": ".text", "paddr": 0, "size": 100},
        "invalid",
        {"name": ".data", "paddr": 100, "size": 50},
    ]

    analyzer = OverlayAnalyzer(adapter)
    sections = analyzer._get_sections()

    assert len(sections) == 2


def test_get_max_section_end():
    sections = [
        {"paddr": 0, "size": 500},
        {"paddr": 500, "size": 1000},
        {"paddr": 1500, "size": 200},
    ]

    max_end = OverlayAnalyzer._get_max_section_end(sections)
    assert max_end == 1700


def test_get_max_section_end_empty():
    max_end = OverlayAnalyzer._get_max_section_end([])
    assert max_end == 0


def test_extend_end_with_certificate():
    adapter = MagicMock()
    adapter.cmdj.return_value = [
        {"name": "SECURITY", "paddr": 5000, "size": 1000}
    ]

    analyzer = OverlayAnalyzer(adapter)
    extended_end = analyzer._extend_end_with_certificate(3000)

    assert extended_end == 6000


def test_extend_end_with_certificate_smaller():
    adapter = MagicMock()
    adapter.cmdj.return_value = [
        {"name": "SECURITY", "paddr": 2000, "size": 500}
    ]

    analyzer = OverlayAnalyzer(adapter)
    extended_end = analyzer._extend_end_with_certificate(5000)

    assert extended_end == 5000


def test_extend_end_with_certificate_no_security():
    adapter = MagicMock()
    adapter.cmdj.return_value = [
        {"name": "IMPORT", "paddr": 2000, "size": 500}
    ]

    analyzer = OverlayAnalyzer(adapter)
    extended_end = analyzer._extend_end_with_certificate(5000)

    assert extended_end == 5000


def test_extend_end_with_certificate_invalid():
    adapter = MagicMock()
    adapter.cmdj.return_value = "invalid"

    analyzer = OverlayAnalyzer(adapter)
    extended_end = analyzer._extend_end_with_certificate(5000)

    assert extended_end == 5000


def test_analyze_overlay_content():
    adapter = MagicMock()
    overlay_data = [0x4D, 0x5A] + [0x41] * 100
    adapter.cmdj.return_value = overlay_data

    analyzer = OverlayAnalyzer(adapter)
    result = {
        "overlay_entropy": 0.0,
        "overlay_hashes": {},
        "patterns_found": [],
        "potential_type": "unknown",
        "extracted_strings": [],
        "embedded_files": [],
    }
    analyzer._analyze_overlay_content(result, 0, 1000)

    assert result["overlay_entropy"] > 0
    assert "md5" in result["overlay_hashes"]
    assert len(result["embedded_files"]) > 0


def test_analyze_overlay_content_no_data():
    adapter = MagicMock()
    adapter.cmdj.return_value = None

    analyzer = OverlayAnalyzer(adapter)
    result = {
        "overlay_entropy": 0.0,
        "overlay_hashes": {},
        "patterns_found": [],
        "potential_type": "unknown",
        "extracted_strings": [],
        "embedded_files": [],
    }
    analyzer._analyze_overlay_content(result, 0, 1000)


def test_analyze_overlay_content_exception():
    adapter = MagicMock()
    adapter.cmdj.side_effect = Exception("Error")

    analyzer = OverlayAnalyzer(adapter)
    result = {
        "overlay_entropy": 0.0,
        "overlay_hashes": {},
        "patterns_found": [],
        "potential_type": "unknown",
        "extracted_strings": [],
        "embedded_files": [],
    }
    analyzer._analyze_overlay_content(result, 0, 1000)


def test_calculate_entropy():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    data = [0] * 256
    entropy = analyzer._calculate_entropy(data)
    assert entropy == 0.0

    data = list(range(256))
    entropy = analyzer._calculate_entropy(data)
    assert entropy > 0


def test_check_patterns_nsis():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    data = [0xEF, 0xBE, 0xAD, 0xDE, 0x4E, 0x75, 0x6C, 0x6C, 0x73, 0x6F, 0x66, 0x74] + [0] * 100
    patterns = analyzer._check_patterns(data)

    assert any(p["name"] == "NSIS" for p in patterns)


def test_check_patterns_inno_setup():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    data = [0x49, 0x6E, 0x6E, 0x6F, 0x20, 0x53, 0x65, 0x74, 0x75, 0x70] + [0] * 100
    patterns = analyzer._check_patterns(data)

    assert any(p["name"] == "Inno Setup" for p in patterns)


def test_check_patterns_encrypted():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    data = list(range(256)) * 10
    patterns = analyzer._check_patterns(data)

    assert any(p["type"] == "encrypted" for p in patterns)


def test_check_patterns_xml():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    data = [0x3C, 0x3F, 0x78, 0x6D, 0x6C] + [0] * 100
    patterns = analyzer._check_patterns(data)

    assert any(p["name"] == "XML data" for p in patterns)


def test_check_patterns_json():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    data = [0x7B, 0x22] + [0] * 100
    patterns = analyzer._check_patterns(data)

    assert any(p["name"] == "JSON data" for p in patterns)


def test_check_patterns_asn1():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    data = [0x30, 0x82] + [0] * 100
    patterns = analyzer._check_patterns(data)

    assert any(p["name"] == "ASN.1 structure (possible certificate)" for p in patterns)


def test_determine_overlay_type_installer():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    patterns = [{"type": "installer", "name": "NSIS"}]
    data = [0] * 100

    overlay_type = analyzer._determine_overlay_type(patterns, data)
    assert overlay_type == "installer (NSIS)"


def test_determine_overlay_type_encrypted():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    patterns = []
    data = list(range(256)) * 10

    overlay_type = analyzer._determine_overlay_type(patterns, data)
    assert overlay_type == "encrypted/compressed"


def test_determine_overlay_type_padding():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    patterns = []
    data = [0] * 1024

    overlay_type = analyzer._determine_overlay_type(patterns, data)
    assert overlay_type == "padding"


def test_determine_overlay_type_data():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    patterns = []
    data = [0x41, 0x42, 0x43] * 100

    overlay_type = analyzer._determine_overlay_type(patterns, data)
    assert overlay_type == "data"


def test_determine_overlay_type_multiple_patterns():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    patterns = [
        {"type": "config", "name": "XML"},
        {"type": "config", "name": "JSON"},
    ]
    data = [0] * 100

    overlay_type = analyzer._determine_overlay_type(patterns, data)
    assert overlay_type == "config"


def test_check_file_signatures():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    data = [0x4D, 0x5A] + [0] * 100 + [0x50, 0x4B, 0x03, 0x04] + [0] * 100
    signatures = analyzer._check_file_signatures(data)

    assert len(signatures) >= 2
    assert any(s["type"] == "PE" for s in signatures)
    assert any(s["type"] == "ZIP" for s in signatures)


def test_check_file_signatures_pdf():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    data = [0x25, 0x50, 0x44, 0x46] + [0] * 100
    signatures = analyzer._check_file_signatures(data)

    assert any(s["type"] == "PDF" for s in signatures)


def test_check_file_signatures_png():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    data = [0x89, 0x50, 0x4E, 0x47] + [0] * 100
    signatures = analyzer._check_file_signatures(data)

    assert any(s["type"] == "PNG" for s in signatures)


def test_looks_encrypted_high_entropy():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    data = list(range(256)) * 2
    assert analyzer._looks_encrypted(data) is True


def test_looks_encrypted_unique_bytes():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    import random
    data = [random.randint(0, 255) for _ in range(256)]
    result = analyzer._looks_encrypted(data)


def test_looks_encrypted_false():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    data = [0x41] * 256
    assert analyzer._looks_encrypted(data) is False


def test_looks_encrypted_too_short():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    data = [0] * 100
    assert analyzer._looks_encrypted(data) is False


def test_extract_strings():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    data = [0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x00, 0x57, 0x6F, 0x72, 0x6C, 0x64]
    strings = analyzer._extract_strings(data, min_length=4)

    assert len(strings) > 0


def test_find_pattern_found():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    data = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05]
    pattern = [0x02, 0x03, 0x04]

    assert analyzer._find_pattern(data, pattern) is True


def test_find_pattern_not_found():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    data = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05]
    pattern = [0x06, 0x07]

    assert analyzer._find_pattern(data, pattern) is False


def test_find_pattern_at_end():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    data = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05]
    pattern = [0x04, 0x05]

    assert analyzer._find_pattern(data, pattern) is True


def test_find_all_patterns_multiple():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    data = [0x01, 0x02, 0x03, 0x01, 0x02, 0x03, 0x01, 0x02, 0x03]
    pattern = [0x01, 0x02]

    positions = analyzer._find_all_patterns(data, pattern)
    assert len(positions) == 3
    assert positions == [0, 3, 6]


def test_find_all_patterns_none():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    data = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05]
    pattern = [0x06, 0x07]

    positions = analyzer._find_all_patterns(data, pattern)
    assert len(positions) == 0


def test_check_suspicious_indicators():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    result = {
        "overlay_size": 2000000,
        "overlay_entropy": 7.8,
        "embedded_files": [{"type": "PE", "offset": 100}],
        "patterns_found": [{"name": "AutoIt"}],
        "extracted_strings": ["cmd.exe", "powershell.exe"],
        "suspicious_indicators": [],
    }
    analyzer._check_suspicious_indicators(result)

    assert len(result["suspicious_indicators"]) > 0


def test_check_large_overlay():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    result = {"overlay_size": 2000000}
    suspicious = []
    analyzer._check_large_overlay(result, suspicious)

    assert len(suspicious) == 1
    assert suspicious[0]["indicator"] == "Large overlay"
    assert suspicious[0]["severity"] == "medium"


def test_check_large_overlay_small():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    result = {"overlay_size": 1000}
    suspicious = []
    analyzer._check_large_overlay(result, suspicious)

    assert len(suspicious) == 0


def test_check_entropy_high():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    result = {"overlay_entropy": 7.8}
    suspicious = []
    analyzer._check_entropy(result, suspicious)

    assert len(suspicious) == 1
    assert suspicious[0]["indicator"] == "High entropy"
    assert suspicious[0]["severity"] == "high"


def test_check_entropy_low():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    result = {"overlay_entropy": 5.0}
    suspicious = []
    analyzer._check_entropy(result, suspicious)

    assert len(suspicious) == 0


def test_check_embedded_executables_pe():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    result = {"embedded_files": [{"type": "PE", "offset": 100}]}
    suspicious = []
    analyzer._check_embedded_executables(result, suspicious)

    assert len(suspicious) == 1
    assert suspicious[0]["indicator"] == "Embedded executable"
    assert suspicious[0]["severity"] == "high"


def test_check_embedded_executables_elf():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    result = {"embedded_files": [{"type": "ELF", "offset": 200}]}
    suspicious = []
    analyzer._check_embedded_executables(result, suspicious)

    assert len(suspicious) == 1


def test_check_embedded_executables_none():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    result = {"embedded_files": []}
    suspicious = []
    analyzer._check_embedded_executables(result, suspicious)

    assert len(suspicious) == 0


def test_check_autoit():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    result = {"patterns_found": [{"name": "AutoIt"}]}
    suspicious = []
    analyzer._check_autoit(result, suspicious)

    assert len(suspicious) == 1
    assert suspicious[0]["indicator"] == "AutoIt script"
    assert suspicious[0]["severity"] == "medium"


def test_check_autoit_none():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    result = {"patterns_found": [{"name": "NSIS"}]}
    suspicious = []
    analyzer._check_autoit(result, suspicious)

    assert len(suspicious) == 0


def test_check_suspicious_strings():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    result = {"extracted_strings": ["cmd.exe", "powershell.exe", "VirtualAlloc"]}
    suspicious = []
    analyzer._check_suspicious_strings(result, suspicious)

    assert len(suspicious) == 1
    assert suspicious[0]["indicator"] == "Suspicious strings"
    assert suspicious[0]["severity"] == "medium"


def test_check_suspicious_strings_case_insensitive():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    result = {"extracted_strings": ["CMD.EXE", "POWERSHELL.EXE"]}
    suspicious = []
    analyzer._check_suspicious_strings(result, suspicious)

    assert len(suspicious) == 1


def test_check_suspicious_strings_none():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    result = {"extracted_strings": ["normal string", "hello world"]}
    suspicious = []
    analyzer._check_suspicious_strings(result, suspicious)

    assert len(suspicious) == 0


def test_check_suspicious_strings_limit():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    result = {"extracted_strings": ["cmd.exe"] * 10}
    suspicious = []
    analyzer._check_suspicious_strings(result, suspicious)

    assert len(suspicious) == 1
    assert len(suspicious[0]["details"]) < 500


def test_default_result():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    result = analyzer._default_result()

    assert result["available"] is True
    assert result["has_overlay"] is False
    assert result["overlay_offset"] == 0
    assert result["overlay_size"] == 0
    assert result["overlay_entropy"] == 0.0
    assert result["overlay_hashes"] == {}
    assert result["patterns_found"] == []
    assert result["potential_type"] == "unknown"
    assert result["suspicious_indicators"] == []
    assert result["extracted_strings"] == []
    assert result["file_size"] == 0
    assert result["pe_end"] == 0
    assert result["embedded_files"] == []
    assert result["error"] == ""


def test_analyze_overlay_content_hash_exception():
    adapter = MagicMock()
    analyzer = OverlayAnalyzer(adapter)

    overlay_data = [300] * 100
    adapter.cmdj.return_value = overlay_data

    result = {
        "overlay_entropy": 0.0,
        "overlay_hashes": {},
        "patterns_found": [],
        "potential_type": "unknown",
        "extracted_strings": [],
        "embedded_files": [],
    }
    analyzer._analyze_overlay_content(result, 0, 1000)


def test_full_workflow_with_all_patterns():
    adapter = MagicMock()

    nsis_signature = [0xEF, 0xBE, 0xAD, 0xDE, 0x4E, 0x75, 0x6C, 0x6C, 0x73, 0x6F, 0x66, 0x74]
    pe_signature = [0x4D, 0x5A]
    xml_data = [0x3C, 0x3F, 0x78, 0x6D, 0x6C]
    overlay_data = nsis_signature + [0] * 100 + pe_signature + [0] * 100 + xml_data + [0x41, 0x42, 0x43] * 200

    adapter.cmdj.side_effect = [
        {"core": {"size": 15000}},
        [{"name": ".text", "paddr": 0, "size": 5000}],
        [],
        overlay_data,
    ]

    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()

    assert result["has_overlay"] is True
    assert len(result["patterns_found"]) > 0
    assert len(result["embedded_files"]) > 0
    assert len(result["suspicious_indicators"]) > 0


def test_analyze_with_certificate_extension():
    adapter = MagicMock()
    adapter.cmdj.side_effect = [
        {"core": {"size": 10000}},
        [{"name": ".text", "paddr": 0, "size": 3000}],
        [{"name": "SECURITY", "paddr": 5000, "size": 1000}],
        [0x41] * 100,
    ]

    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()

    assert result["has_overlay"] is True
    assert result["pe_end"] == 6000
    assert result["overlay_size"] == 4000
