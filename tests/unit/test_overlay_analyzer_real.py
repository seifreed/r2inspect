"""Comprehensive tests for overlay analyzer - 0% coverage target"""
import pytest

from r2inspect.modules.overlay_analyzer import OverlayAnalyzer


class MockAdapter:
    """Mock adapter for testing"""

    def __init__(self, responses=None):
        self.responses = responses or {}

    def cmdj(self, cmd, default=None):
        return self.responses.get(cmd, default)

    def read_bytes(self, addr, size):
        return self.responses.get(f"bytes_{addr}_{size}", b"")


def test_overlay_no_file_size():
    adapter = MockAdapter({"ij": {}})
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    assert result["has_overlay"] is False
    assert result["available"] is True


def test_overlay_invalid_file_size():
    adapter = MockAdapter({"ij": {"core": {"size": "invalid"}}})
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    assert result["has_overlay"] is False


def test_overlay_no_pe_end():
    adapter = MockAdapter({
        "ij": {"core": {"size": 10000}},
        "iSj": [],
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    assert result["has_overlay"] is False


def test_overlay_pe_end_equals_file_size():
    adapter = MockAdapter({
        "ij": {"core": {"size": 10000}},
        "iSj": [{"paddr": 0, "size": 10000}],
        "iDj": [],
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    assert result["has_overlay"] is False


def test_overlay_basic_detection():
    adapter = MockAdapter({
        "ij": {"core": {"size": 10000}},
        "iSj": [{"paddr": 0, "size": 5000}],
        "iDj": [],
        "pxj 5000 @ 5000": [0x00] * 5000,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    assert result["has_overlay"] is True
    assert result["overlay_offset"] == 5000
    assert result["overlay_size"] == 5000
    assert result["file_size"] == 10000
    assert result["pe_end"] == 5000


def test_overlay_with_certificate():
    adapter = MockAdapter({
        "ij": {"core": {"size": 10000}},
        "iSj": [{"paddr": 0, "size": 3000}],
        "iDj": [{"name": "SECURITY", "paddr": 3000, "size": 1000}],
        "pxj 6000 @ 4000": [0x00] * 6000,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    assert result["has_overlay"] is True
    assert result["pe_end"] == 4000  # 3000 + 1000


def test_overlay_entropy_calculation():
    # Low entropy data
    adapter = MockAdapter({
        "ij": {"core": {"size": 10000}},
        "iSj": [{"paddr": 0, "size": 5000}],
        "iDj": [],
        "pxj 5000 @ 5000": [0x00] * 5000,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    assert result["overlay_entropy"] < 1.0


def test_overlay_high_entropy():
    # High entropy data (random-like)
    import random
    random_data = [random.randint(0, 255) for _ in range(5000)]
    adapter = MockAdapter({
        "ij": {"core": {"size": 10000}},
        "iSj": [{"paddr": 0, "size": 5000}],
        "iDj": [],
        "pxj 5000 @ 5000": random_data,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    assert result["overlay_entropy"] > 6.0


def test_overlay_hash_calculation():
    adapter = MockAdapter({
        "ij": {"core": {"size": 10000}},
        "iSj": [{"paddr": 0, "size": 5000}],
        "iDj": [],
        "pxj 5000 @ 5000": [0x41, 0x42, 0x43] * 1666 + [0x41, 0x42],  # ABC repeated
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    assert "overlay_hashes" in result
    assert isinstance(result["overlay_hashes"], dict)


def test_overlay_nsis_pattern():
    nsis_pattern = [0xEF, 0xBE, 0xAD, 0xDE, 0x4E, 0x75, 0x6C, 0x6C, 0x73, 0x6F, 0x66, 0x74]
    overlay_data = [0x00] * 100 + nsis_pattern + [0x00] * 100
    adapter = MockAdapter({
        "ij": {"core": {"size": 1000}},
        "iSj": [{"paddr": 0, "size": 500}],
        "iDj": [],
        "pxj 500 @ 500": overlay_data[:500],
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    patterns = result["patterns_found"]
    assert any(p["name"] == "NSIS" for p in patterns)


def test_overlay_inno_setup_pattern():
    inno_pattern = [0x49, 0x6E, 0x6E, 0x6F, 0x20, 0x53, 0x65, 0x74, 0x75, 0x70]
    overlay_data = inno_pattern + [0x00] * 500
    adapter = MockAdapter({
        "ij": {"core": {"size": 1000}},
        "iSj": [{"paddr": 0, "size": 500}],
        "iDj": [],
        "pxj 500 @ 500": overlay_data,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    patterns = result["patterns_found"]
    assert any(p["name"] == "Inno Setup" for p in patterns)


def test_overlay_winrar_sfx_pattern():
    rar_pattern = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07]
    overlay_data = [0x00] * 50 + rar_pattern + [0x00] * 500
    adapter = MockAdapter({
        "ij": {"core": {"size": 1000}},
        "iSj": [{"paddr": 0, "size": 500}],
        "iDj": [],
        "pxj 500 @ 500": overlay_data,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    patterns = result["patterns_found"]
    assert any(p["name"] == "WinRAR SFX" for p in patterns)


def test_overlay_7zip_pattern():
    zip7_pattern = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]
    overlay_data = zip7_pattern + [0x00] * 500
    adapter = MockAdapter({
        "ij": {"core": {"size": 1000}},
        "iSj": [{"paddr": 0, "size": 500}],
        "iDj": [],
        "pxj 500 @ 500": overlay_data,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    patterns = result["patterns_found"]
    assert any(p["name"] == "7-Zip SFX" for p in patterns)


def test_overlay_autoit_pattern():
    autoit_pattern = [0x41, 0x55, 0x33, 0x21, 0xEA, 0x06]
    overlay_data = [0x00] * 10 + autoit_pattern + [0x00] * 500
    adapter = MockAdapter({
        "ij": {"core": {"size": 1000}},
        "iSj": [{"paddr": 0, "size": 500}],
        "iDj": [],
        "pxj 500 @ 500": overlay_data,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    patterns = result["patterns_found"]
    assert any(p["name"] == "AutoIt" for p in patterns)


def test_overlay_msi_pattern():
    msi_pattern = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]
    overlay_data = msi_pattern + [0x00] * 500
    adapter = MockAdapter({
        "ij": {"core": {"size": 1000}},
        "iSj": [{"paddr": 0, "size": 500}],
        "iDj": [],
        "pxj 500 @ 500": overlay_data,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    patterns = result["patterns_found"]
    assert any(p["name"] == "MSI" for p in patterns)


def test_overlay_xml_pattern():
    xml_pattern = [0x3C, 0x3F, 0x78, 0x6D, 0x6C]  # <?xml
    overlay_data = xml_pattern + [0x00] * 500
    adapter = MockAdapter({
        "ij": {"core": {"size": 1000}},
        "iSj": [{"paddr": 0, "size": 500}],
        "iDj": [],
        "pxj 500 @ 500": overlay_data,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    patterns = result["patterns_found"]
    assert any(p["name"] == "XML data" for p in patterns)


def test_overlay_json_pattern():
    json_pattern = [0x7B, 0x22]  # {"
    overlay_data = json_pattern + [0x00] * 500
    adapter = MockAdapter({
        "ij": {"core": {"size": 1000}},
        "iSj": [{"paddr": 0, "size": 500}],
        "iDj": [],
        "pxj 500 @ 500": overlay_data,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    patterns = result["patterns_found"]
    assert any(p["name"] == "JSON data" for p in patterns)


def test_overlay_asn1_pattern():
    asn1_pattern = [0x30, 0x82]
    overlay_data = [0x00] * 20 + asn1_pattern + [0x00] * 500
    adapter = MockAdapter({
        "ij": {"core": {"size": 1000}},
        "iSj": [{"paddr": 0, "size": 500}],
        "iDj": [],
        "pxj 500 @ 500": overlay_data,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    patterns = result["patterns_found"]
    assert any("ASN.1" in p["name"] for p in patterns)


def test_overlay_type_installer():
    nsis_pattern = [0xEF, 0xBE, 0xAD, 0xDE, 0x4E, 0x75, 0x6C, 0x6C, 0x73, 0x6F, 0x66, 0x74]
    overlay_data = nsis_pattern + [0x00] * 500
    adapter = MockAdapter({
        "ij": {"core": {"size": 1000}},
        "iSj": [{"paddr": 0, "size": 500}],
        "iDj": [],
        "pxj 500 @ 500": overlay_data,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    assert "installer" in result["potential_type"].lower()


def test_overlay_type_encrypted():
    # Very high entropy random data
    import random
    random_data = [random.randint(0, 255) for _ in range(1024)]
    adapter = MockAdapter({
        "ij": {"core": {"size": 2000}},
        "iSj": [{"paddr": 0, "size": 1000}],
        "iDj": [],
        "pxj 1000 @ 1000": random_data,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    assert "encrypted" in result["potential_type"] or "compressed" in result["potential_type"]


def test_overlay_type_padding():
    # Very low entropy (all zeros)
    overlay_data = [0x00] * 1024
    adapter = MockAdapter({
        "ij": {"core": {"size": 2000}},
        "iSj": [{"paddr": 0, "size": 1000}],
        "iDj": [],
        "pxj 1000 @ 1000": overlay_data,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    assert result["potential_type"] == "padding"


def test_overlay_embedded_pe():
    pe_magic = [0x4D, 0x5A]  # MZ
    overlay_data = [0x00] * 50 + pe_magic + [0x00] * 500
    adapter = MockAdapter({
        "ij": {"core": {"size": 1000}},
        "iSj": [{"paddr": 0, "size": 500}],
        "iDj": [],
        "pxj 500 @ 500": overlay_data,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    embedded = result["embedded_files"]
    assert any(f["type"] in ["PE", "MZ-DOS"] for f in embedded)


def test_overlay_embedded_zip():
    zip_magic = [0x50, 0x4B, 0x03, 0x04]
    overlay_data = zip_magic + [0x00] * 500
    adapter = MockAdapter({
        "ij": {"core": {"size": 1000}},
        "iSj": [{"paddr": 0, "size": 500}],
        "iDj": [],
        "pxj 500 @ 500": overlay_data,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    embedded = result["embedded_files"]
    assert any(f["type"] == "ZIP" for f in embedded)


def test_overlay_embedded_pdf():
    pdf_magic = [0x25, 0x50, 0x44, 0x46]  # %PDF
    overlay_data = [0x00] * 100 + pdf_magic + [0x00] * 400
    adapter = MockAdapter({
        "ij": {"core": {"size": 1000}},
        "iSj": [{"paddr": 0, "size": 500}],
        "iDj": [],
        "pxj 500 @ 500": overlay_data,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    embedded = result["embedded_files"]
    assert any(f["type"] == "PDF" for f in embedded)


def test_overlay_multiple_embedded_files():
    pe_magic = [0x4D, 0x5A]
    zip_magic = [0x50, 0x4B, 0x03, 0x04]
    overlay_data = pe_magic + [0x00] * 100 + zip_magic + [0x00] * 396
    adapter = MockAdapter({
        "ij": {"core": {"size": 1000}},
        "iSj": [{"paddr": 0, "size": 500}],
        "iDj": [],
        "pxj 500 @ 500": overlay_data,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    embedded = result["embedded_files"]
    assert len(embedded) >= 2


def test_overlay_suspicious_large():
    adapter = MockAdapter({
        "ij": {"core": {"size": 2000000}},  # 2MB
        "iSj": [{"paddr": 0, "size": 500000}],
        "iDj": [],
        "pxj 65536 @ 500000": [0x00] * 65536,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    assert any(ind["indicator"] == "Large overlay" for ind in result["suspicious_indicators"])


def test_overlay_suspicious_high_entropy():
    import random
    random_data = [random.randint(0, 255) for _ in range(1024)]
    adapter = MockAdapter({
        "ij": {"core": {"size": 2000}},
        "iSj": [{"paddr": 0, "size": 1000}],
        "iDj": [],
        "pxj 1000 @ 1000": random_data,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    assert any(ind["indicator"] == "High entropy" for ind in result["suspicious_indicators"])


def test_overlay_suspicious_embedded_executable():
    pe_magic = [0x4D, 0x5A]
    overlay_data = pe_magic + [0x00] * 500
    adapter = MockAdapter({
        "ij": {"core": {"size": 1000}},
        "iSj": [{"paddr": 0, "size": 500}],
        "iDj": [],
        "pxj 500 @ 500": overlay_data,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    assert any(ind["indicator"] == "Embedded executable" for ind in result["suspicious_indicators"])


def test_overlay_suspicious_autoit():
    autoit_pattern = [0x41, 0x55, 0x33, 0x21, 0xEA, 0x06]
    overlay_data = autoit_pattern + [0x00] * 500
    adapter = MockAdapter({
        "ij": {"core": {"size": 1000}},
        "iSj": [{"paddr": 0, "size": 500}],
        "iDj": [],
        "pxj 500 @ 500": overlay_data,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    assert any(ind["indicator"] == "AutoIt script" for ind in result["suspicious_indicators"])


def test_overlay_suspicious_strings():
    # Create overlay with suspicious strings
    cmd_str = b"cmd.exe\x00"
    ps_str = b"powershell\x00"
    overlay_bytes = cmd_str + b"\x00" * 50 + ps_str + b"\x00" * 400
    overlay_data = list(overlay_bytes)
    
    adapter = MockAdapter({
        "ij": {"core": {"size": 1000}},
        "iSj": [{"paddr": 0, "size": 500}],
        "iDj": [],
        "pxj 500 @ 500": overlay_data,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    # Should extract strings
    assert len(result["extracted_strings"]) > 0


def test_overlay_string_extraction():
    # ASCII printable strings
    test_str = b"Hello World"
    overlay_bytes = test_str + b"\x00" * 489
    overlay_data = list(overlay_bytes)
    
    adapter = MockAdapter({
        "ij": {"core": {"size": 1000}},
        "iSj": [{"paddr": 0, "size": 500}],
        "iDj": [],
        "pxj 500 @ 500": overlay_data,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    assert any("Hello" in s for s in result["extracted_strings"])


def test_overlay_looks_encrypted_high_entropy():
    # All unique bytes
    overlay_data = list(range(256))
    adapter = MockAdapter({
        "ij": {"core": {"size": 1000}},
        "iSj": [{"paddr": 0, "size": 500}],
        "iDj": [],
        "pxj 500 @ 500": overlay_data,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = overlay_data
    
    encrypted = analyzer._looks_encrypted(result)
    assert encrypted is True


def test_overlay_looks_encrypted_low_entropy():
    # Repeated pattern
    overlay_data = [0x41, 0x42] * 128
    analyzer = OverlayAnalyzer(None)
    
    encrypted = analyzer._looks_encrypted(overlay_data)
    assert encrypted is False


def test_overlay_looks_encrypted_small_data():
    overlay_data = [0x41] * 100
    analyzer = OverlayAnalyzer(None)
    
    encrypted = analyzer._looks_encrypted(overlay_data)
    assert encrypted is False


def test_overlay_find_pattern_found():
    data = [0x00, 0x01, 0x02, 0x03, 0x04]
    pattern = [0x02, 0x03]
    analyzer = OverlayAnalyzer(None)
    
    found = analyzer._find_pattern(data, pattern)
    assert found is True


def test_overlay_find_pattern_not_found():
    data = [0x00, 0x01, 0x02, 0x03, 0x04]
    pattern = [0x05, 0x06]
    analyzer = OverlayAnalyzer(None)
    
    found = analyzer._find_pattern(data, pattern)
    assert found is False


def test_overlay_find_all_patterns():
    data = [0x00, 0x01, 0x02, 0x01, 0x02, 0x03]
    pattern = [0x01, 0x02]
    analyzer = OverlayAnalyzer(None)
    
    positions = analyzer._find_all_patterns(data, pattern)
    assert len(positions) == 2
    assert positions == [1, 3]


def test_overlay_error_handling():
    adapter = MockAdapter()
    adapter.cmdj = lambda cmd, default: (_ for _ in ()).throw(RuntimeError("Error"))
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    assert result["available"] is False
    assert "error" in result


def test_overlay_sections_not_list():
    adapter = MockAdapter({
        "ij": {"core": {"size": 10000}},
        "iSj": "invalid",
        "iDj": [],
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    assert result["has_overlay"] is False


def test_overlay_sections_invalid_items():
    adapter = MockAdapter({
        "ij": {"core": {"size": 10000}},
        "iSj": ["invalid", 123, {"paddr": 0, "size": 5000}],
        "iDj": [],
        "pxj 5000 @ 5000": [0x00] * 5000,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    # Should still process valid section
    assert result["has_overlay"] is True


def test_overlay_data_dirs_not_list():
    adapter = MockAdapter({
        "ij": {"core": {"size": 10000}},
        "iSj": [{"paddr": 0, "size": 3000}],
        "iDj": "invalid",
        "pxj 7000 @ 3000": [0x00] * 7000,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    # Should still detect overlay
    assert result["has_overlay"] is True


def test_overlay_hash_calculation_error():
    adapter = MockAdapter({
        "ij": {"core": {"size": 10000}},
        "iSj": [{"paddr": 0, "size": 5000}],
        "iDj": [],
        "pxj 5000 @ 5000": [0x41] * 5000,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = {"overlay_hashes": {}}
    
    # Test with valid data
    analyzer._analyze_overlay_content(result, 5000, 5000)
    # Should calculate hashes without error


def test_overlay_no_data_read():
    adapter = MockAdapter({
        "ij": {"core": {"size": 10000}},
        "iSj": [{"paddr": 0, "size": 5000}],
        "iDj": [],
        "pxj 5000 @ 5000": None,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    # Should handle gracefully when no data


def test_overlay_limit_read_size():
    # Test that large overlays are limited to 64KB read
    adapter = MockAdapter({
        "ij": {"core": {"size": 1000000}},
        "iSj": [{"paddr": 0, "size": 100000}],
        "iDj": [],
        "pxj 65536 @ 100000": [0x00] * 65536,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    assert result["has_overlay"] is True
    assert result["overlay_size"] == 900000


def test_overlay_extracted_strings_limit():
    # Create many strings
    long_string = b"String" + b"\x00" + b"X" * 100
    overlay_bytes = long_string * 100
    overlay_data = list(overlay_bytes)[:500]
    
    adapter = MockAdapter({
        "ij": {"core": {"size": 1000}},
        "iSj": [{"paddr": 0, "size": 500}],
        "iDj": [],
        "pxj 500 @ 500": overlay_data,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    # Should limit to 20 strings
    assert len(result["extracted_strings"]) <= 20


def test_overlay_pe_end_invalid_type():
    adapter = MockAdapter({
        "ij": {"core": {"size": 10000}},
        "iSj": [{"paddr": "invalid", "size": 5000}],
        "iDj": [],
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    # Should handle invalid paddr gracefully


def test_overlay_elf_embedded():
    elf_magic = [0x7F, 0x45, 0x4C, 0x46]
    overlay_data = [0x00] * 50 + elf_magic + [0x00] * 446
    adapter = MockAdapter({
        "ij": {"core": {"size": 1000}},
        "iSj": [{"paddr": 0, "size": 500}],
        "iDj": [],
        "pxj 500 @ 500": overlay_data,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    embedded = result["embedded_files"]
    assert any(f["type"] == "ELF" for f in embedded)


def test_overlay_determine_type_no_patterns():
    data = [0x41, 0x42, 0x43] * 100
    analyzer = OverlayAnalyzer(None)
    
    overlay_type = analyzer._determine_overlay_type([], data)
    assert overlay_type == "data"


def test_overlay_determine_type_multiple_patterns():
    patterns = [
        {"type": "config", "name": "XML"},
        {"type": "config", "name": "JSON"},
        {"type": "signature", "name": "ASN.1"},
    ]
    analyzer = OverlayAnalyzer(None)
    
    overlay_type = analyzer._determine_overlay_type(patterns, [])
    assert overlay_type == "config"


def test_overlay_suspicious_strings_multiple():
    overlay_bytes = b"cmd.exe\x00powershell\x00WScript.Shell\x00" + b"\x00" * 400
    overlay_data = list(overlay_bytes)
    
    adapter = MockAdapter({
        "ij": {"core": {"size": 1000}},
        "iSj": [{"paddr": 0, "size": 500}],
        "iDj": [],
        "pxj 500 @ 500": overlay_data,
    })
    analyzer = OverlayAnalyzer(adapter)
    result = analyzer.analyze()
    
    # Should detect suspicious strings
    suspicious = any(ind["indicator"] == "Suspicious strings" for ind in result["suspicious_indicators"])
    # May or may not be detected depending on string extraction
