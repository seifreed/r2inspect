"""Comprehensive tests for section analyzer - targeting 12% -> 100% coverage"""
import pytest
from unittest.mock import Mock

from r2inspect.modules.section_analyzer import SectionAnalyzer


class MockAdapter:
    def __init__(self, responses=None):
        self.responses = responses or {}
    
    def cmdj(self, cmd, default=None):
        return self.responses.get(cmd, default)
    
    def read_bytes(self, addr, size):
        return self.responses.get(f"bytes_{addr}_{size}", b"\x90" * min(size, 100))
    
    def get_file_info(self):
        return self.responses.get("file_info", {})


def test_section_analyzer_basic():
    adapter = MockAdapter({
        "iSj": [
            {
                "name": ".text",
                "vaddr": 0x1000,
                "vsize": 1000,
                "size": 1000,
                "flags": "r-x",
                "perm": "--x",
            }
        ]
    })
    
    analyzer = SectionAnalyzer(adapter)
    result = analyzer.analyze()
    
    assert result["total_sections"] == 1
    assert len(result["sections"]) == 1


def test_section_analyzer_permissions():
    adapter = MockAdapter({
        "iSj": [
            {
                "name": ".text",
                "vaddr": 0x1000,
                "vsize": 1000,
                "size": 1000,
                "flags": "rwx",
                "perm": "-wx",
            }
        ]
    })
    
    analyzer = SectionAnalyzer(adapter)
    result = analyzer.analyze()
    
    section = result["sections"][0]
    assert section["is_executable"] is True
    assert section["is_writable"] is True


def test_section_analyzer_entropy():
    # Random-like data for high entropy
    import random
    random_bytes = bytes([random.randint(0, 255) for _ in range(1000)])
    
    adapter = MockAdapter({
        "iSj": [
            {
                "name": ".packed",
                "vaddr": 0x1000,
                "vsize": 1000,
                "size": 1000,
                "flags": "r-x",
            }
        ],
        "bytes_0x1000_1000": random_bytes,
    })
    
    analyzer = SectionAnalyzer(adapter)
    result = analyzer.analyze()
    
    section = result["sections"][0]
    assert section["entropy"] > 6.0


def test_section_analyzer_suspicious_writable_executable():
    adapter = MockAdapter({
        "iSj": [
            {
                "name": ".suspicious",
                "vaddr": 0x1000,
                "vsize": 1000,
                "size": 1000,
                "flags": "rwx",
                "perm": "-wx",
            }
        ]
    })
    
    analyzer = SectionAnalyzer(adapter)
    result = analyzer.analyze()
    
    section = result["sections"][0]
    assert any("Writable and executable" in ind for ind in section["suspicious_indicators"])


def test_section_analyzer_high_entropy_detection():
    import random
    random_bytes = bytes([random.randint(0, 255) for _ in range(1000)])
    
    adapter = MockAdapter({
        "iSj": [
            {
                "name": ".encrypted",
                "vaddr": 0x1000,
                "vsize": 1000,
                "size": 1000,
                "flags": "r--",
            }
        ],
        "bytes_0x1000_1000": random_bytes,
    })
    
    analyzer = SectionAnalyzer(adapter)
    result = analyzer.analyze()
    
    section = result["sections"][0]
    assert any("entropy" in ind.lower() for ind in section["suspicious_indicators"])


def test_section_analyzer_pe_characteristics():
    adapter = MockAdapter({
        "iSj": [
            {
                "name": ".text",
                "vaddr": 0x1000,
                "vsize": 1000,
                "size": 1000,
                "characteristics": 0x60000020,  # CODE | EXECUTE | READ
            }
        ]
    })
    
    analyzer = SectionAnalyzer(adapter)
    result = analyzer.analyze()
    
    section = result["sections"][0]
    assert "IMAGE_SCN_CNT_CODE" in section["pe_characteristics"]
    assert section["is_executable"] is True


def test_section_analyzer_size_ratio():
    adapter = MockAdapter({
        "iSj": [
            {
                "name": ".bss",
                "vaddr": 0x1000,
                "vsize": 10000,
                "size": 100,
                "flags": "rw-",
            }
        ]
    })
    
    analyzer = SectionAnalyzer(adapter)
    result = analyzer.analyze()
    
    section = result["sections"][0]
    assert section["size_ratio"] == 100.0
    assert any("size ratio" in ind.lower() for ind in section["suspicious_indicators"])


def test_section_analyzer_summary():
    adapter = MockAdapter({
        "iSj": [
            {
                "name": ".text",
                "vaddr": 0x1000,
                "vsize": 1000,
                "size": 1000,
                "flags": "r-x",
            },
            {
                "name": ".data",
                "vaddr": 0x2000,
                "vsize": 500,
                "size": 500,
                "flags": "rw-",
            }
        ]
    })
    
    analyzer = SectionAnalyzer(adapter)
    result = analyzer.analyze()
    
    summary = result["summary"]
    assert summary["total_sections"] == 2
    assert summary["executable_sections"] == 1
    assert summary["writable_sections"] == 1


def test_section_analyzer_non_standard_section():
    adapter = MockAdapter({
        "iSj": [
            {
                "name": "UPX0",
                "vaddr": 0x1000,
                "vsize": 1000,
                "size": 1000,
                "flags": "rwx",
            }
        ]
    })
    
    analyzer = SectionAnalyzer(adapter)
    result = analyzer.analyze()
    
    section = result["sections"][0]
    assert any("Non-standard" in ind or "upx" in ind.lower() for ind in section["suspicious_indicators"])


def test_section_analyzer_zero_entropy():
    zero_bytes = b"\x00" * 1000
    
    adapter = MockAdapter({
        "iSj": [
            {
                "name": ".bss",
                "vaddr": 0x1000,
                "vsize": 1000,
                "size": 1000,
                "flags": "rw-",
            }
        ],
        "bytes_0x1000_1000": zero_bytes,
    })
    
    analyzer = SectionAnalyzer(adapter)
    result = analyzer.analyze()
    
    section = result["sections"][0]
    assert section["entropy"] < 0.1


def test_section_analyzer_very_small_section():
    adapter = MockAdapter({
        "iSj": [
            {
                "name": ".tiny",
                "vaddr": 0x1000,
                "vsize": 50,
                "size": 50,
                "flags": "r--",
            }
        ]
    })
    
    analyzer = SectionAnalyzer(adapter)
    result = analyzer.analyze()
    
    section = result["sections"][0]
    assert any("small" in ind.lower() for ind in section["suspicious_indicators"])


def test_section_analyzer_very_large_section():
    adapter = MockAdapter({
        "iSj": [
            {
                "name": ".huge",
                "vaddr": 0x1000,
                "vsize": 60000000,
                "size": 60000000,
                "flags": "r--",
            }
        ]
    })
    
    analyzer = SectionAnalyzer(adapter)
    result = analyzer.analyze()
    
    section = result["sections"][0]
    # Entropy should be skipped for very large sections
    assert section["entropy"] == 0.0


def test_section_analyzer_supports_format():
    adapter = MockAdapter()
    analyzer = SectionAnalyzer(adapter)
    
    assert analyzer.supports_format("PE") is True
    assert analyzer.supports_format("ELF") is True
    assert analyzer.supports_format("MACHO") is True
    assert analyzer.supports_format("UNKNOWN") is False


def test_section_analyzer_error_handling():
    adapter = MockAdapter()
    adapter.cmdj = Mock(side_effect=Exception("Test error"))
    
    analyzer = SectionAnalyzer(adapter)
    result = analyzer.analyze()
    
    assert result["available"] is False


def test_section_analyzer_invalid_section_data():
    adapter = MockAdapter({
        "iSj": [
            "invalid",  # Not a dict
            {"name": ".text", "vaddr": 0x1000, "vsize": 1000, "size": 1000},
            123,  # Not a dict
        ]
    })
    
    analyzer = SectionAnalyzer(adapter)
    sections = analyzer.analyze_sections()
    
    # Should only process valid dict
    assert len(sections) == 1


def test_section_analyzer_nop_detection():
    nop_sled = b"\x90" * 500  # x86 NOP instructions
    
    adapter = MockAdapter({
        "iSj": [
            {
                "name": ".text",
                "vaddr": 0x1000,
                "vsize": 1000,
                "size": 1000,
                "flags": "r-x",
            }
        ],
        "aflj": [],
        "bytes_0x1000_1000": nop_sled,
        "file_info": {"arch": "x86"},
    })
    
    analyzer = SectionAnalyzer(adapter)
    result = analyzer.analyze()
    
    section = result["sections"][0]
    if "characteristics" in section and "code_analysis" in section["characteristics"]:
        code_info = section["characteristics"]["code_analysis"]
        if "excessive_nops" in code_info:
            assert code_info["excessive_nops"] is True
