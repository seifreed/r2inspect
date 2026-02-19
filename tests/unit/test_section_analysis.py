from __future__ import annotations

from unittest.mock import Mock

from r2inspect.modules.section_analyzer import SectionAnalyzer


def test_section_analyzer_category():
    adapter = Mock()
    analyzer = SectionAnalyzer(adapter, None)
    
    assert analyzer.get_category() == "metadata"


def test_section_analyzer_description():
    adapter = Mock()
    analyzer = SectionAnalyzer(adapter, None)
    
    description = analyzer.get_description()
    assert isinstance(description, str)
    assert len(description) > 0


def test_section_analyzer_supports_pe():
    adapter = Mock()
    analyzer = SectionAnalyzer(adapter, None)
    
    assert analyzer.supports_format("PE") is True
    assert analyzer.supports_format("PE32") is True
    assert analyzer.supports_format("PE32+") is True


def test_section_analyzer_supports_elf():
    adapter = Mock()
    analyzer = SectionAnalyzer(adapter, None)
    
    assert analyzer.supports_format("ELF") is True


def test_section_analyzer_supports_macho():
    adapter = Mock()
    analyzer = SectionAnalyzer(adapter, None)
    
    assert analyzer.supports_format("MACH0") is True
    assert analyzer.supports_format("MACHO") is True


def test_section_analyzer_unsupported_format():
    adapter = Mock()
    analyzer = SectionAnalyzer(adapter, None)
    
    assert analyzer.supports_format("UNKNOWN") is False


def test_section_analysis_structure():
    adapter = Mock()
    adapter.r2 = Mock()
    adapter.cmdj = Mock(return_value=[
        {
            "name": ".text",
            "vaddr": 0x1000,
            "vsize": 1000,
            "size": 1000,
            "flags": "r-x",
            "perm": "r-x"
        }
    ])
    adapter.read_bytes = Mock(return_value=b"\x90" * 1000)
    adapter.get_file_info = Mock(return_value={"arch": "x86"})
    
    analyzer = SectionAnalyzer(adapter, None)
    result = analyzer.analyze()
    
    assert "sections" in result
    assert "summary" in result
    assert "total_sections" in result


def test_section_fields_present():
    adapter = Mock()
    adapter.r2 = Mock()
    adapter.cmdj = Mock(return_value=[
        {
            "name": ".text",
            "vaddr": 0x1000,
            "vsize": 1000,
            "size": 1000,
            "flags": "r-x",
            "perm": "r-x"
        }
    ])
    adapter.read_bytes = Mock(return_value=b"\x90" * 1000)
    adapter.get_file_info = Mock(return_value={"arch": "x86"})
    
    analyzer = SectionAnalyzer(adapter, None)
    result = analyzer.analyze()
    
    if result.get("sections"):
        section = result["sections"][0]
        assert "name" in section
        assert "entropy" in section
        assert "is_executable" in section
        assert "is_writable" in section
        assert "is_readable" in section


def test_section_summary_fields():
    adapter = Mock()
    adapter.r2 = Mock()
    adapter.cmdj = Mock(return_value=[
        {
            "name": ".text",
            "vaddr": 0x1000,
            "vsize": 1000,
            "size": 1000,
            "flags": "r-x",
            "perm": "r-x"
        }
    ])
    adapter.read_bytes = Mock(return_value=b"\x00" * 1000)
    adapter.get_file_info = Mock(return_value={"arch": "x86"})
    
    analyzer = SectionAnalyzer(adapter, None)
    summary = analyzer.get_section_summary()
    
    assert "total_sections" in summary
    assert "executable_sections" in summary
    assert "writable_sections" in summary
    assert "suspicious_sections" in summary
    assert "high_entropy_sections" in summary
    assert "avg_entropy" in summary


def test_section_empty_list():
    adapter = Mock()
    adapter.r2 = Mock()
    adapter.cmdj = Mock(return_value=[])
    
    analyzer = SectionAnalyzer(adapter, None)
    sections = analyzer.analyze_sections()
    
    assert sections == []


def test_section_decode_pe_characteristics():
    adapter = Mock()
    analyzer = SectionAnalyzer(adapter, None)
    
    flags = analyzer._decode_pe_characteristics(0x20000020)
    
    assert "IMAGE_SCN_CNT_CODE" in flags
    assert "IMAGE_SCN_MEM_EXECUTE" in flags


def test_section_calculate_size_ratio():
    adapter = Mock()
    analyzer = SectionAnalyzer(adapter, None)
    
    analysis = {"virtual_size": 5000, "raw_size": 1000}
    ratio = analyzer._calculate_size_ratio(analysis)
    
    assert ratio == 5.0


def test_section_calculate_size_ratio_zero():
    adapter = Mock()
    analyzer = SectionAnalyzer(adapter, None)
    
    analysis = {"virtual_size": 1000, "raw_size": 0}
    ratio = analyzer._calculate_size_ratio(analysis)
    
    assert ratio == 0.0


def test_section_standard_sections():
    adapter = Mock()
    analyzer = SectionAnalyzer(adapter, None)
    
    assert ".text" in analyzer.standard_sections
    assert ".data" in analyzer.standard_sections
    assert ".rdata" in analyzer.standard_sections


def test_section_entropy_indicator_high():
    adapter = Mock()
    analyzer = SectionAnalyzer(adapter, None)
    
    indicators = analyzer._check_entropy_indicators(7.6)
    
    assert len(indicators) > 0
    assert any("High entropy" in ind for ind in indicators)


def test_section_entropy_indicator_moderate():
    adapter = Mock()
    analyzer = SectionAnalyzer(adapter, None)
    
    indicators = analyzer._check_entropy_indicators(7.2)
    
    assert len(indicators) > 0
    assert any("entropy" in ind.lower() for ind in indicators)


def test_section_permission_indicators_wx():
    adapter = Mock()
    analyzer = SectionAnalyzer(adapter, None)
    
    analysis = {"is_writable": True, "is_executable": True, "entropy": 5.0}
    indicators = analyzer._check_permission_indicators(analysis)
    
    assert any("Writable and executable" in ind for ind in indicators)


def test_section_size_indicators_large_ratio():
    adapter = Mock()
    analyzer = SectionAnalyzer(adapter, None)
    
    indicators = analyzer._check_size_indicators(10000, 1000)
    
    assert len(indicators) > 0


def test_section_size_indicators_small():
    adapter = Mock()
    analyzer = SectionAnalyzer(adapter, None)
    
    indicators = analyzer._check_size_indicators(50, 50)
    
    assert any("Very small section" in ind for ind in indicators)
