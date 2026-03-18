"""Comprehensive tests for elf_analyzer.py - 100% coverage target."""

from r2inspect.modules.elf_analyzer import ELFAnalyzer


def test_elf_analyzer_init():
    """Test ElfAnalyzer initialization."""
    analyzer = ELFAnalyzer(adapter=None)
    assert analyzer is not None


def test_elf_analyzer_category():
    """Test ELFAnalyzer category."""
    analyzer = ELFAnalyzer(adapter=None)
    assert analyzer.get_category() == "format"


def test_elf_analyzer_description():
    """Test ELFAnalyzer description."""
    analyzer = ELFAnalyzer(adapter=None)
    desc = analyzer.get_description()
    assert "ELF" in desc


def test_elf_analyzer_supports_format():
    """Test ELFAnalyzer format support."""
    analyzer = ELFAnalyzer(adapter=None)
    assert analyzer.supports_format("ELF") is True
    assert analyzer.supports_format("elf") is True
    assert analyzer.supports_format("ELF32") is True
    assert analyzer.supports_format("ELF64") is True
    assert analyzer.supports_format("PE") is False
    assert analyzer.supports_format("MACHO") is False


def test_elf_analyzer_edge_cases():
    """Test edge cases in elf_analyzer."""
    analyzer = ELFAnalyzer(adapter=None, config=None)
    assert analyzer.supports_format("") is False
    assert analyzer.supports_format("elf32") is True
