from __future__ import annotations

from r2inspect.modules.tlsh_analyzer import TLSHAnalyzer


def test_tlsh_similarity_levels():
    assert TLSHAnalyzer.get_similarity_level(None) == "Unknown"
    assert TLSHAnalyzer.get_similarity_level(0) == "Identical"
    assert TLSHAnalyzer.get_similarity_level(10) == "Very Similar"
    assert TLSHAnalyzer.get_similarity_level(40) == "Similar"
    assert TLSHAnalyzer.get_similarity_level(80) == "Somewhat Similar"
    assert TLSHAnalyzer.get_similarity_level(150) == "Different"
    assert TLSHAnalyzer.get_similarity_level(500) == "Very Different"


def test_tlsh_compare_empty_returns_none():
    assert TLSHAnalyzer.compare_hashes("", "") is None
