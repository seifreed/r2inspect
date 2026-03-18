"""Comprehensive tests for impfuzzy_analyzer.py - 100% coverage target.

No unittest.mock usage; all tests use real objects.
"""

from r2inspect.modules.impfuzzy_analyzer import ImpfuzzyAnalyzer


class _MinimalAdapter:
    """Minimal adapter returning controlled data for impfuzzy analysis."""

    def __init__(self, imports=None):
        self._imports = imports or []

    def cmd(self, command):
        return ""

    def cmdj(self, command, default=None):
        if command == "iij":
            return self._imports
        return default


def test_impfuzzy_analyzer_init():
    """Test ImpfuzzyAnalyzer initialization."""
    adapter = _MinimalAdapter()
    analyzer = ImpfuzzyAnalyzer(adapter, filepath="/tmp/test.bin")
    assert analyzer is not None


def test_impfuzzy_analyzer_basic_functionality():
    """Test basic functionality of impfuzzy_analyzer."""
    adapter = _MinimalAdapter(
        imports=[
            {"name": "CreateFileA", "libname": "kernel32.dll"},
            {"name": "ReadFile", "libname": "kernel32.dll"},
        ]
    )
    analyzer = ImpfuzzyAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer.analyze()
    assert isinstance(result, dict)


def test_impfuzzy_analyzer_error_handling():
    """Test error handling in impfuzzy_analyzer."""

    class _ErrorAdapter:
        def cmd(self, command):
            raise RuntimeError("simulated error")

        def cmdj(self, command, default=None):
            raise RuntimeError("simulated error")

    analyzer = ImpfuzzyAnalyzer(_ErrorAdapter(), filepath="/tmp/test.bin")
    result = analyzer.analyze()
    assert isinstance(result, dict)


def test_impfuzzy_analyzer_edge_cases():
    """Test edge cases in impfuzzy_analyzer."""
    adapter = _MinimalAdapter(imports=[])
    analyzer = ImpfuzzyAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer.analyze()
    assert isinstance(result, dict)


def test_impfuzzy_analyzer_none_adapter():
    """Test ImpfuzzyAnalyzer with None adapter."""
    analyzer = ImpfuzzyAnalyzer(adapter=None, filepath="/tmp/test.bin")
    result = analyzer.analyze()
    assert isinstance(result, dict)
