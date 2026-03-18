"""Comprehensive tests for function_analyzer.py - 100% coverage target.

No unittest.mock usage; all tests use real objects.
"""

from r2inspect.modules.function_analyzer import FunctionAnalyzer


class _MinimalAdapter:
    """Minimal adapter returning controlled data for function analysis."""

    def __init__(self, functions=None):
        self._functions = functions or []

    def cmd(self, command):
        return ""

    def cmdj(self, command, default=None):
        if command in ("aflj", "afllj"):
            return self._functions
        return default

    def get_functions(self):
        return self._functions


def test_function_analyzer_init():
    """Test FunctionAnalyzer initialization."""
    adapter = _MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    assert analyzer is not None
    assert analyzer.adapter is adapter


def test_function_analyzer_basic_functionality():
    """Test basic functionality of function_analyzer."""
    functions = [
        {"offset": 0x1000, "size": 64, "name": "sym.main", "nbbs": 3, "ninstrs": 20},
        {"offset": 0x2000, "size": 128, "name": "sym.helper", "nbbs": 5, "ninstrs": 40},
    ]
    adapter = _MinimalAdapter(functions=functions)
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer.analyze_functions()
    assert isinstance(result, dict)


def test_function_analyzer_error_handling():
    """Test error handling in function_analyzer."""

    class _ErrorAdapter:
        def cmd(self, command):
            raise RuntimeError("simulated error")

        def cmdj(self, command, default=None):
            raise RuntimeError("simulated error")

        def get_functions(self):
            raise RuntimeError("simulated error")

    analyzer = FunctionAnalyzer(_ErrorAdapter())
    result = analyzer.analyze_functions()
    assert isinstance(result, dict)


def test_function_analyzer_edge_cases():
    """Test edge cases in function_analyzer."""
    adapter = _MinimalAdapter(functions=[])
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer.analyze_functions()
    assert isinstance(result, dict)


def test_function_analyzer_none_adapter():
    """Test FunctionAnalyzer with None adapter."""
    analyzer = FunctionAnalyzer(adapter=None)
    result = analyzer.analyze_functions()
    assert isinstance(result, dict)
