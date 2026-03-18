"""Comprehensive tests for ccbhash_analyzer.py - 100% coverage target."""

from r2inspect.modules.ccbhash_analyzer import (
    CCBHashAnalyzer,
    NO_FUNCTIONS_FOUND,
    NO_FUNCTIONS_ANALYZED,
)


def test_ccbhash_analyzer_init():
    """Test CcbhashAnalyzer initialization."""
    analyzer = CCBHashAnalyzer(adapter=None, filepath="/tmp/test.bin")
    assert analyzer is not None


def test_ccbhash_analyzer_constants():
    """Test module-level constants."""
    assert NO_FUNCTIONS_FOUND == "No functions found in binary"
    assert NO_FUNCTIONS_ANALYZED == "No functions could be analyzed for CCBHash"


def test_ccbhash_analyzer_check_library_availability():
    """Test _check_library_availability returns tuple."""
    analyzer = CCBHashAnalyzer(adapter=None, filepath="/tmp/test.bin")
    available, msg = analyzer._check_library_availability()
    assert isinstance(available, bool)
    assert msg is None or isinstance(msg, str)


def test_ccbhash_analyzer_attributes():
    """Test analyzer has expected attributes."""
    analyzer = CCBHashAnalyzer(adapter=None, filepath="/tmp/test.bin")
    assert hasattr(analyzer, "adapter")
    assert hasattr(analyzer, "filepath")


def test_ccbhash_analyzer_empty_filepath_raises():
    """Test that empty filepath raises ValueError."""
    import pytest

    with pytest.raises(ValueError, match="filepath cannot be empty"):
        CCBHashAnalyzer(adapter=None, filepath="")
