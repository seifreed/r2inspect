"""Comprehensive tests for compiler_detector.py - 100% coverage target."""

from r2inspect.modules.compiler_detector import CompilerDetector
from r2inspect.modules.compiler_signatures import COMPILER_SIGNATURES


def test_compiler_detector_init():
    """Test CompilerDetector initialization."""
    detector = CompilerDetector(adapter=None)
    assert detector is not None
    assert detector.adapter is None
    assert detector.r2 is None
    assert detector.config is None


def test_compiler_detector_has_signatures():
    """Test CompilerDetector loads compiler signatures."""
    detector = CompilerDetector(adapter=None)
    assert detector.compiler_signatures is COMPILER_SIGNATURES
    assert isinstance(detector.compiler_signatures, dict)


def test_compiler_detector_has_msvc_versions():
    """Test CompilerDetector has MSVC version mapping."""
    detector = CompilerDetector(adapter=None)
    assert isinstance(detector.msvc_versions, dict)
    assert "MSVCR90.dll" in detector.msvc_versions
    assert "VCRUNTIME140.dll" in detector.msvc_versions


def test_compiler_detector_with_config():
    """Test CompilerDetector with config parameter."""
    detector = CompilerDetector(adapter=None, config={"some": "config"})
    assert detector.config == {"some": "config"}


def test_compiler_detector_edge_cases():
    """Test edge cases in compiler_detector."""
    detector = CompilerDetector(adapter=None, config=None)
    assert detector.config is None
    assert detector.adapter is None
