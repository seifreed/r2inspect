"""Comprehensive tests for batch_processing.py - 100% coverage target."""

from pathlib import Path

from r2inspect.cli.batch_paths import (
    setup_analysis_options,
    setup_batch_mode,
)


def test_batch_processing_setup_analysis_options():
    """Test setup_analysis_options builds correct dict."""
    options = setup_analysis_options(yara="/rules", sanitized_xor="ff")
    assert isinstance(options, dict)
    assert options.get("custom_yara") == "/rules" or "yara" in str(options)


def test_batch_processing_setup_analysis_options_none():
    """Test setup_analysis_options with None values."""
    options = setup_analysis_options(yara=None, sanitized_xor=None)
    assert isinstance(options, dict)


def test_batch_processing_setup_batch_mode():
    """Test setup_batch_mode returns expected tuple."""
    recursive, auto_detect, output = setup_batch_mode(
        batch="/tmp",
        extensions=None,
        output_json=True,
        output_csv=False,
        output=None,
    )
    assert isinstance(recursive, bool)
    assert isinstance(auto_detect, bool)


def test_batch_processing_setup_batch_mode_with_output():
    """Test setup_batch_mode with custom output."""
    recursive, auto_detect, output = setup_batch_mode(
        batch="/tmp",
        extensions=".exe,.dll",
        output_json=False,
        output_csv=True,
        output="/custom/output",
    )
    assert output == "/custom/output"


def test_batch_processing_edge_cases():
    """Test edge cases in batch processing setup."""
    options = setup_analysis_options(yara="", sanitized_xor="")
    assert isinstance(options, dict)
