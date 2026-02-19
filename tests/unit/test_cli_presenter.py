#!/usr/bin/env python3
"""Comprehensive tests for r2inspect/cli/presenter.py - targeting 100% coverage."""

import pytest


def test_normalize_display_results_with_dict():
    """Test normalize_display_results with a valid dict."""
    from r2inspect.cli.presenter import normalize_display_results
    
    results = {
        "section1": {"data": "value1"},
        "section2": {"data": "value2"},
        "section3": {"data": "value3"}
    }
    
    normalized = normalize_display_results(results)
    
    # Should preserve all keys
    assert "section1" in normalized
    assert "section2" in normalized
    assert "section3" in normalized
    
    # Should add __present__ key with all section names
    assert "__present__" in normalized
    assert isinstance(normalized["__present__"], set)
    assert "section1" in normalized["__present__"]
    assert "section2" in normalized["__present__"]
    assert "section3" in normalized["__present__"]


def test_normalize_display_results_with_none():
    """Test normalize_display_results with None input."""
    from r2inspect.cli.presenter import normalize_display_results
    
    normalized = normalize_display_results(None)
    
    # Should return dict with empty __present__ set
    assert isinstance(normalized, dict)
    assert "__present__" in normalized
    assert isinstance(normalized["__present__"], set)
    assert len(normalized["__present__"]) == 0


def test_normalize_display_results_with_empty_dict():
    """Test normalize_display_results with empty dict."""
    from r2inspect.cli.presenter import normalize_display_results
    
    results = {}
    normalized = normalize_display_results(results)
    
    assert "__present__" in normalized
    assert isinstance(normalized["__present__"], set)
    assert len(normalized["__present__"]) == 0


def test_normalize_display_results_preserves_existing_present():
    """Test normalize_display_results when __present__ already exists."""
    from r2inspect.cli.presenter import normalize_display_results
    
    existing_present = {"existing1", "existing2"}
    results = {
        "section1": {"data": "value"},
        "__present__": existing_present
    }
    
    normalized = normalize_display_results(results)
    
    # Should preserve the existing __present__
    assert normalized["__present__"] is existing_present
    assert "existing1" in normalized["__present__"]


def test_normalize_display_results_does_not_modify_original():
    """Test normalize_display_results doesn't modify the original dict."""
    from r2inspect.cli.presenter import normalize_display_results
    
    original = {
        "section1": {"data": "value1"},
        "section2": {"data": "value2"}
    }
    original_keys = set(original.keys())
    
    normalized = normalize_display_results(original)
    
    # Original should not be modified
    assert set(original.keys()) == original_keys
    assert "__present__" not in original


def test_get_section_key_present_in_set():
    """Test get_section when key is in __present__ set."""
    from r2inspect.cli.presenter import get_section
    
    results = {
        "section1": {"data": "value1"},
        "__present__": {"section1", "section2"}
    }
    
    value, present = get_section(results, "section1", default=None)
    
    assert value == {"data": "value1"}
    assert present is True


def test_get_section_key_not_in_set():
    """Test get_section when key is not in __present__ set."""
    from r2inspect.cli.presenter import get_section
    
    results = {
        "section1": {"data": "value1"},
        "__present__": {"section1"}  # section2 not in set
    }
    
    default = {"default": "data"}
    value, present = get_section(results, "section2", default=default)
    
    assert value == default
    assert present is False


def test_get_section_no_present_key_exists():
    """Test get_section when key exists but no __present__ set."""
    from r2inspect.cli.presenter import get_section
    
    results = {
        "section1": {"data": "value1"},
        # No __present__ key
    }
    
    value, present = get_section(results, "section1", default=None)
    
    assert value == {"data": "value1"}
    assert present is True


def test_get_section_no_present_key_missing():
    """Test get_section when key doesn't exist and no __present__ set."""
    from r2inspect.cli.presenter import get_section
    
    results = {
        "section1": {"data": "value1"},
        # No __present__ key
    }
    
    default = {"default": "data"}
    value, present = get_section(results, "section2", default=default)
    
    assert value == default
    assert present is False


def test_get_section_present_not_a_set():
    """Test get_section when __present__ exists but is not a set."""
    from r2inspect.cli.presenter import get_section
    
    results = {
        "section1": {"data": "value1"},
        "__present__": "not_a_set"  # Invalid type
    }
    
    # Should fall back to checking key in results
    value, present = get_section(results, "section1", default=None)
    
    assert value == {"data": "value1"}
    assert present is True


def test_get_section_present_not_a_set_key_missing():
    """Test get_section when __present__ is not a set and key is missing."""
    from r2inspect.cli.presenter import get_section
    
    results = {
        "section1": {"data": "value1"},
        "__present__": ["not", "a", "set"]  # Invalid type
    }
    
    default = {"default": "data"}
    value, present = get_section(results, "section2", default=default)
    
    assert value == default
    assert present is False


def test_get_section_with_none_value():
    """Test get_section when value in results is None."""
    from r2inspect.cli.presenter import get_section
    
    results = {
        "section1": None,
        "__present__": {"section1"}
    }
    
    default = {"default": "data"}
    value, present = get_section(results, "section1", default=default)
    
    # Should return None (actual value), not default
    assert value is None
    assert present is True


def test_get_section_with_none_default():
    """Test get_section with None as default value."""
    from r2inspect.cli.presenter import get_section
    
    results = {
        "section1": {"data": "value1"},
        "__present__": {"section1"}
    }
    
    value, present = get_section(results, "missing_section", default=None)
    
    assert value is None
    assert present is False


def test_get_section_default_types():
    """Test get_section with various default types."""
    from r2inspect.cli.presenter import get_section
    
    results = {
        "__present__": set()
    }
    
    # Dict default
    value1, present1 = get_section(results, "key1", default={})
    assert value1 == {}
    assert present1 is False
    
    # List default
    value2, present2 = get_section(results, "key2", default=[])
    assert value2 == []
    assert present2 is False
    
    # String default
    value3, present3 = get_section(results, "key3", default="default")
    assert value3 == "default"
    assert present3 is False
    
    # Int default
    value4, present4 = get_section(results, "key4", default=0)
    assert value4 == 0
    assert present4 is False


def test_get_section_complex_data():
    """Test get_section with complex nested data structures."""
    from r2inspect.cli.presenter import get_section
    
    complex_data = {
        "nested": {
            "level1": {
                "level2": {
                    "value": 123
                }
            }
        }
    }
    
    results = {
        "section1": complex_data,
        "__present__": {"section1"}
    }
    
    value, present = get_section(results, "section1", default=None)
    
    assert value == complex_data
    assert present is True
    assert value["nested"]["level1"]["level2"]["value"] == 123


def test_normalize_and_get_section_integration():
    """Test integration of normalize_display_results and get_section."""
    from r2inspect.cli.presenter import normalize_display_results, get_section
    
    original_results = {
        "section1": {"data": "value1"},
        "section2": {"data": "value2"}
    }
    
    # Normalize
    normalized = normalize_display_results(original_results)
    
    # Get existing section
    value1, present1 = get_section(normalized, "section1", default=None)
    assert value1 == {"data": "value1"}
    assert present1 is True
    
    # Get missing section
    value2, present2 = get_section(normalized, "section3", default={"default": "value"})
    assert value2 == {"default": "value"}
    assert present2 is False


def test_get_section_empty_string_key():
    """Test get_section with empty string as key."""
    from r2inspect.cli.presenter import get_section
    
    results = {
        "": {"data": "empty_key"},
        "__present__": {""}
    }
    
    value, present = get_section(results, "", default=None)
    
    assert value == {"data": "empty_key"}
    assert present is True


def test_get_section_special_characters_in_key():
    """Test get_section with special characters in key names."""
    from r2inspect.cli.presenter import get_section
    
    results = {
        "section.with.dots": {"data": "value"},
        "section-with-dashes": {"data": "value2"},
        "__present__": {"section.with.dots", "section-with-dashes"}
    }
    
    value1, present1 = get_section(results, "section.with.dots", default=None)
    assert present1 is True
    
    value2, present2 = get_section(results, "section-with-dashes", default=None)
    assert present2 is True
