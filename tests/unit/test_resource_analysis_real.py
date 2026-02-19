#!/usr/bin/env python3
"""Tests for modules/resource_analysis.py"""

from __future__ import annotations

from unittest.mock import Mock

from r2inspect.modules import resource_analysis


def test_run_resource_analysis_basic():
    analyzer = Mock()
    analyzer._init_result_structure.return_value = {
        "has_resources": False,
        "resource_directory": None,
        "total_resources": 0,
        "total_size": 0,
        "resource_types": [],
        "resources": [],
        "version_info": None,
        "manifest": None,
        "icons": [],
        "strings": [],
        "suspicious_resources": [],
        "statistics": {},
    }
    analyzer._get_resource_directory.return_value = None
    logger = Mock()
    
    result = resource_analysis.run_resource_analysis(analyzer, logger)
    
    assert result["available"] is True
    assert result["has_resources"] is False


def test_run_resource_analysis_with_resources():
    analyzer = Mock()
    analyzer._init_result_structure.return_value = {
        "has_resources": False,
        "resource_directory": None,
        "total_resources": 0,
        "total_size": 0,
        "resource_types": [],
        "resources": [],
        "version_info": None,
        "manifest": None,
        "icons": [],
        "strings": [],
        "suspicious_resources": [],
        "statistics": {},
    }
    analyzer._get_resource_directory.return_value = {"rva": 0x1000}
    analyzer._parse_resources.return_value = [
        {"type": "RT_ICON", "size": 1024},
        {"type": "RT_VERSION", "size": 512},
    ]
    logger = Mock()
    
    result = resource_analysis.run_resource_analysis(analyzer, logger)
    
    assert result["available"] is True
    assert result["has_resources"] is True
    assert result["resource_directory"] == {"rva": 0x1000}
    assert result["total_resources"] == 2
    analyzer._analyze_resource_types.assert_called_once()
    analyzer._extract_version_info.assert_called_once()
    analyzer._extract_manifest.assert_called_once()
    analyzer._extract_icons.assert_called_once()
    analyzer._extract_strings.assert_called_once()
    analyzer._calculate_statistics.assert_called_once()
    analyzer._check_suspicious_resources.assert_called_once()


def test_run_resource_analysis_no_resources():
    analyzer = Mock()
    analyzer._init_result_structure.return_value = {
        "has_resources": False,
        "resource_directory": None,
        "total_resources": 0,
        "total_size": 0,
        "resource_types": [],
        "resources": [],
        "version_info": None,
        "manifest": None,
        "icons": [],
        "strings": [],
        "suspicious_resources": [],
        "statistics": {},
    }
    analyzer._get_resource_directory.return_value = {"rva": 0x1000}
    analyzer._parse_resources.return_value = []
    logger = Mock()
    
    result = resource_analysis.run_resource_analysis(analyzer, logger)
    
    assert result["available"] is True
    assert result["has_resources"] is True
    assert result["total_resources"] == 0


def test_run_resource_analysis_none_resources():
    analyzer = Mock()
    analyzer._init_result_structure.return_value = {
        "has_resources": False,
        "resource_directory": None,
        "total_resources": 0,
        "total_size": 0,
        "resource_types": [],
        "resources": [],
        "version_info": None,
        "manifest": None,
        "icons": [],
        "strings": [],
        "suspicious_resources": [],
        "statistics": {},
    }
    analyzer._get_resource_directory.return_value = {"rva": 0x1000}
    analyzer._parse_resources.return_value = None
    logger = Mock()
    
    result = resource_analysis.run_resource_analysis(analyzer, logger)
    
    assert result["available"] is True
    assert result["has_resources"] is True
    assert result["total_resources"] == 0


def test_run_resource_analysis_exception():
    analyzer = Mock()
    analyzer._init_result_structure.return_value = {
        "has_resources": False,
        "resource_directory": None,
        "total_resources": 0,
        "total_size": 0,
        "resource_types": [],
        "resources": [],
        "version_info": None,
        "manifest": None,
        "icons": [],
        "strings": [],
        "suspicious_resources": [],
        "statistics": {},
    }
    analyzer._get_resource_directory.side_effect = Exception("Test error")
    logger = Mock()
    
    result = resource_analysis.run_resource_analysis(analyzer, logger)
    
    assert result["available"] is False
    assert result["has_resources"] is False
    assert "error" in result
    assert result["error"] == "Test error"
    logger.error.assert_called_once()
