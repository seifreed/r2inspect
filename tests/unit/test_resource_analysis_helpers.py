from unittest.mock import MagicMock
import pytest

from r2inspect.modules.resource_analysis import run_resource_analysis


def test_run_resource_analysis_no_resources():
    analyzer = MagicMock()
    analyzer._init_result_structure.return_value = {
        "has_resources": False,
        "resource_directory": None,
        "total_resources": 0,
    }
    analyzer._get_resource_directory.return_value = None
    
    logger = MagicMock()
    
    result = run_resource_analysis(analyzer, logger)
    
    assert result["available"] is True
    assert result["has_resources"] is False
    analyzer._get_resource_directory.assert_called_once()


def test_run_resource_analysis_with_resources():
    analyzer = MagicMock()
    analyzer._init_result_structure.return_value = {
        "has_resources": False,
        "resource_directory": None,
        "total_resources": 0,
        "resources": [],
        "resource_types": [],
    }
    analyzer._get_resource_directory.return_value = {"offset": 0x1000}
    analyzer._parse_resources.return_value = [
        {"type": "icon", "size": 100},
        {"type": "version", "size": 200},
    ]
    
    logger = MagicMock()
    
    result = run_resource_analysis(analyzer, logger)
    
    assert result["available"] is True
    assert result["has_resources"] is True
    assert result["total_resources"] == 2
    analyzer._analyze_resource_types.assert_called_once()
    analyzer._extract_version_info.assert_called_once()
    analyzer._extract_manifest.assert_called_once()


def test_run_resource_analysis_empty_resource_list():
    analyzer = MagicMock()
    analyzer._init_result_structure.return_value = {
        "has_resources": False,
        "resource_directory": None,
        "total_resources": 0,
        "resources": [],
    }
    analyzer._get_resource_directory.return_value = {"offset": 0x1000}
    analyzer._parse_resources.return_value = []
    
    logger = MagicMock()
    
    result = run_resource_analysis(analyzer, logger)
    
    assert result["available"] is True
    assert result["has_resources"] is True
    assert result["total_resources"] == 0


def test_run_resource_analysis_exception():
    analyzer = MagicMock()
    analyzer._init_result_structure.side_effect = Exception("Init failed")
    
    logger = MagicMock()
    
    with pytest.raises(Exception) as exc:
        run_resource_analysis(analyzer, logger)
    
    assert "Init failed" in str(exc.value)


def test_run_resource_analysis_parse_exception():
    analyzer = MagicMock()
    analyzer._init_result_structure.return_value = {
        "has_resources": False,
        "resource_directory": None,
        "total_resources": 0,
        "resources": [],
    }
    analyzer._get_resource_directory.return_value = {"offset": 0x1000}
    analyzer._parse_resources.side_effect = Exception("Parse error")
    
    logger = MagicMock()
    
    with pytest.raises(Exception):
        run_resource_analysis(analyzer, logger)
