#!/usr/bin/env python3
"""Comprehensive tests for inspector_helpers.py execution mixin."""

from unittest.mock import Mock, MagicMock
from r2inspect.core.inspector_helpers import InspectorExecutionMixin


class MockInspector(InspectorExecutionMixin):
    """Mock inspector for testing the mixin."""
    
    def __init__(self):
        self.adapter = Mock()
        self.config = Mock()
        self.filename = "test.bin"
        self.registry = Mock()
        self._result_aggregator = Mock()


def test_execute_with_progress_returns_dict():
    inspector = MockInspector()
    pipeline = Mock()
    pipeline.execute_with_progress.return_value = {"result": "data"}
    
    result = inspector._execute_with_progress(pipeline, {}, lambda x: None)
    assert result == {"result": "data"}
    pipeline.execute_with_progress.assert_called_once()


def test_execute_with_progress_converts_non_dict():
    inspector = MockInspector()
    pipeline = Mock()
    pipeline.execute_with_progress.return_value = "not_a_dict"
    
    result = inspector._execute_with_progress(pipeline, {}, lambda x: None)
    assert result == {}


def test_execute_without_progress_returns_dict():
    inspector = MockInspector()
    pipeline = Mock()
    pipeline.execute.return_value = {"result": "data"}
    
    result = inspector._execute_without_progress(pipeline, {})
    assert result == {"result": "data"}
    pipeline.execute.assert_called_with({}, parallel=False)


def test_execute_without_progress_with_parallel():
    inspector = MockInspector()
    pipeline = Mock()
    pipeline.execute.return_value = {"result": "data"}
    
    result = inspector._execute_without_progress(pipeline, {}, parallel=True)
    assert result == {"result": "data"}
    pipeline.execute.assert_called_with({}, parallel=True)


def test_execute_without_progress_converts_non_dict():
    inspector = MockInspector()
    pipeline = Mock()
    pipeline.execute.return_value = ["not", "dict"]
    
    result = inspector._execute_without_progress(pipeline, {})
    assert result == {}


def test_as_dict_with_dict():
    result = InspectorExecutionMixin._as_dict({"key": "value"})
    assert result == {"key": "value"}


def test_as_dict_with_non_dict():
    assert InspectorExecutionMixin._as_dict("string") == {}
    assert InspectorExecutionMixin._as_dict(123) == {}
    assert InspectorExecutionMixin._as_dict(None) == {}
    assert InspectorExecutionMixin._as_dict([1, 2, 3]) == {}


def test_as_bool_dict_with_dict():
    input_data = {"key1": 1, "key2": 0, "key3": True, "key4": False, "key5": "string"}
    result = InspectorExecutionMixin._as_bool_dict(input_data)
    assert result == {"key1": True, "key2": False, "key3": True, "key4": False, "key5": True}


def test_as_bool_dict_with_mixed_keys():
    input_data = {1: True, "str": False, 3.14: 1}
    result = InspectorExecutionMixin._as_bool_dict(input_data)
    assert result == {"1": True, "str": False, "3.14": True}


def test_as_bool_dict_with_non_dict():
    assert InspectorExecutionMixin._as_bool_dict("string") == {}
    assert InspectorExecutionMixin._as_bool_dict(123) == {}
    assert InspectorExecutionMixin._as_bool_dict(None) == {}


def test_as_str_with_string():
    result = InspectorExecutionMixin._as_str("test")
    assert result == "test"


def test_as_str_with_non_string():
    assert InspectorExecutionMixin._as_str(123) == ""
    assert InspectorExecutionMixin._as_str(None) == ""
    assert InspectorExecutionMixin._as_str([1, 2]) == ""


def test_as_str_with_custom_default():
    assert InspectorExecutionMixin._as_str(123, default="custom") == "custom"
    assert InspectorExecutionMixin._as_str(None, default="N/A") == "N/A"


def test_execute_analyzer_not_found():
    inspector = MockInspector()
    inspector.registry.get_analyzer_class.return_value = None
    
    result = inspector._execute_analyzer("nonexistent_analyzer")
    assert result == {}
    inspector.registry.get_analyzer_class.assert_called_with("nonexistent_analyzer")


def test_execute_analyzer_default_method():
    inspector = MockInspector()
    analyzer_class = Mock()
    inspector.registry.get_analyzer_class.return_value = analyzer_class
    
    mock_analyzer = Mock()
    mock_analyzer.analyze.return_value = {"data": "result"}
    analyzer_class.return_value = mock_analyzer
    
    result = inspector._execute_analyzer("test_analyzer")
    assert result == {"data": "result"}


def test_execute_analyzer_custom_method():
    inspector = MockInspector()
    analyzer_class = Mock()
    inspector.registry.get_analyzer_class.return_value = analyzer_class
    
    mock_analyzer = Mock()
    mock_analyzer.custom_method.return_value = {"custom": "data"}
    analyzer_class.return_value = mock_analyzer
    
    result = inspector._execute_analyzer("test_analyzer", "custom_method")
    assert result == {"custom": "data"}
    mock_analyzer.custom_method.assert_called_once()


def test_execute_analyzer_method_not_found():
    inspector = MockInspector()
    analyzer_class = Mock()
    inspector.registry.get_analyzer_class.return_value = analyzer_class
    
    mock_analyzer = Mock(spec=[])
    analyzer_class.return_value = mock_analyzer
    
    result = inspector._execute_analyzer("test_analyzer", "missing_method")
    assert result == {}


def test_execute_analyzer_with_args():
    inspector = MockInspector()
    analyzer_class = Mock()
    inspector.registry.get_analyzer_class.return_value = analyzer_class
    
    mock_analyzer = Mock()
    mock_analyzer.analyze.return_value = {"result": "ok"}
    analyzer_class.return_value = mock_analyzer
    
    result = inspector._execute_analyzer("test_analyzer", "analyze", "arg1", "arg2")
    assert result == {"result": "ok"}
    mock_analyzer.analyze.assert_called_with("arg1", "arg2")


def test_execute_analyzer_with_kwargs():
    inspector = MockInspector()
    analyzer_class = Mock()
    inspector.registry.get_analyzer_class.return_value = analyzer_class
    
    mock_analyzer = Mock()
    mock_analyzer.analyze.return_value = {"result": "ok"}
    analyzer_class.return_value = mock_analyzer
    
    result = inspector._execute_analyzer("test_analyzer", "analyze", key="value")
    assert result == {"result": "ok"}
    mock_analyzer.analyze.assert_called_with(key="value")


def test_execute_analyzer_raises_exception():
    inspector = MockInspector()
    analyzer_class = Mock()
    inspector.registry.get_analyzer_class.return_value = analyzer_class
    analyzer_class.side_effect = Exception("Test error")
    
    result = inspector._execute_analyzer("test_analyzer")
    assert result == {}


def test_execute_list_returns_list():
    inspector = MockInspector()
    analyzer_class = Mock()
    inspector.registry.get_analyzer_class.return_value = analyzer_class
    
    mock_analyzer = Mock()
    mock_analyzer.analyze.return_value = ["item1", "item2"]
    analyzer_class.return_value = mock_analyzer
    
    result = inspector._execute_list("test_analyzer")
    assert result == ["item1", "item2"]


def test_execute_list_converts_non_list():
    inspector = MockInspector()
    analyzer_class = Mock()
    inspector.registry.get_analyzer_class.return_value = analyzer_class
    
    mock_analyzer = Mock()
    mock_analyzer.analyze.return_value = {"not": "list"}
    analyzer_class.return_value = mock_analyzer
    
    result = inspector._execute_list("test_analyzer")
    assert result == []


def test_execute_dict_returns_dict():
    inspector = MockInspector()
    analyzer_class = Mock()
    inspector.registry.get_analyzer_class.return_value = analyzer_class
    
    mock_analyzer = Mock()
    mock_analyzer.analyze.return_value = {"key": "value"}
    analyzer_class.return_value = mock_analyzer
    
    result = inspector._execute_dict("test_analyzer")
    assert result == {"key": "value"}


def test_execute_dict_converts_non_dict():
    inspector = MockInspector()
    analyzer_class = Mock()
    inspector.registry.get_analyzer_class.return_value = analyzer_class
    
    mock_analyzer = Mock()
    mock_analyzer.analyze.return_value = ["not", "dict"]
    analyzer_class.return_value = mock_analyzer
    
    result = inspector._execute_dict("test_analyzer")
    assert result == {}


def test_get_file_info():
    inspector = MockInspector()
    inspector.adapter.cmdj.return_value = {"size": 1024, "name": "test.bin"}
    
    result = inspector.get_file_info()
    assert isinstance(result, dict)


def test_detect_file_format():
    inspector = MockInspector()
    inspector.adapter.cmdj.return_value = {"info": {"bintype": "pe"}}
    
    result = inspector._detect_file_format()
    assert isinstance(result, str)


def test_get_pe_info():
    inspector = MockInspector()
    inspector.registry.get_analyzer_class.return_value = Mock()
    
    result = inspector.get_pe_info()
    assert isinstance(result, dict)


def test_get_elf_info():
    inspector = MockInspector()
    inspector.registry.get_analyzer_class.return_value = Mock()
    
    result = inspector.get_elf_info()
    assert isinstance(result, dict)


def test_get_macho_info():
    inspector = MockInspector()
    inspector.registry.get_analyzer_class.return_value = Mock()
    
    result = inspector.get_macho_info()
    assert isinstance(result, dict)


def test_get_strings():
    inspector = MockInspector()
    analyzer_class = Mock()
    inspector.registry.get_analyzer_class.return_value = analyzer_class
    
    mock_analyzer = Mock()
    mock_analyzer.extract_strings.return_value = ["string1", "string2"]
    analyzer_class.return_value = mock_analyzer
    
    result = inspector.get_strings()
    assert result == ["string1", "string2"]


def test_get_security_features():
    inspector = MockInspector()
    analyzer_class = Mock()
    inspector.registry.get_analyzer_class.return_value = analyzer_class
    
    mock_analyzer = Mock()
    mock_analyzer.get_security_features.return_value = {"aslr": True, "dep": False}
    analyzer_class.return_value = mock_analyzer
    
    result = inspector.get_security_features()
    assert result == {"aslr": True, "dep": False}


def test_get_imports():
    inspector = MockInspector()
    analyzer_class = Mock()
    inspector.registry.get_analyzer_class.return_value = analyzer_class
    
    mock_analyzer = Mock()
    mock_analyzer.get_imports.return_value = [{"name": "kernel32.dll"}]
    analyzer_class.return_value = mock_analyzer
    
    result = inspector.get_imports()
    assert result == [{"name": "kernel32.dll"}]


def test_get_exports():
    inspector = MockInspector()
    analyzer_class = Mock()
    inspector.registry.get_analyzer_class.return_value = analyzer_class
    
    mock_analyzer = Mock()
    mock_analyzer.get_exports.return_value = [{"name": "DllMain"}]
    analyzer_class.return_value = mock_analyzer
    
    result = inspector.get_exports()
    assert result == [{"name": "DllMain"}]


def test_get_sections():
    inspector = MockInspector()
    analyzer_class = Mock()
    inspector.registry.get_analyzer_class.return_value = analyzer_class
    
    mock_analyzer = Mock()
    mock_analyzer.analyze_sections.return_value = [{"name": ".text"}]
    analyzer_class.return_value = mock_analyzer
    
    result = inspector.get_sections()
    assert result == [{"name": ".text"}]


def test_detect_packer():
    inspector = MockInspector()
    analyzer_class = Mock()
    inspector.registry.get_analyzer_class.return_value = analyzer_class
    
    mock_analyzer = Mock()
    mock_analyzer.detect.return_value = {"is_packed": True}
    analyzer_class.return_value = mock_analyzer
    
    result = inspector.detect_packer()
    assert result == {"is_packed": True}


def test_detect_crypto():
    inspector = MockInspector()
    analyzer_class = Mock()
    inspector.registry.get_analyzer_class.return_value = analyzer_class
    
    mock_analyzer = Mock()
    mock_analyzer.detect.return_value = {"algorithms": ["AES"]}
    analyzer_class.return_value = mock_analyzer
    
    result = inspector.detect_crypto()
    assert "algorithms" in result


def test_detect_crypto_analyzer_not_found():
    inspector = MockInspector()
    inspector.registry.get_analyzer_class.return_value = None
    
    result = inspector.detect_crypto()
    assert result["error"] == "Analyzer not found"


def test_detect_anti_analysis():
    inspector = MockInspector()
    analyzer_class = Mock()
    inspector.registry.get_analyzer_class.return_value = analyzer_class
    
    mock_analyzer = Mock()
    mock_analyzer.detect.return_value = {"anti_debug": True}
    analyzer_class.return_value = mock_analyzer
    
    result = inspector.detect_anti_analysis()
    assert result == {"anti_debug": True}


def test_detect_compiler():
    inspector = MockInspector()
    analyzer_class = Mock()
    inspector.registry.get_analyzer_class.return_value = analyzer_class
    
    mock_analyzer = Mock()
    mock_analyzer.detect_compiler.return_value = {"compiler": "MSVC"}
    analyzer_class.return_value = mock_analyzer
    
    result = inspector.detect_compiler()
    assert result == {"compiler": "MSVC"}


def test_run_yara_rules():
    inspector = MockInspector()
    analyzer_class = Mock()
    inspector.registry.get_analyzer_class.return_value = analyzer_class
    
    mock_analyzer = Mock()
    mock_analyzer.scan.return_value = [{"rule": "malware"}]
    analyzer_class.return_value = mock_analyzer
    
    result = inspector.run_yara_rules()
    assert result == [{"rule": "malware"}]


def test_run_yara_rules_with_custom_path():
    inspector = MockInspector()
    analyzer_class = Mock()
    inspector.registry.get_analyzer_class.return_value = analyzer_class
    
    mock_analyzer = Mock()
    mock_analyzer.scan.return_value = [{"rule": "custom"}]
    analyzer_class.return_value = mock_analyzer
    
    result = inspector.run_yara_rules("/path/to/rules")
    assert result == [{"rule": "custom"}]
    mock_analyzer.scan.assert_called_with("/path/to/rules")


def test_search_xor():
    inspector = MockInspector()
    analyzer_class = Mock()
    inspector.registry.get_analyzer_class.return_value = analyzer_class
    
    mock_analyzer = Mock()
    mock_analyzer.search_xor.return_value = [{"offset": 100}]
    analyzer_class.return_value = mock_analyzer
    
    result = inspector.search_xor("test")
    assert result == [{"offset": 100}]
    mock_analyzer.search_xor.assert_called_with("test")


def test_generate_indicators():
    inspector = MockInspector()
    inspector._result_aggregator.generate_indicators.return_value = [{"type": "suspicious"}]
    
    result = inspector.generate_indicators({"data": "test"})
    assert result == [{"type": "suspicious"}]


def test_generate_indicators_non_list():
    inspector = MockInspector()
    inspector._result_aggregator.generate_indicators.return_value = "not_a_list"
    
    result = inspector.generate_indicators({"data": "test"})
    assert result == []


def test_analyze_functions():
    inspector = MockInspector()
    analyzer_class = Mock()
    inspector.registry.get_analyzer_class.return_value = analyzer_class
    
    mock_analyzer = Mock()
    mock_analyzer.analyze_functions.return_value = {"count": 10}
    analyzer_class.return_value = mock_analyzer
    
    result = inspector.analyze_functions()
    assert result == {"count": 10}


def test_analyze_ssdeep():
    inspector = MockInspector()
    inspector.registry.get_analyzer_class.return_value = Mock()
    result = inspector.analyze_ssdeep()
    assert isinstance(result, dict)


def test_analyze_tlsh():
    inspector = MockInspector()
    inspector.registry.get_analyzer_class.return_value = Mock()
    result = inspector.analyze_tlsh()
    assert isinstance(result, dict)


def test_analyze_telfhash():
    inspector = MockInspector()
    inspector.registry.get_analyzer_class.return_value = Mock()
    result = inspector.analyze_telfhash()
    assert isinstance(result, dict)


def test_analyze_rich_header():
    inspector = MockInspector()
    inspector.registry.get_analyzer_class.return_value = Mock()
    result = inspector.analyze_rich_header()
    assert isinstance(result, dict)


def test_analyze_impfuzzy():
    inspector = MockInspector()
    inspector.registry.get_analyzer_class.return_value = Mock()
    result = inspector.analyze_impfuzzy()
    assert isinstance(result, dict)


def test_analyze_ccbhash():
    inspector = MockInspector()
    inspector.registry.get_analyzer_class.return_value = Mock()
    result = inspector.analyze_ccbhash()
    assert isinstance(result, dict)


def test_analyze_binlex():
    inspector = MockInspector()
    inspector.registry.get_analyzer_class.return_value = Mock()
    result = inspector.analyze_binlex()
    assert isinstance(result, dict)


def test_analyze_binbloom():
    inspector = MockInspector()
    inspector.registry.get_analyzer_class.return_value = Mock()
    result = inspector.analyze_binbloom()
    assert isinstance(result, dict)


def test_analyze_simhash():
    inspector = MockInspector()
    inspector.registry.get_analyzer_class.return_value = Mock()
    result = inspector.analyze_simhash()
    assert isinstance(result, dict)


def test_analyze_bindiff():
    inspector = MockInspector()
    inspector.registry.get_analyzer_class.return_value = Mock()
    result = inspector.analyze_bindiff()
    assert isinstance(result, dict)


def test_generate_executive_summary():
    inspector = MockInspector()
    inspector._result_aggregator.generate_executive_summary.return_value = {"summary": "data"}
    
    result = inspector.generate_executive_summary({"analysis": "results"})
    assert result == {"summary": "data"}


def test_generate_executive_summary_non_dict():
    inspector = MockInspector()
    inspector._result_aggregator.generate_executive_summary.return_value = ["not", "dict"]
    
    result = inspector.generate_executive_summary({"analysis": "results"})
    assert result == {}
