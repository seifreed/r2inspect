from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from r2inspect.abstractions.base_analyzer import BaseAnalyzer


class ConcreteAnalyzer(BaseAnalyzer):
    def analyze(self) -> dict[str, Any]:
        return self._init_result_structure({"test_field": "value"})

    def get_category(self) -> str:
        return "test_category"

    def get_description(self) -> str:
        return "Test analyzer description"


class FormatSpecificAnalyzer(BaseAnalyzer):
    def analyze(self) -> dict[str, Any]:
        return {"available": True}

    def supports_format(self, file_format: str) -> bool:
        return file_format.upper() in {"PE", "PE32"}

    def get_supported_formats(self) -> set[str]:
        return {"PE", "PE32"}


class UnavailableAnalyzer(BaseAnalyzer):
    def analyze(self) -> dict[str, Any]:
        return {"available": False}

    @classmethod
    def is_available(cls) -> bool:
        return False


def test_base_analyzer_initialization_with_filepath(tmp_path: Path) -> None:
    test_file = tmp_path / "test.bin"

    analyzer = ConcreteAnalyzer(filepath=str(test_file))

    assert analyzer.filepath == Path(test_file)
    assert analyzer.adapter is None
    assert analyzer.r2 is None
    assert analyzer.config is None


def test_base_analyzer_initialization_with_path_object(tmp_path: Path) -> None:
    test_file = tmp_path / "test.bin"

    analyzer = ConcreteAnalyzer(filepath=test_file)

    assert analyzer.filepath == test_file


def test_base_analyzer_initialization_without_filepath() -> None:
    analyzer = ConcreteAnalyzer()

    assert analyzer.filepath is None


def test_base_analyzer_initialization_with_adapter() -> None:
    class MockAdapter:
        pass

    adapter = MockAdapter()

    analyzer = ConcreteAnalyzer(adapter=adapter)

    assert analyzer.adapter is adapter
    assert analyzer.r2 is adapter


def test_base_analyzer_initialization_with_config() -> None:
    class MockConfig:
        pass

    config = MockConfig()

    analyzer = ConcreteAnalyzer(config=config)

    assert analyzer.config is config


def test_base_analyzer_initialization_with_kwargs() -> None:
    analyzer = ConcreteAnalyzer(custom_param="value", another_param=123)

    assert analyzer._extra_params["custom_param"] == "value"
    assert analyzer._extra_params["another_param"] == 123


def test_base_analyzer_init_result_structure_basic() -> None:
    analyzer = ConcreteAnalyzer()

    result = analyzer._init_result_structure()

    assert result["available"] is False
    assert result["error"] is None
    assert result["analyzer"] == "concrete"
    assert result["execution_time"] == 0.0


def test_base_analyzer_init_result_structure_with_additional_fields() -> None:
    analyzer = ConcreteAnalyzer()

    result = analyzer._init_result_structure(
        {"hash_value": None, "hash_type": "test", "custom": 42}
    )

    assert result["available"] is False
    assert result["error"] is None
    assert result["analyzer"] == "concrete"
    assert result["hash_value"] is None
    assert result["hash_type"] == "test"
    assert result["custom"] == 42


def test_base_analyzer_mark_unavailable() -> None:
    analyzer = ConcreteAnalyzer()

    result = {"available": True, "error": None}
    updated = analyzer._mark_unavailable(result, "Test error")

    assert updated["available"] is False
    assert updated["error"] == "Test error"


def test_base_analyzer_mark_unavailable_with_library_available() -> None:
    analyzer = ConcreteAnalyzer()

    result = {"available": True}
    updated = analyzer._mark_unavailable(result, "Missing lib", library_available=False)

    assert updated["available"] is False
    assert updated["library_available"] is False
    assert updated["error"] == "Missing lib"


def test_base_analyzer_get_name_basic() -> None:
    analyzer = ConcreteAnalyzer()

    assert analyzer.get_name() == "concrete"


def test_base_analyzer_get_name_removes_analyzer_suffix() -> None:
    class TestAnalyzer(BaseAnalyzer):
        def analyze(self) -> dict[str, Any]:
            return {}

    analyzer = TestAnalyzer()

    assert analyzer.get_name() == "test"


def test_base_analyzer_get_name_removes_detector_suffix() -> None:
    class PackerDetector(BaseAnalyzer):
        def analyze(self) -> dict[str, Any]:
            return {}

    detector = PackerDetector()

    assert detector.get_name() == "packer"


def test_base_analyzer_get_name_camelcase_conversion() -> None:
    class MyComplexAnalyzer(BaseAnalyzer):
        def analyze(self) -> dict[str, Any]:
            return {}

    analyzer = MyComplexAnalyzer()

    assert analyzer.get_name() == "my_complex"


def test_base_analyzer_get_name_caching() -> None:
    analyzer = ConcreteAnalyzer()

    name1 = analyzer.get_name()
    name2 = analyzer.get_name()

    assert name1 == name2
    assert analyzer._cached_name == "concrete"


def test_base_analyzer_get_category_default() -> None:
    class DefaultAnalyzer(BaseAnalyzer):
        def analyze(self) -> dict[str, Any]:
            return {}

    analyzer = DefaultAnalyzer()

    assert analyzer.get_category() == "unknown"


def test_base_analyzer_get_category_custom() -> None:
    analyzer = ConcreteAnalyzer()

    assert analyzer.get_category() == "test_category"


def test_base_analyzer_get_category_caching() -> None:
    class CachingAnalyzer(BaseAnalyzer):
        def analyze(self) -> dict[str, Any]:
            return {}

    analyzer = CachingAnalyzer()

    category1 = analyzer.get_category()
    analyzer._cached_category = "modified"
    category2 = analyzer.get_category()

    assert category1 == "unknown"
    assert category2 == "modified"


def test_base_analyzer_get_description_custom() -> None:
    analyzer = ConcreteAnalyzer()

    assert analyzer.get_description() == "Test analyzer description"


def test_base_analyzer_get_description_default() -> None:
    class DefaultAnalyzer(BaseAnalyzer):
        def analyze(self) -> dict[str, Any]:
            return {}

    analyzer = DefaultAnalyzer()

    assert "DefaultAnalyzer" in analyzer.get_description()
    assert "No description provided" in analyzer.get_description()


def test_base_analyzer_supports_format_default() -> None:
    analyzer = ConcreteAnalyzer()

    assert analyzer.supports_format("PE") is True
    assert analyzer.supports_format("ELF") is True
    assert analyzer.supports_format("MACHO") is True


def test_base_analyzer_supports_format_custom() -> None:
    analyzer = FormatSpecificAnalyzer()

    assert analyzer.supports_format("PE") is True
    assert analyzer.supports_format("pe32") is True
    assert analyzer.supports_format("ELF") is False


def test_base_analyzer_get_supported_formats_default() -> None:
    analyzer = ConcreteAnalyzer()

    formats = analyzer.get_supported_formats()

    assert formats == set()


def test_base_analyzer_get_supported_formats_custom() -> None:
    analyzer = FormatSpecificAnalyzer()

    formats = analyzer.get_supported_formats()

    assert formats == {"PE", "PE32"}


def test_base_analyzer_is_available_default() -> None:
    assert ConcreteAnalyzer.is_available() is True


def test_base_analyzer_is_available_custom() -> None:
    assert UnavailableAnalyzer.is_available() is False


def test_base_analyzer_log_debug(caplog) -> None:
    import logging

    caplog.set_level(logging.DEBUG)
    analyzer = ConcreteAnalyzer()

    analyzer._log_debug("Debug message")

    assert "[concrete] Debug message" in caplog.text


def test_base_analyzer_log_info(caplog) -> None:
    import logging

    caplog.set_level(logging.INFO)
    analyzer = ConcreteAnalyzer()

    analyzer._log_info("Info message")

    assert "[concrete] Info message" in caplog.text


def test_base_analyzer_log_warning(caplog) -> None:
    import logging

    caplog.set_level(logging.WARNING)
    analyzer = ConcreteAnalyzer()

    analyzer._log_warning("Warning message")

    assert "[concrete] Warning message" in caplog.text


def test_base_analyzer_log_error(caplog) -> None:
    import logging

    caplog.set_level(logging.ERROR)
    analyzer = ConcreteAnalyzer()

    analyzer._log_error("Error message")

    assert "[concrete] Error message" in caplog.text


def test_base_analyzer_measure_execution_time() -> None:
    analyzer = ConcreteAnalyzer()

    @analyzer._measure_execution_time
    def test_function():
        import time

        time.sleep(0.01)
        return {"data": "result"}

    result = test_function()

    assert result["data"] == "result"
    assert result["execution_time"] > 0


def test_base_analyzer_measure_execution_time_non_dict() -> None:
    analyzer = ConcreteAnalyzer()

    @analyzer._measure_execution_time
    def test_function():
        return "not a dict"

    result = test_function()

    assert result == "not a dict"


def test_base_analyzer_analysis_context_success() -> None:
    analyzer = ConcreteAnalyzer()
    result = {"available": False, "error": None}

    with analyzer._analysis_context(result, error_message="Test error"):
        pass

    assert result["available"] is True
    assert result["error"] is None


def test_base_analyzer_analysis_context_exception() -> None:
    analyzer = ConcreteAnalyzer()
    result = {"available": False, "error": None}

    with analyzer._analysis_context(result, error_message="Analysis failed"):
        raise ValueError("Test exception")

    assert result["available"] is False
    assert result["error"] == "Test exception"


def test_base_analyzer_analysis_context_no_set_available() -> None:
    analyzer = ConcreteAnalyzer()
    result = {"available": False, "error": None}

    with analyzer._analysis_context(
        result, error_message="Test error", set_available=False
    ):
        pass

    assert result["available"] is False


def test_base_analyzer_get_file_size_success(tmp_path: Path) -> None:
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"test content")

    analyzer = ConcreteAnalyzer(filepath=test_file)
    size = analyzer.get_file_size()

    assert size == 12


def test_base_analyzer_get_file_size_no_filepath() -> None:
    analyzer = ConcreteAnalyzer()
    size = analyzer.get_file_size()

    assert size is None


def test_base_analyzer_get_file_size_error() -> None:
    analyzer = ConcreteAnalyzer(filepath="/nonexistent/file.bin")
    size = analyzer.get_file_size()

    assert size is None


def test_base_analyzer_get_file_extension_success(tmp_path: Path) -> None:
    test_file = tmp_path / "test.EXE"
    test_file.write_bytes(b"test")

    analyzer = ConcreteAnalyzer(filepath=test_file)
    ext = analyzer.get_file_extension()

    assert ext == "exe"


def test_base_analyzer_get_file_extension_no_filepath() -> None:
    analyzer = ConcreteAnalyzer()
    ext = analyzer.get_file_extension()

    assert ext == ""


def test_base_analyzer_get_file_extension_no_extension(tmp_path: Path) -> None:
    test_file = tmp_path / "noext"
    test_file.write_bytes(b"test")

    analyzer = ConcreteAnalyzer(filepath=test_file)
    ext = analyzer.get_file_extension()

    assert ext == ""


def test_base_analyzer_file_exists_true(tmp_path: Path) -> None:
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"test")

    analyzer = ConcreteAnalyzer(filepath=test_file)

    assert analyzer.file_exists() is True


def test_base_analyzer_file_exists_false() -> None:
    analyzer = ConcreteAnalyzer(filepath="/nonexistent/file.bin")

    assert analyzer.file_exists() is False


def test_base_analyzer_file_exists_no_filepath() -> None:
    analyzer = ConcreteAnalyzer()

    assert analyzer.file_exists() is False


def test_base_analyzer_file_exists_directory(tmp_path: Path) -> None:
    test_dir = tmp_path / "test_dir"
    test_dir.mkdir()

    analyzer = ConcreteAnalyzer(filepath=test_dir)

    assert analyzer.file_exists() is False


def test_base_analyzer_str_representation(tmp_path: Path) -> None:
    test_file = tmp_path / "sample.bin"

    analyzer = ConcreteAnalyzer(filepath=test_file)
    str_repr = str(analyzer)

    assert "ConcreteAnalyzer" in str_repr
    assert "name=concrete" in str_repr
    assert "category=test_category" in str_repr
    assert "file=sample.bin" in str_repr


def test_base_analyzer_str_representation_no_file() -> None:
    analyzer = ConcreteAnalyzer()
    str_repr = str(analyzer)

    assert "ConcreteAnalyzer" in str_repr
    assert "file=no_file" in str_repr


def test_base_analyzer_repr_representation(tmp_path: Path) -> None:
    test_file = tmp_path / "sample.bin"

    class MockAdapter:
        pass

    class MockConfig:
        pass

    adapter = MockAdapter()
    config = MockConfig()

    analyzer = ConcreteAnalyzer(filepath=test_file, adapter=adapter, config=config)
    repr_str = repr(analyzer)

    assert "ConcreteAnalyzer" in repr_str
    assert "filepath=" in repr_str
    assert "r2=<r2pipe>" in repr_str
    assert "config=<Config>" in repr_str


def test_base_analyzer_repr_representation_no_adapter_config() -> None:
    analyzer = ConcreteAnalyzer()
    repr_str = repr(analyzer)

    assert "ConcreteAnalyzer" in repr_str
    assert "r2=None" in repr_str
    assert "config=None" in repr_str
