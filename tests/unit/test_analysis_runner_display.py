#!/usr/bin/env python3
"""Comprehensive tests for r2inspect/cli/analysis_runner.py"""

from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from r2inspect.cli.analysis_runner import (
    add_statistics_to_results,
    handle_main_error,
    has_circuit_breaker_data,
    output_console_results,
    output_csv_results,
    output_json_results,
    output_results,
    print_status_if_appropriate,
    run_analysis,
    setup_analysis_options,
    setup_single_file_output,
)


def test_run_analysis_basic():
    inspector = MagicMock()
    options = {"full_analysis": True}

    with patch("r2inspect.cli.analysis_runner.AnalyzeBinaryUseCase") as mock_use_case:
        mock_instance = mock_use_case.return_value
        mock_instance.run.return_value = {"file_info": {"name": "test.exe"}}

        with patch("r2inspect.cli.analysis_runner.print_status_if_appropriate"):
            with patch("r2inspect.cli.analysis_runner.output_results"):
                result = run_analysis(inspector, options, False, False, None)
                assert "file_info" in result
                mock_instance.run.assert_called_once_with(inspector, options)


def test_run_analysis_with_json_output():
    inspector = MagicMock()
    options = {}

    with patch("r2inspect.cli.analysis_runner.AnalyzeBinaryUseCase") as mock_use_case:
        mock_instance = mock_use_case.return_value
        mock_instance.run.return_value = {}

        with patch("r2inspect.cli.analysis_runner.print_status_if_appropriate"):
            with patch("r2inspect.cli.analysis_runner.output_results") as mock_output:
                run_analysis(inspector, options, True, False, "output.json")
                mock_output.assert_called_once()
                args = mock_output.call_args[0]
                assert args[1] is True
                assert args[2] is False


def test_run_analysis_with_csv_output():
    inspector = MagicMock()
    options = {}

    with patch("r2inspect.cli.analysis_runner.AnalyzeBinaryUseCase") as mock_use_case:
        mock_instance = mock_use_case.return_value
        mock_instance.run.return_value = {}

        with patch("r2inspect.cli.analysis_runner.print_status_if_appropriate"):
            with patch("r2inspect.cli.analysis_runner.output_results") as mock_output:
                run_analysis(inspector, options, False, True, "output.csv")
                mock_output.assert_called_once()


def test_run_analysis_verbose():
    inspector = MagicMock()
    options = {}

    with patch("r2inspect.cli.analysis_runner.AnalyzeBinaryUseCase") as mock_use_case:
        mock_instance = mock_use_case.return_value
        mock_instance.run.return_value = {}

        with patch("r2inspect.cli.analysis_runner.print_status_if_appropriate"):
            with patch("r2inspect.cli.analysis_runner.output_results") as mock_output:
                run_analysis(inspector, options, False, False, None, verbose=True)
                args = mock_output.call_args[0]
                assert args[4] is True


def test_print_status_if_appropriate():
    console = MagicMock()
    with patch("r2inspect.cli.analysis_runner.analysis_output") as mock_analysis_output:
        print_status_if_appropriate(True, False, "output.json")
        mock_analysis_output.print_status_if_needed.assert_called_once()


def test_print_status_if_appropriate_no_output():
    console = MagicMock()
    with patch("r2inspect.cli.analysis_runner.analysis_output") as mock_analysis_output:
        print_status_if_appropriate(False, False, None)
        mock_analysis_output.print_status_if_needed.assert_called_once()


def test_add_statistics_to_results():
    results = {}
    with patch("r2inspect.cli.analysis_runner.default_analysis_service") as mock_service:
        add_statistics_to_results(results)
        mock_service.add_statistics.assert_called_once_with(results)


def test_add_statistics_to_results_existing():
    results = {"file_info": {"name": "test.exe"}}
    with patch("r2inspect.cli.analysis_runner.default_analysis_service") as mock_service:
        add_statistics_to_results(results)
        mock_service.add_statistics.assert_called_once()


def test_has_circuit_breaker_data_true():
    circuit_stats = {"total_calls": 100, "failures": 5}
    with patch("r2inspect.cli.analysis_runner.default_analysis_service") as mock_service:
        mock_service.has_circuit_breaker_data.return_value = True
        result = has_circuit_breaker_data(circuit_stats)
        assert result is True


def test_has_circuit_breaker_data_false():
    circuit_stats = {}
    with patch("r2inspect.cli.analysis_runner.default_analysis_service") as mock_service:
        mock_service.has_circuit_breaker_data.return_value = False
        result = has_circuit_breaker_data(circuit_stats)
        assert result is False


def test_output_results_json():
    results = {"file_info": {"name": "test.exe"}}

    with patch("r2inspect.cli.analysis_runner.analysis_output") as mock_output:
        output_results(results, True, False, "output.json", False)
        mock_output.output_results.assert_called_once()


def test_output_results_csv():
    results = {"file_info": {"name": "test.exe"}}

    with patch("r2inspect.cli.analysis_runner.analysis_output") as mock_output:
        output_results(results, False, True, "output.csv", False)
        mock_output.output_results.assert_called_once()


def test_output_results_console():
    results = {"file_info": {"name": "test.exe"}}

    with patch("r2inspect.cli.analysis_runner.analysis_output") as mock_output:
        output_results(results, False, False, None, False)
        mock_output.output_results.assert_called_once()


def test_output_results_verbose():
    results = {"file_info": {"name": "test.exe"}}

    with patch("r2inspect.cli.analysis_runner.analysis_output") as mock_output:
        output_results(results, False, False, None, True)
        mock_output.output_results.assert_called_once()


def test_output_json_results():
    formatter = MagicMock()
    console = MagicMock()

    with patch("r2inspect.cli.analysis_runner.analysis_output") as mock_output:
        output_json_results(formatter, "output.json")
        mock_output._output_json_results.assert_called_once()


def test_output_json_results_no_file():
    formatter = MagicMock()
    console = MagicMock()

    with patch("r2inspect.cli.analysis_runner.analysis_output") as mock_output:
        output_json_results(formatter, None)
        mock_output._output_json_results.assert_called_once()


def test_output_csv_results():
    formatter = MagicMock()
    console = MagicMock()

    with patch("r2inspect.cli.analysis_runner.analysis_output") as mock_output:
        output_csv_results(formatter, "output.csv")
        mock_output._output_csv_results.assert_called_once()


def test_output_csv_results_no_file():
    formatter = MagicMock()
    console = MagicMock()

    with patch("r2inspect.cli.analysis_runner.analysis_output") as mock_output:
        output_csv_results(formatter, None)
        mock_output._output_csv_results.assert_called_once()


def test_output_console_results():
    results = {"file_info": {"name": "test.exe"}}

    with patch("r2inspect.cli.analysis_runner.analysis_output") as mock_output:
        output_console_results(results, False)
        mock_output._output_console_results.assert_called_once_with(results, False)


def test_output_console_results_verbose():
    results = {"file_info": {"name": "test.exe"}}

    with patch("r2inspect.cli.analysis_runner.analysis_output") as mock_output:
        output_console_results(results, True)
        mock_output._output_console_results.assert_called_once_with(results, True)


def test_setup_single_file_output_json(tmp_path):
    result = setup_single_file_output(True, False, None, "test.exe")
    assert str(result).endswith("_analysis.json")
    assert "test" in str(result)


def test_setup_single_file_output_csv(tmp_path):
    result = setup_single_file_output(False, True, None, "test.exe")
    assert str(result).endswith("_analysis.csv")
    assert "test" in str(result)


def test_setup_single_file_output_custom():
    result = setup_single_file_output(True, False, "custom.json", "test.exe")
    assert result == "custom.json"


def test_setup_single_file_output_none():
    result = setup_single_file_output(False, False, None, "test.exe")
    assert result is None


def test_setup_single_file_output_creates_directory():
    with patch("pathlib.Path.mkdir") as mock_mkdir:
        setup_single_file_output(True, False, None, "test.exe")
        mock_mkdir.assert_called_once_with(exist_ok=True)


def test_setup_single_file_output_path_object():
    result = setup_single_file_output(True, False, None, "/full/path/to/test.exe")
    assert isinstance(result, Path)


def test_setup_analysis_options_default():
    options = setup_analysis_options(None, None)
    assert options["detect_packer"] is True
    assert options["detect_crypto"] is True
    assert options["detect_av"] is True
    assert options["full_analysis"] is True
    assert options["custom_yara"] is None
    assert options["xor_search"] is None


def test_setup_analysis_options_with_yara():
    options = setup_analysis_options("/path/to/yara", None)
    assert options["custom_yara"] == "/path/to/yara"
    assert options["detect_packer"] is True


def test_setup_analysis_options_with_xor():
    options = setup_analysis_options(None, "xor_string")
    assert options["xor_search"] == "xor_string"
    assert options["full_analysis"] is True


def test_setup_analysis_options_with_both():
    options = setup_analysis_options("/yara/path", "xor_data")
    assert options["custom_yara"] == "/yara/path"
    assert options["xor_search"] == "xor_data"


def test_handle_main_error_non_verbose():
    error = ValueError("Test error message")
    console = MagicMock()

    with patch("r2inspect.cli.analysis_runner.console", console):
        with pytest.raises(SystemExit) as exc_info:
            handle_main_error(error, verbose=False)
        assert exc_info.value.code == 1
        console.print.assert_called_once()


def test_handle_main_error_verbose():
    error = RuntimeError("Test runtime error")
    console = MagicMock()

    with patch("r2inspect.cli.analysis_runner.console", console):
        with patch("traceback.print_exc") as mock_traceback:
            with pytest.raises(SystemExit) as exc_info:
                handle_main_error(error, verbose=True)
            assert exc_info.value.code == 1
            mock_traceback.assert_called_once()


def test_handle_main_error_message():
    error = Exception("Custom error")
    console = MagicMock()

    with patch("r2inspect.cli.analysis_runner.console", console):
        with pytest.raises(SystemExit):
            handle_main_error(error, verbose=False)
        call_args = console.print.call_args[0][0]
        assert "Custom error" in call_args


def test_run_analysis_integration():
    inspector = MagicMock()
    options = {"full_analysis": True, "detect_packer": True}

    with patch("r2inspect.cli.analysis_runner.AnalyzeBinaryUseCase") as mock_use_case:
        mock_instance = mock_use_case.return_value
        mock_instance.run.return_value = {
            "file_info": {"name": "test.exe", "size": 1024},
            "pe_info": {"subsystem": "Console"},
        }

        with patch("r2inspect.cli.analysis_runner.print_status_if_appropriate"):
            with patch("r2inspect.cli.analysis_runner.output_results"):
                result = run_analysis(inspector, options, True, False, "out.json", verbose=True)
                assert result["file_info"]["name"] == "test.exe"


def test_output_results_path_object():
    results = {}
    output_path = Path("output.json")

    with patch("r2inspect.cli.analysis_runner.analysis_output") as mock_output:
        output_results(results, True, False, output_path, False)
        mock_output.output_results.assert_called_once()


def test_setup_single_file_output_nested_path(tmp_path):
    nested_path = tmp_path / "nested" / "dir" / "file.exe"
    result = setup_single_file_output(True, False, None, str(nested_path))
    assert isinstance(result, Path)
    assert result.name.endswith("_analysis.json")


def test_setup_single_file_output_special_characters():
    result = setup_single_file_output(True, False, None, "test-file.v2.exe")
    assert "test-file.v2" in str(result)


def test_has_circuit_breaker_data_complex():
    circuit_stats = {
        "total_calls": 1000,
        "failures": 10,
        "success_rate": 0.99,
        "state": "closed",
    }
    with patch("r2inspect.cli.analysis_runner.default_analysis_service") as mock_service:
        mock_service.has_circuit_breaker_data.return_value = True
        result = has_circuit_breaker_data(circuit_stats)
        assert result is True
        mock_service.has_circuit_breaker_data.assert_called_once_with(circuit_stats)


def test_run_analysis_all_output_types():
    inspector = MagicMock()
    options = {}

    with patch("r2inspect.cli.analysis_runner.AnalyzeBinaryUseCase") as mock_use_case:
        mock_instance = mock_use_case.return_value
        mock_instance.run.return_value = {"file_info": {}}

        with patch("r2inspect.cli.analysis_runner.print_status_if_appropriate"):
            with patch("r2inspect.cli.analysis_runner.output_results") as mock_output:
                run_analysis(inspector, options, True, True, "output.json", verbose=True)
                args = mock_output.call_args[0]
                assert args[1] is True
                assert args[2] is True
                assert args[4] is True
