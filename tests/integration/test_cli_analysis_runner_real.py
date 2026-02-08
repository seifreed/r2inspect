from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.cli import analysis_runner
from r2inspect.config import Config
from r2inspect.error_handling import ErrorHandlingStrategy, ErrorPolicy, handle_errors
from r2inspect.error_handling.unified_handler import get_circuit_breaker_stats
from r2inspect.factory import create_inspector
from r2inspect.utils import error_handler, retry_manager
from r2inspect.utils.error_handler import ErrorCategory, ErrorSeverity, reset_error_stats
from r2inspect.utils.retry_manager import RetryConfig

pytestmark = pytest.mark.requires_r2

FIXTURE_DIR = Path("samples/fixtures")


def _make_inspector(tmp_path: Path):
    config = Config(str(tmp_path / "r2inspect_analysis_runner.json"))
    return create_inspector(
        filename=str(FIXTURE_DIR / "hello_pe.exe"), config=config, verbose=False
    )


def test_analysis_runner_outputs_and_stats(tmp_path: Path) -> None:
    output_json = tmp_path / "result.json"
    output_csv = tmp_path / "result.csv"

    with _make_inspector(tmp_path) as inspector:
        results = analysis_runner.run_analysis(
            inspector=inspector,
            options=analysis_runner.setup_analysis_options(None, None),
            output_json=True,
            output_csv=False,
            output_file=output_json,
            verbose=False,
        )

    assert output_json.exists()
    assert "file_info" in results

    formatter = analysis_runner.OutputFormatter(results)
    analysis_runner.output_csv_results(formatter, output_csv)
    assert output_csv.exists()

    analysis_runner.output_json_results(formatter, None)
    analysis_runner.output_csv_results(formatter, None)


def test_analysis_runner_verbose_stats_paths(tmp_path: Path) -> None:
    reset_error_stats()
    retry_manager.reset_retry_stats()

    @error_handler.error_handler(
        category=ErrorCategory.FILE_ACCESS, severity=ErrorSeverity.HIGH, fallback_result=None
    )
    def _raise_file_error() -> None:
        raise FileNotFoundError("missing")

    _raise_file_error()

    with pytest.raises(TimeoutError):
        retry_manager.global_retry_manager.retry_operation(
            lambda: (_ for _ in ()).throw(TimeoutError("timeout")),
            command_type="generic",
            config=RetryConfig(max_attempts=1, base_delay=0.0, jitter=False),
        )

    policy = ErrorPolicy(
        strategy=ErrorHandlingStrategy.CIRCUIT_BREAK,
        max_retries=0,
        retry_delay=0.0,
        retry_backoff=1.0,
        retry_jitter=False,
        fallback_value="fallback",
        circuit_threshold=1,
        circuit_timeout=1,
    )

    @handle_errors(policy)
    def _circuit_fail() -> str:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        _circuit_fail()

    circuit_stats = get_circuit_breaker_stats()
    assert analysis_runner.has_circuit_breaker_data(circuit_stats) is True

    results = {}
    analysis_runner.add_statistics_to_results(results)
    assert "error_statistics" in results
    assert "retry_statistics" in results
    assert "circuit_breaker_statistics" in results

    results = {
        "file_info": {
            "name": "sample.bin",
            "size": 1,
            "file_type": "Unknown",
            "md5": "x",
        }
    }
    analysis_runner.output_console_results(results, verbose=True)


def test_analysis_runner_helpers_and_status(tmp_path: Path) -> None:
    analysis_runner.print_status_if_appropriate(False, False, None)
    analysis_runner.print_status_if_appropriate(True, False, "out.json")

    output = analysis_runner.setup_single_file_output(True, False, None, "input.exe")
    assert output is not None

    csv_output = analysis_runner.setup_single_file_output(False, True, None, "input.exe")
    assert csv_output is not None

    results = {"file_info": {"name": "sample.bin"}}
    analysis_runner.output_results(
        results, output_json=False, output_csv=True, output_file=None, verbose=False
    )

    with pytest.raises(SystemExit):
        analysis_runner.handle_main_error(RuntimeError("boom"), verbose=True)
