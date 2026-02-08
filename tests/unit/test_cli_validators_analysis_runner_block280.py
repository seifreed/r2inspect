from __future__ import annotations

import os
from pathlib import Path

import pytest

from r2inspect.cli import analysis_runner, validators
from r2inspect.error_handling.policies import ErrorHandlingStrategy, ErrorPolicy
from r2inspect.error_handling.unified_handler import handle_errors, reset_circuit_breakers
from r2inspect.utils.error_handler import ErrorCategory, ErrorInfo, ErrorSeverity, reset_error_stats
from r2inspect.utils.retry_manager import global_retry_manager, reset_retry_stats


@pytest.mark.unit
def test_validators_file_output_and_threads(tmp_path: Path) -> None:
    empty_file = tmp_path / "empty.bin"
    empty_file.write_bytes(b"")
    errors = validators.validate_file_input(str(empty_file))
    assert any("File is empty" in e for e in errors)

    output_file = tmp_path / "out.txt"
    output_file.write_text("data")
    os.chmod(output_file, 0o400)
    try:
        errors = validators.validate_output_input(str(output_file))
        assert any("Cannot write" in e for e in errors)
    finally:
        os.chmod(output_file, 0o600)

    errors = validators.validate_yara_input(str(tmp_path / "missing"))
    assert errors

    config = tmp_path / "config.bad"
    config.write_text("data")
    errors = validators.validate_config_input(str(config))
    assert any("Config file must be" in e for e in errors)

    errors = validators.validate_extensions_input("**")
    assert any("Invalid file extension" in e for e in errors)

    errors = validators.validate_extensions_input("averyverylongext")
    assert any("File extension too long" in e for e in errors)

    assert validators.validate_threads_input(0)
    assert validators.validate_threads_input(100)


@pytest.mark.unit
def test_validate_input_mode_and_xor_warning(capsys) -> None:
    with pytest.raises(SystemExit):
        validators.validate_input_mode(None, None)

    validators.handle_xor_input("$$$")
    captured = capsys.readouterr()
    assert "Warning" in captured.out


@pytest.mark.unit
def test_add_statistics_to_results_with_error_retry_and_circuit() -> None:
    reset_error_stats()
    reset_retry_stats()
    reset_circuit_breakers()

    # Record an error
    error_info = ErrorInfo(
        exception=ValueError("bad"),
        severity=ErrorSeverity.MEDIUM,
        category=ErrorCategory.INPUT_VALIDATION,
        recoverable=False,
        suggested_action="fix",
    )
    from r2inspect.utils.error_handler import global_error_manager

    global_error_manager.handle_error(error_info)

    # Record a retry
    state = {"calls": 0}

    def flaky(**_kwargs: object) -> str:
        state["calls"] += 1
        if state["calls"] < 2:
            raise TimeoutError("fail")
        return "ok"

    global_retry_manager.retry_operation(flaky, command_type="generic", command="noop")

    # Trigger circuit breaker stats
    policy = ErrorPolicy(
        strategy=ErrorHandlingStrategy.CIRCUIT_BREAK,
        circuit_threshold=1,
        circuit_timeout=1.0,
    )

    @handle_errors(policy)
    def always_fail() -> None:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        always_fail()

    results: dict[str, object] = {}
    analysis_runner.add_statistics_to_results(results)
    assert "error_statistics" in results
    assert "retry_statistics" in results
    assert "circuit_breaker_statistics" in results
