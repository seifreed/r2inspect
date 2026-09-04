import os
import sys
from pathlib import Path

import pytest

from r2inspect.infrastructure.command_runner import (
    CommandResourceError,
    cleanup_command_output,
    run_command,
)
from tests.helpers import env_vars


def test_run_command_passes_arguments_without_a_shell() -> None:
    argument = "literal;$(exit 9)"

    completed = run_command(
        [sys.executable, "-c", "import sys; print(sys.argv[1])", argument], timeout=2
    )

    assert completed.returncode == 0
    assert completed.stdout.strip() == argument


def test_run_command_honors_process_timeout_override() -> None:
    original = os.environ.get("R2INSPECT_CMD_TIMEOUT_SECONDS")
    os.environ["R2INSPECT_CMD_TIMEOUT_SECONDS"] = "0.01"
    try:
        with pytest.raises(TimeoutError, match="0.01 seconds"):
            run_command(
                [sys.executable, "-c", "import time; time.sleep(1)"],
                timeout=120,
            )
    finally:
        if original is None:
            os.environ.pop("R2INSPECT_CMD_TIMEOUT_SECONDS", None)
        else:
            os.environ["R2INSPECT_CMD_TIMEOUT_SECONDS"] = original


def test_run_command_spills_large_output_and_keeps_bounded_preview() -> None:
    with env_vars(R2INSPECT_CMD_MAX_OUTPUT_BYTES="16"):
        completed = run_command([sys.executable, "-c", "print('x' * 100)"], timeout=2)
    try:
        assert len(completed.stdout.encode()) == 16
        assert completed.output_truncated is True
        assert completed.stdout_path is not None
        assert len(Path(completed.stdout_path).read_text()) == 101
    finally:
        cleanup_command_output(completed)


def test_run_command_rejects_output_past_spool_limit() -> None:
    with (
        env_vars(R2INSPECT_CMD_MAX_OUTPUT_BYTES="16", R2INSPECT_CMD_MAX_SPOOL_BYTES="32"),
        pytest.raises(CommandResourceError, match="output exceeded") as raised,
    ):
        run_command([sys.executable, "-c", "print('x' * 100)"], timeout=2)
    cleanup_command_output(raised.value.result)


def test_run_command_uses_configured_sandbox_prefix() -> None:
    with env_vars(R2INSPECT_CMD_SANDBOX_PREFIX="env R2INSPECT_SANDBOXED=1"):
        completed = run_command(
            [sys.executable, "-c", "import os; print(os.getenv('R2INSPECT_SANDBOXED'))"],
            timeout=2,
        )
    assert completed.stdout.strip() == "1"


def test_run_command_enforces_memory_limit() -> None:
    with (
        env_vars(R2INSPECT_CMD_MAX_MEMORY_MB="1"),
        pytest.raises(CommandResourceError, match="memory limit exceeded") as raised,
    ):
        run_command(
            [sys.executable, "-c", "import time; data=bytearray(8_000_000); time.sleep(1)"],
            timeout=2,
        )
    cleanup_command_output(raised.value.result)
