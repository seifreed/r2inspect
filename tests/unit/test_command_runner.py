import os
import sys

import pytest

from r2inspect.infrastructure.command_runner import run_command


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
