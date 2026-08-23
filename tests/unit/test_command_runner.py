import sys

from r2inspect.infrastructure.command_runner import run_command


def test_run_command_passes_arguments_without_a_shell() -> None:
    argument = "literal;$(exit 9)"

    completed = run_command(
        [sys.executable, "-c", "import sys; print(sys.argv[1])", argument], timeout=2
    )

    assert completed.returncode == 0
    assert completed.stdout.strip() == argument
