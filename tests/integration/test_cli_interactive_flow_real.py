from __future__ import annotations

import os
import subprocess
import sys
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

import pytest

pytestmark = pytest.mark.requires_r2


def test_interactive_flow_real(samples_dir: Path, tmp_path: Path) -> None:
    sample = samples_dir / "hello_pe.exe"
    repo_root = Path(__file__).resolve().parents[2]
    code = (
        "import sys\n"
        "from r2inspect.factory import create_inspector\n"
        "from r2inspect.cli.interactive import run_interactive_mode\n"
        "path = sys.argv[1]\n"
        "with create_inspector(path) as inspector:\n"
        '    run_interactive_mode(inspector, {"batch_mode": True})\n'
    )
    env = dict(os.environ)
    env.setdefault("R2INSPECT_TEST_MODE", "1")
    env.setdefault("R2INSPECT_ANALYSIS_DEPTH", "1")
    env.setdefault("R2INSPECT_DISABLE_PLUGINS", "1")
    env.setdefault("R2INSPECT_MAX_WORKERS", "1")
    env.setdefault("R2INSPECT_MAX_THREADS", "1")
    env.setdefault("COVERAGE_PROCESS_START", str(repo_root / "pyproject.toml"))

    input_data = "\n".join(
        [
            "info",
            "strings",
            "imports",
            "exports",
            "sections",
            "pe",
            "analyze",
            "help",
            "quit",
            "",
        ]
    )

    result = subprocess.run(
        [sys.executable, "-c", code, str(sample)],
        input=input_data,
        text=True,
        capture_output=True,
        cwd=repo_root,
        env=env,
        timeout=180,
        check=False,
    )
    assert result.returncode == 0
    assert "Interactive Mode" in result.stdout


def test_interactive_flow_inprocess_real(samples_dir: Path) -> None:
    sample = samples_dir / "hello_pe.exe"
    input_stream = StringIO(
        "\n".join(
            [
                "",
                "info",
                "strings",
                "imports",
                "exports",
                "sections",
                "pe",
                "analyze",
                "help",
                "quit",
            ]
        )
    )
    env = {
        "R2INSPECT_TEST_MODE": "1",
        "R2INSPECT_ANALYSIS_DEPTH": "1",
        "R2INSPECT_DISABLE_PLUGINS": "1",
        "R2INSPECT_MAX_WORKERS": "1",
        "R2INSPECT_MAX_THREADS": "1",
    }
    original_env = dict(os.environ)
    os.environ.update(env)
    try:
        from r2inspect.cli.interactive import run_interactive_mode
        from r2inspect.factory import create_inspector

        with create_inspector(str(sample)) as inspector:
            original_stdin = sys.stdin
            try:
                sys.stdin = input_stream
                with redirect_stdout(StringIO()):
                    run_interactive_mode(inspector, {"batch_mode": True})
            finally:
                sys.stdin = original_stdin
    finally:
        os.environ.clear()
        os.environ.update(original_env)


def test_interactive_flow_inprocess_unknown_and_eof(samples_dir: Path) -> None:
    sample = samples_dir / "hello_pe.exe"
    input_stream = StringIO("unknown_command\n")
    env = {
        "R2INSPECT_TEST_MODE": "1",
        "R2INSPECT_ANALYSIS_DEPTH": "1",
        "R2INSPECT_DISABLE_PLUGINS": "1",
        "R2INSPECT_MAX_WORKERS": "1",
        "R2INSPECT_MAX_THREADS": "1",
    }
    original_env = dict(os.environ)
    os.environ.update(env)
    try:
        from r2inspect.cli.interactive import run_interactive_mode
        from r2inspect.factory import create_inspector

        with create_inspector(str(sample)) as inspector:
            original_stdin = sys.stdin
            try:
                sys.stdin = input_stream
                with redirect_stdout(StringIO()):
                    run_interactive_mode(inspector, {"batch_mode": True})
            finally:
                sys.stdin = original_stdin
    finally:
        os.environ.clear()
        os.environ.update(original_env)


def test_interactive_flow_inprocess_keyboard_interrupt(samples_dir: Path) -> None:
    sample = samples_dir / "hello_pe.exe"
    env = {
        "R2INSPECT_TEST_MODE": "1",
        "R2INSPECT_ANALYSIS_DEPTH": "1",
        "R2INSPECT_DISABLE_PLUGINS": "1",
        "R2INSPECT_MAX_WORKERS": "1",
        "R2INSPECT_MAX_THREADS": "1",
    }
    original_env = dict(os.environ)
    os.environ.update(env)
    try:
        from r2inspect.cli.interactive import run_interactive_mode
        from r2inspect.factory import create_inspector

        class InterruptingStdin:
            def readline(self, *args, **kwargs) -> str:
                raise KeyboardInterrupt

        with create_inspector(str(sample)) as inspector:
            original_stdin = sys.stdin
            try:
                sys.stdin = InterruptingStdin()
                with redirect_stdout(StringIO()):
                    run_interactive_mode(inspector, {"batch_mode": True})
            finally:
                sys.stdin = original_stdin
    finally:
        os.environ.clear()
        os.environ.update(original_env)
