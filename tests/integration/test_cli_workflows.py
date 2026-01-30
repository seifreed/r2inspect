import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.requires_r2

ROOT = Path(__file__).resolve().parents[2]


def _run_cli(args, input_data=None, timeout=60):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    cmd = [
        sys.executable,
        "-c",
        "from r2inspect.cli_main import cli; cli()",
        *args,
    ]
    return subprocess.run(
        cmd,
        input=input_data,
        text=True,
        capture_output=True,
        env=env,
        timeout=timeout,
    )


def test_cli_help():
    result = _run_cli(["--help"])
    assert result.returncode == 0
    assert "Usage:" in result.stdout
    assert "Interactive mode" in result.stdout


def test_cli_list_yara():
    rules_dir = ROOT / "r2inspect" / "rules" / "yara"
    result = _run_cli(["--list-yara", "--yara", str(rules_dir)])
    assert result.returncode == 0
    assert "YARA" in result.stdout


def test_cli_version():
    result = _run_cli(["--version"])
    assert result.returncode == 0
    assert "r2inspect" in result.stdout


def test_cli_analyze_json_output(tmp_path):
    output_file = tmp_path / "out.json"
    target = ROOT / "samples" / "fixtures" / "hello_macho"
    result = _run_cli([str(target), "--json", "-o", str(output_file)])
    assert result.returncode == 0
    assert output_file.exists()

    payload = json.loads(output_file.read_text())
    assert payload["format_detection"]["file_format"] == "Mach-O"


def test_cli_batch_json_output(tmp_path):
    batch_dir = tmp_path / "batch"
    batch_dir.mkdir()
    src = ROOT / "samples" / "fixtures" / "edge_tiny.bin"
    dest = batch_dir / "edge_tiny.bin"
    dest.write_bytes(src.read_bytes())

    output_dir = tmp_path / "out"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    cmd = [
        sys.executable,
        "-c",
        "from r2inspect.cli_main import cli; cli()",
        "--batch",
        str(batch_dir),
        "--extensions",
        "bin",
        "--json",
        "-o",
        str(output_dir),
        "--threads",
        "1",
        "--quiet",
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    deadline = time.time() + 30
    while time.time() < deadline:
        if output_dir.exists() and any(p.suffix == ".json" for p in output_dir.iterdir()):
            proc.terminate()
            break
        if proc.poll() is not None:
            break
        time.sleep(0.5)

    if proc.poll() is None:
        proc.kill()
        proc.wait(timeout=5)

    assert output_dir.exists()
    assert any(p.suffix == ".json" for p in output_dir.iterdir())


def test_cli_interactive_quit():
    target = ROOT / "samples" / "fixtures" / "hello_macho"
    result = _run_cli([str(target), "-i"], input_data="quit\n", timeout=30)
    assert result.returncode == 0
    assert "Interactive Mode" in result.stdout
