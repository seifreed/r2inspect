import runpy
import subprocess
import sys
from pathlib import Path
from tempfile import NamedTemporaryFile

from r2inspect.abstractions.base_analyzer import BaseAnalyzer


class DummyAnalyzer(BaseAnalyzer):
    def analyze(self) -> dict[str, object]:
        return {"available": True}


def test_package_main_entrypoint_help():
    result = subprocess.run(
        [sys.executable, "-m", "r2inspect", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    output = (result.stdout + result.stderr).lower()
    assert result.returncode == 0
    assert "r2inspect" in output or "usage" in output


def test_package_main_entrypoint_runpy():
    original_argv = sys.argv[:]
    try:
        sys.argv = ["r2inspect", "--help"]
        try:
            runpy.run_module("r2inspect", run_name="__main__")
        except SystemExit as exc:
            assert exc.code in (0, None)
    finally:
        sys.argv = original_argv


def test_base_analyzer_defaults_and_utilities(tmp_path: Path):
    sample = tmp_path / "file.bin"
    sample.write_bytes(b"abc")

    analyzer = DummyAnalyzer(filepath=sample)
    analyzer._cached_category = "custom"

    assert analyzer.get_category() == "custom"
    analyzer._cached_category = None
    assert analyzer.get_category() == "unknown"
    assert analyzer.supports_format("PE") is True
    assert analyzer.get_supported_formats() == set()
    assert analyzer.get_description().endswith("No description provided")
    assert DummyAnalyzer.is_available() is True

    assert analyzer.get_file_size() == 3
    assert analyzer.get_file_extension() == "bin"
    assert analyzer.file_exists() is True

    missing = DummyAnalyzer(filepath=tmp_path / "missing.bin")
    assert missing.get_file_size() is None
    assert missing.get_file_extension() == "bin"
    assert missing.file_exists() is False

    nofile = DummyAnalyzer()
    assert nofile.get_file_size() is None
    assert nofile.get_file_extension() == ""
    assert nofile.file_exists() is False

    def _work():
        return {"ok": True}

    wrapped = analyzer._measure_execution_time(_work)
    output = wrapped()
    assert "execution_time" in output

    analyzer._log_debug("debug")
    analyzer._log_info("info")
    analyzer._log_warning("warn")
    analyzer._log_error("error")

    assert "DummyAnalyzer" in str(analyzer)
    assert "DummyAnalyzer" in repr(analyzer)
