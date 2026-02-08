from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.cli import analysis_runner as ar


class DummyInspector:
    def analyze(self, **_options):
        return {"file_info": {"name": "sample"}}


def test_run_analysis_basic(capsys) -> None:
    results = ar.run_analysis(
        DummyInspector(),
        options={},
        output_json=False,
        output_csv=False,
        output_file=None,
        verbose=False,
    )
    out = capsys.readouterr().out
    assert "Starting analysis" in out
    assert results["file_info"]["name"] == "sample"


def test_output_json_and_csv_to_file(tmp_path: Path) -> None:
    results = {"ok": True}
    formatter = ar.OutputFormatter(results)

    json_path = tmp_path / "out.json"
    ar.output_json_results(formatter, json_path)
    assert json_path.read_text()

    csv_path = tmp_path / "out.csv"
    ar.output_csv_results(formatter, csv_path)
    assert csv_path.read_text()


def test_setup_single_file_output_creates_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.chdir(tmp_path)
    out = ar.setup_single_file_output(True, False, None, "sample.bin")
    assert out is not None
    assert Path(out).name == "sample_analysis.json"


def test_handle_main_error_verbose() -> None:
    with pytest.raises(SystemExit):
        ar.handle_main_error(RuntimeError("boom"), verbose=True)


def test_has_circuit_breaker_data_nested() -> None:
    assert ar.has_circuit_breaker_data({}) is False
    assert ar.has_circuit_breaker_data({"x": {"failure_count": 1}}) is True
