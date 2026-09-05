from __future__ import annotations

import json
from pathlib import Path

from benchmarks.calibrate_classification import calibrate


def test_calibrate_classification_finds_function_cutoff(tmp_path: Path) -> None:
    cases = []
    for index, (label, functions) in enumerate(
        (("benign", 10), ("benign", 20), ("malware", 100), ("malware", 120))
    ):
        report_name = f"report-{index}.json"
        (tmp_path / report_name).write_text(
            json.dumps({"extras": {"functions": {"total_functions": functions}}}),
            encoding="utf-8",
        )
        cases.append({"class": label, "report": report_name})
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"corpus_id": "test", "cases": cases}), encoding="utf-8")

    result = calibrate(manifest)

    assert result["min_functions"] == 20
    assert result["precision"] == 1.0
    assert result["recall"] == 1.0
