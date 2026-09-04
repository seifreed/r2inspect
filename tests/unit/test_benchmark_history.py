import json
from pathlib import Path

from benchmarks.benchmark_history import update_history


def test_history_is_persistent_and_dashboard_lists_runs(tmp_path: Path) -> None:
    metrics = tmp_path / "metrics.json"
    metrics.write_text(
        json.dumps(
            {
                "cases": 3,
                "analyzers": {
                    "execution_failure_rate": 0.0,
                    "dependency_unavailable_rate": 0.0,
                },
                "latency_seconds": {"p95": 1.5},
                "classification": {"precision": 1.0, "recall": 1.0},
            }
        ),
        encoding="utf-8",
    )
    history = tmp_path / "history.json"
    dashboard = tmp_path / "dashboard.md"
    for run_id in ("1", "2"):
        update_history(history, dashboard, {"public": metrics}, run_id=run_id, commit="abc")

    assert [run["run_id"] for run in json.loads(history.read_text())["runs"]] == ["1", "2"]
    assert "| 2 | public | 3 | 0.0 | 0.0 | 1.5 | 1.0 | 1.0 |" in dashboard.read_text()
