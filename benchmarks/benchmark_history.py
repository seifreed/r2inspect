#!/usr/bin/env python3
"""Append benchmark metrics to portable history and render an Actions dashboard."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _summary(path: Path) -> dict[str, Any]:
    metrics = json.loads(path.read_text(encoding="utf-8"))
    classification = metrics.get("classification", {})
    return {
        "cases": metrics.get("cases"),
        "failure_rate": metrics.get("analyzers", {}).get("execution_failure_rate"),
        "dependency_rate": metrics.get("analyzers", {}).get("dependency_unavailable_rate"),
        "latency_p95": metrics.get("latency_seconds", {}).get("p95"),
        "precision": classification.get("precision"),
        "recall": classification.get("recall"),
    }


def update_history(
    history_path: Path,
    dashboard_path: Path,
    metrics: dict[str, Path],
    *,
    run_id: str,
    commit: str,
    clustering: Path | None = None,
) -> None:
    history = (
        json.loads(history_path.read_text(encoding="utf-8"))
        if history_path.is_file()
        else {"schema_version": "r2inspect.benchmark-history/v1", "runs": []}
    )
    record = {
        "run_id": run_id,
        "commit": commit,
        "recorded_at": datetime.now(UTC).isoformat(),
        "metrics": {name: _summary(path) for name, path in sorted(metrics.items())},
    }
    if clustering:
        record["clustering"] = json.loads(clustering.read_text(encoding="utf-8"))
    history["runs"] = [run for run in history.get("runs", []) if run.get("run_id") != run_id]
    history["runs"].append(record)
    history["runs"] = history["runs"][-365:]
    history_path.parent.mkdir(parents=True, exist_ok=True)
    history_path.write_text(json.dumps(history, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "# r2inspect benchmark dashboard",
        "",
        "| Run | Corpus | Cases | Failure | Dependency | P95 | Precision | Recall |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for run in reversed(history["runs"]):
        for name, values in run["metrics"].items():
            cells = [run["run_id"], name, *(values[key] for key in values)]
            lines.append(
                "| " + " | ".join("-" if value is None else str(value) for value in cells) + " |"
            )
    dashboard_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--history", type=Path, required=True)
    parser.add_argument("--dashboard", type=Path, required=True)
    parser.add_argument("--metric", action="append", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--clustering", type=Path)
    args = parser.parse_args()
    metrics = {}
    for value in args.metric:
        name, separator, path = value.partition("=")
        if not separator or not name or not path:
            raise SystemExit("--metric must be NAME=PATH")
        metrics[name] = Path(path)
    update_history(
        args.history,
        args.dashboard,
        metrics,
        run_id=args.run_id,
        commit=args.commit,
        clustering=args.clustering,
    )


if __name__ == "__main__":
    main()
